"""
Policy-aware helpers that read AWS's own managed-policy documents.

Two things the probes need from a policy's definition:

  * resource_arn_for_action(): when a policy grants an action only on a
    specific Resource ARN pattern (e.g. AmazonDataZoneFullAccess grants
    iam:GetPolicy only on
    "arn:aws:iam::*:policy/service-role/AmazonDataZoneRedshiftAccessPolicy*"),
    a generic mock ARN would be denied on the resource even when the identity
    has the permission. This returns a concrete, well-formed ARN matching the
    pattern so the probe tests the permission, or None when the action is
    granted on "*" (no resource constraint).

  * is_action_conditioned(): whether the statement granting an action carries
    a Condition. A conditioned action can be denied for reasons unrelated to
    the permission, so the pipeline treats such a denial as inconclusive.
"""
import fnmatch
import json
import os
import re

import boto3

from util import MANAGED_POLICY_DIRS

MARKER = "claudetest404nonexistent"

# Fallback account id, used only to fill a wildcard account segment in a
# resource ARN so the synthesized (nonexistent) resource belongs to the
# caller. The caller's real account is resolved at runtime via caller_account.
DEFAULT_ACCOUNT = "123456789012"

_ACCOUNT_CACHE = {}
_STATEMENTS_CACHE = {}
_CONDITIONED_CACHE = {}


def caller_account(session=None, default=DEFAULT_ACCOUNT):
    """The account id of `session`'s credentials (via STS), cached. Falls back
    to `default` when STS can't be reached (e.g. offline / no credentials)."""
    key = id(session)
    if key in _ACCOUNT_CACHE:
        return _ACCOUNT_CACHE[key]
    account = default
    try:
        account = (session or boto3.Session()).client("sts").get_caller_identity()["Account"]
    except Exception:
        account = default
    _ACCOUNT_CACHE[key] = account
    return account


def _load_policy_document(policy_name):
    """The parsed managed-policy JSON for `policy_name`, or None if not found."""
    for directory in MANAGED_POLICY_DIRS:
        path = os.path.join(directory, f"{policy_name}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.loads(f.read())
    return None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# --- resource-aware mock values -------------------------------------------
def _load_statements(policy_name):
    if policy_name not in _STATEMENTS_CACHE:
        doc = _load_policy_document(policy_name)
        _STATEMENTS_CACHE[policy_name] = _as_list(doc.get("document", {}).get("Statement")) if doc else []
    return _STATEMENTS_CACHE[policy_name]


def _concretize_arn(pattern, region, account=DEFAULT_ACCOUNT):
    """Turn an ARN pattern with wildcards into a concrete, well-formed ARN that
    still matches the pattern: partition '*'->aws, region '*'->region, account
    '*'->our account, and '*'/'?' in the resource part replaced with a marker
    so the resource is well-formed but (almost certainly) nonexistent."""
    parts = pattern.split(":", 5)
    if len(parts) < 6:
        return pattern.replace("*", MARKER).replace("?", "x")
    _arn, partition, service, reg, acct, resource = parts
    partition = "aws" if partition in ("*", "") else partition
    if reg == "*":
        reg = region
    if acct in ("*", ""):
        acct = account
    resource = re.sub(r"[*?]+", MARKER, resource)
    if not resource:
        resource = MARKER
    return ":".join(["arn", partition, service, reg, acct, resource])


def _statement_matches(statement, action):
    """True if this Allow statement grants `action` (handles Action lists and
    wildcards; NotAction statements are ignored)."""
    if statement.get("Effect") != "Allow" or "Action" not in statement:
        return False
    a = action.lower()
    return any(fnmatch.fnmatchcase(a, pat.lower()) for pat in _as_list(statement["Action"]))


def resource_arn_for_action(policy_name, action, region, account=DEFAULT_ACCOUNT):
    """A concrete ARN matching `policy_name`'s Resource constraint for `action`,
    or None when the action is granted on "*" (no constraint) or the policy /
    resource can't be resolved.

    If any matching statement grants the action on "*", the permission is
    unconstrained, so None is returned. Only when every grant is resource-scoped
    do we synthesize a matching ARN, from the first ARN-shaped Resource entry.
    """
    resources = []
    for statement in _load_statements(policy_name):
        if _statement_matches(statement, action):
            resources.extend(_as_list(statement.get("Resource")))

    if not resources:
        return None
    if any(r == "*" for r in resources):
        return None

    for r in resources:
        if isinstance(r, str) and r.startswith("arn:"):
            return _concretize_arn(r, region, account)
    return None


def resource_name(arn):
    """The identifier an API's Name/Id/Path parameter expects, derived from an
    ARN's resource part:
      "parameter/amazon/datazone/q..." -> "/amazon/datazone/q..."  (hierarchical path)
      "role/Bar"                        -> "Bar"                    (single name)
      "function:name"                   -> "name"                  (type:name)
    Hierarchy is detected by more than one "/" segment after the resource type.
    """
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    resource = parts[5]
    if "/" in resource:
        rtype, rest = resource.split("/", 1)
        if "/" in rest:
            return "/" + rest
        return rest
    if ":" in resource:
        return resource.split(":", 1)[1] or None
    return resource or None


# --- conditioned actions ---------------------------------------------------
def _load_conditioned_actions(policy_name):
    """The set of this policy's effective_action strings whose granting
    statement carries a Condition. Empty set if the policy isn't found."""
    if policy_name not in _CONDITIONED_CACHE:
        doc = _load_policy_document(policy_name)
        conditioned = set()
        if doc:
            for entry in (doc.get("effective_actions") or []):
                if entry.get("condition") is not None:
                    conditioned.add(entry["effective_action"])
        _CONDITIONED_CACHE[policy_name] = conditioned
    return _CONDITIONED_CACHE[policy_name]


def is_action_conditioned(policy_name, action):
    """
    True if `action` is conditioned in managed policy `policy_name` -- the
    statement granting it carries a Condition. False otherwise (unconditioned
    grant, action not in the policy, or policy not found).
    """
    return action in _load_conditioned_actions(policy_name)
