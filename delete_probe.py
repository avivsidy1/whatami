"""
Delete-action counterpart of permission_probe. Probes a single Delete* action
live against a generated fake resource and reports the same labels:

  "NOT_ALLOWED"        - denied: no permission.
  "RESOURCE_NOT_FOUND" - permitted; the fake resource doesn't exist.
  "SUCCESS"            - the call succeeded (idempotent delete of a nonexistent
                         resource) -- also means permission.
  "INCONCLUSIVE"       - couldn't tell: action not in the runnable set, params
                         rejected client-side, unreachable endpoint, throttling
                         / 5xx / timeout after retries, or an unreliable action.
  "UNSAFE_SKIPPED"     - not called: the params don't target a fake resource, so
                         the call could delete something real.

Denial detection also matches message variants seen across services (e.g.
Chime's "ForbiddenException", wickr's bare "Access Denied"), since some return
non-standard codes for an admin acting on a nonexistent resource.
"""
import json

import botocore.session
from botocore import xform_name
from botocore.exceptions import ClientError, ParamValidationError

from permission_probe import ACCESS_DENIED_CODES, get_live_client, is_transient_error
from delete_parameters import build_delete_params, has_fake_target, UNSAFE_DENYLIST
from util import RUNNABLE_DELETE_ACTIONS

REGION = "us-east-1"

DENIED_CODE_HINTS = ("accessdenied", "forbidden", "unauthorized", "notauthorized", "authorization")
# Wording of a real IAM permission denial.
DENIED_MESSAGE_HINTS = (
    "not authorized to perform", "does not have permission to perform",
    "aws authorization failed", "no identity-based policy allows", "no explicit allow",
)
# Too generic on its own (some services return "Access Denied" for a
# nonexistent resource even to an admin); only treated as a denial alongside a
# denial-style code.
WEAK_DENIED_MESSAGE_HINT = "access denied"

# These return a not-found error even with no permission, so the response can't
# tell whether the caller holds the permission.
UNRELIABLE_ACTIONS = {"sagemaker:DeleteAIBenchmarkJob", "sagemaker:DeleteAIWorkloadConfig"}

_TARGETS = None
_BOTOCORE_SESSION = None


def _targets():
    global _TARGETS
    if _TARGETS is None:
        with open(RUNNABLE_DELETE_ACTIONS, encoding="utf-8") as f:
            _TARGETS = json.load(f)
    return _TARGETS


def _botocore_session():
    global _BOTOCORE_SESSION
    if _BOTOCORE_SESSION is None:
        _BOTOCORE_SESSION = botocore.session.get_session()
    return _BOTOCORE_SESSION


def is_denied(error_code, error_message):
    """The message decides when present: some services reuse denial codes for
    non-IAM errors even for an admin (e.g. chime:DeleteRoom -> ForbiddenException
    "Not permitted ... [Chime Account ...]"). The code decides only when the
    message is empty, or alongside the generic "access denied" wording."""
    code = error_code or ""
    denied_code = code in ACCESS_DENIED_CODES or any(h in code.lower() for h in DENIED_CODE_HINTS)
    msg = (error_message or "").lower()
    if not msg:
        return denied_code
    if any(h in msg for h in DENIED_MESSAGE_HINTS):
        return True
    return denied_code and WEAK_DENIED_MESSAGE_HINT in msg


def check_delete_action_live(action, region_name=REGION, session=None, policy_name=None):
    """
    Call delete `action` (e.g. "lambda:DeleteFunction") against AWS with a fake
    target, under `session`'s credentials, and classify the result. See the
    module docstring for the labels.

    When `policy_name` is given and that policy grants the action only on a
    specific Resource ARN pattern, the fake target is synthesized to match it.

    Raises ValueError if `action` isn't in "service:Action" format.
    """
    if ":" not in action:
        raise ValueError(f"Action must be in 'service:Action' format, got: {action!r}")
    info = _targets().get(action)
    if info is None or action in UNRELIABLE_ACTIONS:
        return "INCONCLUSIVE"
    if action in UNSAFE_DENYLIST:
        return "UNSAFE_SKIPPED"
    svc_name = info["botocore_service"]
    op = action.split(":", 1)[1]

    resource_arn = None
    if policy_name:
        try:
            from policy_resources import resource_arn_for_action, caller_account
            resource_arn = resource_arn_for_action(
                policy_name, action, region_name, caller_account(session))
        except Exception:
            resource_arn = None

    try:
        op_model = _botocore_session().get_service_model(svc_name).operation_model(op)
        params = build_delete_params(op_model, svc_name, resource_arn)
    except Exception:
        return "INCONCLUSIVE"
    if not has_fake_target(params):
        return "UNSAFE_SKIPPED"

    client = get_live_client(svc_name, region_name, session)
    method = getattr(client, xform_name(op), None)
    if method is None:
        return "INCONCLUSIVE"

    try:
        method(**params)
        return "SUCCESS"
    except ClientError as e:
        if is_transient_error(e):
            return "INCONCLUSIVE"
        err = e.response.get("Error", {})
        return "NOT_ALLOWED" if is_denied(err.get("Code"), err.get("Message")) else "RESOURCE_NOT_FOUND"
    except ParamValidationError:
        return "INCONCLUSIVE"
    except Exception:
        return "INCONCLUSIVE"
