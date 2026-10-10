"""
whatami -- infer which AWS managed policies a set of credentials has.

Pipeline:
  1. Run enumerate-iam to find no-parameter List/Describe actions that work for
     the credentials.
  2. Shortlist every attachable managed policy whose no-parameter list actions
     are all in that worked set ("suspected" policies).
  3. Narrow the shortlist by live-probing each suspect's data-sensitive get,
     list, and delete actions: a probe that comes back NOT_ALLOWED means the
     identity lacks that action, so the policy is dropped (unless the action is
     condition-gated, where a denial is ambiguous).
  4. Rank the survivors by how much unique evidence each contributes and print
     the most likely policies.

Usage:
  python whatami.py --access-key AKIA... --secret-key ... [--session-token ...]
                    [--region us-east-1]

With no credentials, it reuses a previously written worked-actions log.
"""
import argparse
import json
import os
import re
import sys

import boto3

from util import (
    bruteforce_actions_to_policies_format,
    ENUMERATE_IAM_DIR,
    OUTPUT_DIR,
    WORKED_ACTIONS_LOG,
    LIST_ACTIONS_NO_REQUIRED_PARAMS,
    DATA_SENSITIVE_GET_ACTIONS,
    DATA_SENSITIVE_LIST_ACTIONS,
    DATA_SENSITIVE_DELETE_ACTIONS,
)
from permission_probe import check_action_live
from delete_probe import check_delete_action_live
from policy_resources import is_action_conditioned
from policy_ranking import build_unique_most_worked_policy_dict

# Always allowed by enumerate-iam regardless of the identity, so they carry no
# signal and are dropped from the worked set.
DEFAULT_ACTIONS = set(bruteforce_actions_to_policies_format(
    ["sts.get_session_token", "sts.get_caller_identity", "dynamodb.describe_endpoints"]))


def run_enumeration(access_key, secret_key, session_token, region):
    """Run enumerate-iam and write the worked brute-force actions to the log."""
    sys.path.insert(0, ENUMERATE_IAM_DIR)
    from enumerate_iam.main import enumerate_iam

    result = enumerate_iam(access_key, secret_key, session_token, region)
    worked = result.get("bruteforce") or {}

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(WORKED_ACTIONS_LOG, "w") as f:
        for action in worked:
            f.write("-- %s() worked!\n" % action)
    print(f"enumerate-iam found {len(worked)} working actions.")


def load_worked_permissions():
    """Worked actions from the log, in IAM policy format, minus the no-signal
    defaults."""
    with open(WORKED_ACTIONS_LOG) as f:
        worked = re.findall(r"([\w-]+\.\w+)\(\) worked!", f.read())
    return set(bruteforce_actions_to_policies_format(worked)) - DEFAULT_ACTIONS


def find_suspected_policies(all_policies, permissions):
    """Every policy whose no-parameter list actions are all in the worked set.
    Returns {policy: [its list actions]}."""
    worked_lower = {p.lower() for p in permissions}
    suspected = {}
    for policy, actions in all_policies.items():
        if {a.lower() for a in actions}.issubset(worked_lower):
            suspected[policy] = list(actions)
    return suspected


def narrow_by_live_probe(suspected, worked_actions, actions_file, probe, session):
    """Drop any policy that has a data-sensitive action the identity can't call.

    `probe` is check_action_live or check_delete_action_live. A previously
    confirmed action is credited without re-probing. A NOT_ALLOWED result drops
    the policy, unless the action is condition-gated (a denial there is
    ambiguous). Mutates and returns (suspected, worked_actions).
    """
    with open(actions_file) as f:
        policy_actions = json.loads(f.read())

    for policy in list(suspected.keys()):
        for action in policy_actions.get(policy, []):
            if action in worked_actions:
                suspected[policy].append(action)
                continue
            result = probe(action, session=session, policy_name=policy)
            if result in ("RESOURCE_NOT_FOUND", "SUCCESS"):
                suspected[policy].append(action)
                worked_actions.append(action)
            elif result == "NOT_ALLOWED":
                if not is_action_conditioned(policy, action):
                    suspected.pop(policy, None)
                break
            else:  # INCONCLUSIVE / UNSAFE_SKIPPED -- no permission signal
                print(f"  note: {action} was inconclusive; it may affect accuracy")
    return suspected, worked_actions


def print_probe_identity(session):
    try:
        identity = (session or boto3.Session()).client("sts").get_caller_identity()
        print(f"Probing as {identity['Arn']} (account {identity['Account']})")
    except Exception as e:
        print(f"Could not determine probe identity: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Infer which AWS managed policies a set of credentials has.")
    parser.add_argument("--access-key", help="AWS access key id")
    parser.add_argument("--secret-key", help="AWS secret access key")
    parser.add_argument("--session-token", default=None, help="AWS session token (temporary credentials)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    args = parser.parse_args()

    have_creds = bool(args.access_key and args.secret_key)

    # One session, built from the given credentials, shared by every live probe
    # so enumeration and probing run as the same identity. None -> probes use
    # the default credential chain.
    session = None
    if have_creds:
        session = boto3.Session(
            aws_access_key_id=args.access_key,
            aws_secret_access_key=args.secret_key,
            aws_session_token=args.session_token,
            region_name=args.region,
        )
        run_enumeration(args.access_key, args.secret_key, args.session_token, args.region)
    elif not os.path.exists(WORKED_ACTIONS_LOG):
        parser.error("no credentials given and no previous enumeration found; "
                     "pass --access-key and --secret-key")

    print_probe_identity(session)

    permissions = load_worked_permissions()
    all_policies = json.loads(open(LIST_ACTIONS_NO_REQUIRED_PARAMS).read())
    suspected = find_suspected_policies(all_policies, permissions)
    print(f"{len(permissions)} working actions -> {len(suspected)} candidate policies.")

    worked_actions = []
    print("Probing data-sensitive get actions...")
    suspected, worked_actions = narrow_by_live_probe(
        suspected, worked_actions, DATA_SENSITIVE_GET_ACTIONS, check_action_live, session)
    print("Probing data-sensitive list actions...")
    suspected, worked_actions = narrow_by_live_probe(
        suspected, worked_actions, DATA_SENSITIVE_LIST_ACTIONS, check_action_live, session)
    print("Probing data-sensitive delete actions...")
    suspected, worked_actions = narrow_by_live_probe(
        suspected, worked_actions, DATA_SENSITIVE_DELETE_ACTIONS, check_delete_action_live, session)

    most_worked = dict(sorted(suspected.items(), key=lambda kv: len(kv[1]), reverse=True))
    ranked = build_unique_most_worked_policy_dict(most_worked)

    print_results(ranked, suspected)


def confidence_label(unique_actions):
    """A rough confidence tier from how much unique evidence a policy adds.
    More distinguishing actions -> more confident the policy is really
    attached (rather than its actions being explained by a bigger policy)."""
    if unique_actions >= 10:
        return "HIGH"
    if unique_actions >= 3:
        return "MEDIUM"
    return "LOW"


def print_results(ranked, suspected):
    """Print the surviving policies, highest confidence first, with how much
    unique new evidence each adds and how many actions were confirmed for it.
    Policies that add no unique evidence (another policy explains all their
    actions) are omitted."""
    hits = [(p, score) for p, score in ranked.items() if score > 0]
    if not hits:
        print("\nNo policy could be confirmed for this identity.")
        return

    print("\nMost likely attached policies (highest confidence first):")
    print(f"  {'policy':55}  {'confidence':10}  new actions   confirmed actions")
    for policy, unique in hits:
        confirmed = len(set(suspected.get(policy, [])))
        print(f"  {policy:55}  {confidence_label(unique):10}  {unique:<12}  {confirmed}")
    print("\n  new actions       = permissions this policy explains that no higher one does")
    print("  confirmed actions = total actions verified working for this policy")


if __name__ == "__main__":
    main()
