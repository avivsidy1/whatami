"""
Ranks the suspected policies by how much unique evidence each one contributes.

build_unique_most_worked_policy_dict() walks the policies in "most worked
first" order and, for each, counts only the worked actions not already claimed
by a higher-ranked policy. A policy whose every action is also granted by a
bigger policy scores 0 -- it adds no distinguishing evidence of its own.
"""


def build_unique_most_worked_policy_dict(most_worked_policy_dict):
    """
    Given an ordered {policy: [worked action names]} dict (most-worked first),
    return {policy: count}, where count is how many of that policy's worked
    actions had not already been claimed by an earlier policy. Sorted by count,
    descending. Each action is claimed only once.
    """
    order = list(most_worked_policy_dict.keys())
    remaining = set()
    for actions in most_worked_policy_dict.values():
        remaining |= set(actions)

    result = {}
    for name in order:
        policy_actions = set(most_worked_policy_dict[name])
        still_present = policy_actions & remaining
        result[name] = len(still_present)
        remaining -= policy_actions

    return dict(sorted(result.items(), key=lambda kv: -kv[1]))
