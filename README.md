# whatami

**Figure out which AWS managed policies a set of credentials has — without `iam:Get*`/`iam:List*`.**

Given only an access key (and optionally a session token), `whatami` infers the
AWS managed policies most likely attached to that identity. It never reads IAM
directly. Instead it observes which API calls the identity *can* make and
matches that behaviour against AWS's catalogue of managed policies.

## How it works

1. **Enumerate** — runs [enumerate-iam](https://github.com/andresriancho/enumerate-iam)
   (vendored in `enumerate-iam/`) to find no-parameter `List`/`Describe` actions
   that succeed for the credentials.
2. **Shortlist** — keeps every attachable managed policy whose no-parameter list
   actions are *all* in that worked set. These are the "suspected" policies.
3. **Narrow** — for each suspect, live-probes its **data-sensitive** get, list
   and delete actions with safe, auto-generated mock parameters. A data-sensitive
   action returns a different error depending on whether you hold the
   permission, so the probe can tell `NOT_ALLOWED` apart from "permitted but the
   resource doesn't exist". A `NOT_ALLOWED` result drops the policy (unless the
   action is condition-gated, where a denial is ambiguous).
4. **Rank** — orders the survivors by how much *unique* evidence each one
   contributes and prints the most likely policies.

Probes target generated, nonexistent resources (identifiers containing
`claudetest404nonexistent`). Delete probes additionally refuse to run unless the
request targets such a fake resource, so **nothing real is created or deleted**.

## Install

```bash
git clone <this-repo>
cd whatami
python -m venv .venv && . .venv/bin/activate     # optional
pip install -r requirements.txt
```

Python 3.9+.

## Usage

```bash
python whatami.py --access-key AKIA... --secret-key ... [--session-token ...] [--region us-east-1]
```

Example output:

```
enumerate-iam found 142 working actions.
Probing as arn:aws:iam::123456789012:user/some-user (account 123456789012)
142 working actions -> 23 candidate policies.
Probing data-sensitive get actions...
Probing data-sensitive list actions...
Probing data-sensitive delete actions...

Most likely attached policies (highest confidence first):
  AmazonDataZoneFullAccess
  AmazonElastiCacheFullAccess
  ...
```

All probes run as the credentials you pass, so the result reflects *that*
identity. Run with no credentials to reuse the previous enumeration in
`outputs/worked_actions.log`.

## Project layout

| File | Purpose |
|---|---|
| `whatami.py` | Entry point and pipeline (enumerate → shortlist → narrow → rank). |
| `permission_probe.py` | Live probe for a get/list/describe action → permission verdict. |
| `delete_probe.py` | Live probe for a delete action (with a fake-target safety gate). |
| `mock_parameters.py` | Generates correctly-shaped, nonexistent parameter values. |
| `delete_parameters.py` | Parameter builder + safety gate for delete actions. |
| `policy_resources.py` | Reads AWS policy docs: resource-ARN hints and condition checks. |
| `policy_ranking.py` | Ranks suspects by unique evidence. |
| `util.py` | Paths, the enumerate-iam → IAM service map, and small helpers. |
| `enumerate-iam/` | Vendored enumeration tool. |
| `data/` | Per-policy action dictionaries and AWS managed-policy documents. |
| `outputs/` | Runtime enumeration log. |

### `data/`

| File | Contents |
|---|---|
| `list_actions_no_required_params.json` | Policy → its no-parameter list actions (used for the shortlist). |
| `data_sensitive_get_actions.json` | Policy → data-sensitive get/describe actions. |
| `data_sensitive_list_actions.json` | Policy → data-sensitive list actions that need parameters. |
| `data_sensitive_delete_actions.json` | Policy → data-sensitive delete actions. |
| `runnable_delete_actions.json` | Delete action → its botocore service (for the delete probe). |
| `managed_policies/`, `managed_policies_deprecated/` | AWS managed-policy documents (resource/condition data). |

## Notes & limitations

- Only **attachable** AWS-managed policies are considered.
- Policies whose actions are entirely condition-gated or resource-scoped in ways
  that can't be probed safely may not be confirmable.
- The managed-policy dataset is a point-in-time copy of AWS's published data and
  can lag new services/actions slightly.

## Credits

Enumeration is performed by Rhino Security Labs'
[enumerate-iam](https://github.com/andresriancho/enumerate-iam), included under
`enumerate-iam/` with its own license.
