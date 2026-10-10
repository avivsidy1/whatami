"""
Probes a single AWS Get/List/Describe action live, with auto-generated mock
parameters, and reports whether the caller holds the permission:

  "NOT_ALLOWED"        - denied with an access-denied error: no permission.
  "RESOURCE_NOT_FOUND" - permitted, but the mock resource doesn't exist.
  "SUCCESS"            - the call succeeded.
  "INCONCLUSIVE"       - couldn't tell: unknown service/action, a client-side
                         parameter rejection, or throttling / 5xx / timeout
                         that persisted after retries.

RESOURCE_NOT_FOUND and SUCCESS both mean the caller has the permission.
"""
import boto3
import botocore.session
from botocore import xform_name
from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError

from mock_parameters import build_mock_params
from util import build_prefix_map

REGION = "us-east-1"

ACCESS_DENIED_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "NotAuthorizedException", "Forbidden",
}

# Adaptive retries back off on throttling and retry throttling / 5xx /
# connection errors; generous timeouts so a slow endpoint isn't misread.
LIVE_CHECK_CONFIG = Config(
    connect_timeout=10, read_timeout=30,
    retries={"mode": "adaptive", "max_attempts": 8},
)

# Error codes that say nothing about permission: throttling can be returned
# before the permission check, and 5xx/timeouts are just the service being
# flaky. Treating these as "some other error" would make a caller with no
# permission look allowed, so they are reported INCONCLUSIVE instead.
TRANSIENT_CODE_HINTS = (
    "throttl", "toomanyrequests", "requestlimitexceeded", "ratelimitexceeded",
    "slowdown", "provisionedthroughputexceeded", "bandwidthlimitexceeded",
    "priorrequestnotcomplete", "internalfailure", "internalerror",
    "internalserver", "serviceunavailable", "servicefailure", "requesttimeout",
)

_CLIENTS = {}
_PREFIX_MAP_CACHE = None


def is_transient_error(client_error):
    status = client_error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0
    code = (client_error.response.get("Error", {}).get("Code") or "").lower()
    return status == 429 or status >= 500 or any(h in code for h in TRANSIENT_CODE_HINTS)


def get_live_client(svc_name, region_name, session=None):
    """Client with LIVE_CHECK_CONFIG. Cached per (service, region) for the
    default session so the adaptive rate limiter carries across calls."""
    if session is not None:
        return session.client(svc_name, region_name=region_name, config=LIVE_CHECK_CONFIG)
    key = (svc_name, region_name)
    if key not in _CLIENTS:
        _CLIENTS[key] = boto3.Session(region_name=region_name).client(
            svc_name, region_name=region_name, config=LIVE_CHECK_CONFIG)
    return _CLIENTS[key]


def _get_prefix_map(botocore_session):
    # Parsing every botocore service model is slow, so build the map once.
    global _PREFIX_MAP_CACHE
    if _PREFIX_MAP_CACHE is None:
        _PREFIX_MAP_CACHE = build_prefix_map(botocore_session)
    return _PREFIX_MAP_CACHE


def check_action_live(action, region_name=REGION, session=None, policy_name=None):
    """
    Call `action` (e.g. "iam:GetUser") against AWS under `session`'s credentials
    (the default credential chain if not given) and classify the result.

    When `policy_name` is given and that policy grants the action only on a
    specific Resource ARN pattern, the mock value is synthesized to match it,
    so the probe tests the permission rather than the resource constraint.

    Raises ValueError if `action` isn't in "service:Action" format.
    """
    if ":" not in action:
        raise ValueError(f"Action must be in 'service:Action' format, got: {action!r}")
    prefix, op = action.split(":", 1)

    botocore_session = botocore.session.get_session()
    svc_name = _get_prefix_map(botocore_session).get(prefix)
    if svc_name is None:
        return "INCONCLUSIVE"

    try:
        op_model = botocore_session.get_service_model(svc_name).operation_model(op)
    except Exception:
        return "INCONCLUSIVE"

    resource_arn = None
    if policy_name:
        try:
            from policy_resources import resource_arn_for_action, caller_account
            resource_arn = resource_arn_for_action(
                policy_name, action, region_name, caller_account(session))
        except Exception:
            resource_arn = None

    try:
        mock_params = build_mock_params(op_model, svc_name, region_name, resource_arn)
    except Exception:
        return "INCONCLUSIVE"

    client = get_live_client(svc_name, region_name, session)
    method = getattr(client, xform_name(op), None)
    if method is None:
        return "INCONCLUSIVE"

    try:
        method(**mock_params)
        return "SUCCESS"
    except ClientError as e:
        if is_transient_error(e):
            return "INCONCLUSIVE"
        code = e.response.get("Error", {}).get("Code", "")
        return "NOT_ALLOWED" if code in ACCESS_DENIED_CODES else "RESOURCE_NOT_FOUND"
    except ParamValidationError:
        return "INCONCLUSIVE"
    except Exception:
        return "INCONCLUSIVE"
