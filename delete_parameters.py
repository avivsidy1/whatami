"""
Builds mock parameters for a Delete* action, with a safety gate.

Delete probes make real delete calls, so every call must target a generated
fake resource. build_delete_params() fills required parameters (including
nested structures and lists, which the simpler build_mock_params does not),
and has_fake_target() confirms at least one value is a generated fake
identifier before the caller is allowed to make the request. UNSAFE_DENYLIST
excludes actions where the fake value sits in a parameter the API may ignore,
which could otherwise hit a real account-level resource.
"""
from datetime import datetime, timezone

from mock_parameters import generate_value, IDENTIFIER_NAME_RE, EXCLUDED_OPTIONAL_NAMES

REGION = "us-east-1"
FAKE_INT = 999999999
SCALARS = ("string", "integer", "long", "boolean", "double", "float")

# Excluded after manual review even though they pass the fake-target gate: the
# fake value sits in a parameter the API may ignore, so the call could hit a
# real account-level resource.
UNSAFE_DENYLIST = {
    # required `name` is a real account setting; only the optional principalArn
    # is fake -- if ignored, this would reset the real setting.
    "ecs:DeleteAccountSetting",
    # only parameter is optional; docs say "automatic scope detection".
    "signin:DeleteConsoleAuthorizationConfiguration",
}


def mock_shape(name, shape, service, depth=0, resource_arn=None):
    """Mock value for any shape: scalars via mock_parameters, containers filled
    with only their required members (lists/maps get one fake element).
    resource_arn, when given, aligns ARN/Name/Id scalars with the calling
    policy's Resource constraint (see policy_resources)."""
    t = shape.type_name
    if t in SCALARS:
        return generate_value(name, shape, service, REGION, resource_arn)
    if depth > 6:
        raise ValueError(f"shape too deep: {name}")
    if t == "structure":
        return {m: mock_shape(m, shape.members[m], service, depth + 1, resource_arn)
                for m in shape.required_members}
    if t == "list":
        return [mock_shape(name, shape.member, service, depth + 1, resource_arn)]
    if t == "map":
        return {"claudetestkey": mock_shape(name, shape.value, service, depth + 1, resource_arn)}
    if t == "blob":
        return b"claudetest404nonexistent"
    if t == "timestamp":
        return datetime(2020, 1, 1, tzinfo=timezone.utc)
    raise ValueError(f"unsupported shape type {t} for {name}")


def build_delete_params(op_model, service, resource_arn=None):
    shape = op_model.input_shape
    if not shape:
        return {}
    required = set(shape.required_members)
    params = {p: mock_shape(p, shape.members[p], service, resource_arn=resource_arn) for p in required}
    # Optional identifier-looking scalars too, so e.g. ec2:DeleteKeyPair targets
    # a fake KeyName instead of nothing.
    for pname, member in shape.members.items():
        if pname in required or pname.lower() in EXCLUDED_OPTIONAL_NAMES:
            continue
        if member.type_name in SCALARS and IDENTIFIER_NAME_RE.search(pname):
            params[pname] = generate_value(pname, member, service, REGION, resource_arn)
    return params


def has_fake_target(value, key=""):
    """True if any string value contains the fake marker (or a fake numeric id),
    confirming the delete call targets a generated nonexistent resource."""
    if isinstance(value, dict):
        return any(has_fake_target(v, k) for k, v in value.items())
    if isinstance(value, list):
        return any(has_fake_target(v, key) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return False
    if isinstance(value, str):
        return "claude" in value.lower()
    if isinstance(value, int) and not isinstance(value, bool):
        return value == FAKE_INT and "id" in key.lower()
    return False
