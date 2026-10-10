"""
Generates plausible-but-nonexistent values for the required parameters of an
AWS API operation, so an action can be probed against a resource that does not
exist. Correctly-shaped values avoid a client-side validation error, which
lets the call reach AWS and return a clean "access denied" vs "not found"
signal.

When a policy constrains an action to a specific Resource ARN, a matching
value is synthesized instead (see policy_resources), so the probe tests the
permission rather than the resource constraint.
"""
import re

MARKER = "claudetest404nonexistent"

# Placeholder account id used only to build well-formed ARNs for nonexistent
# resources. It does not affect the permission result; the policy-aware path
# resolves the caller's real account at runtime (see policy_resources).
PLACEHOLDER_ACCOUNT = "123456789012"

# Parameter-name fragment (lowercased) -> value template, matched by substring;
# most specific fragments are listed first since the first hit wins.
NAME_HEURISTICS = [
    ("accountid", PLACEHOLDER_ACCOUNT),
    ("arn", None),  # handled specially below (needs service/region/account context)
    ("bucketname", f"{MARKER}-bucket"),
    ("bucket", f"{MARKER}-bucket"),
    ("vpcid", "vpc-000000000claude1"),
    ("subnetid", "subnet-000000000claude1"),
    ("securitygroupid", "sg-000000000claude1"),
    ("instanceid", "i-000000000claude1"),
    ("volumeid", "vol-000000000claude1"),
    ("snapshotid", "snap-000000000claude1"),
    ("imageid", "ami-000000000claude1"),
    ("groupid", "sg-000000000claude1"),
    ("allocationid", "eipalloc-000000claude1"),
    ("gatewayid", "igw-000000000claude1"),
    ("routetableid", "rtb-000000000claude1"),
    ("networkinterfaceid", "eni-000000000claude1"),
    ("keypairname", f"{MARKER}-keypair"),
    ("username", f"{MARKER}user"),
    ("groupname", f"{MARKER}group"),
    ("rolename", f"{MARKER}role"),
    ("policyname", f"{MARKER}policy"),
    ("functionname", f"{MARKER}fn"),
    ("tablename", f"{MARKER}table"),
    ("clusteridentifier", f"{MARKER}cluster"),
    ("clustername", f"{MARKER}cluster"),
    ("dbinstanceidentifier", f"{MARKER}dbinst"),
    ("dbclusteridentifier", f"{MARKER}dbcluster"),
    ("queuename", f"{MARKER}queue"),
    ("queueurl", f"https://sqs.us-east-1.amazonaws.com/{PLACEHOLDER_ACCOUNT}/{MARKER}queue"),
    ("streamname", f"{MARKER}stream"),
    ("keyid", "00000000-0000-0000-0000-000000claude"),
    ("secretid", f"{MARKER}secret"),
    ("parametername", f"/{MARKER}/param"),
    ("loggroupname", f"/{MARKER}/loggroup"),
    ("logstreamname", f"{MARKER}logstream"),
    ("repositoryname", f"{MARKER}repo"),
    ("pipelinename", f"{MARKER}pipeline"),
    ("projectname", f"{MARKER}project"),
    ("domainname", f"{MARKER}.example.com"),
    ("certificatearn", None),
    ("id", f"{MARKER}id"),
    ("name", f"{MARKER}name"),
]

# Optional members matching this suffix are still the identifier being asked
# about (e.g. iam:GetUser's UserName defaults to the caller when omitted), so
# we fill them in to exercise the not-found path. Pagination / filter noise is
# excluded explicitly.
IDENTIFIER_NAME_RE = re.compile(r"(name|id|arn|identifier)$", re.IGNORECASE)
EXCLUDED_OPTIONAL_NAMES = {
    "nexttoken", "marker", "maxresults", "maxitems", "pagesize", "limit",
    "version", "versionid", "requestid", "clientrequesttoken", "clienttoken",
}


def _matches_uuid_pattern(pattern):
    if not pattern:
        return False
    p = pattern.lower()
    return "8}-" in p or "a-f0-9" in p.replace("-", "") or re.search(r"\{8\}.*\{4\}.*\{4\}.*\{4\}.*\{12\}", p)


def _fit_length(value, min_length, max_length):
    if min_length and len(value) < min_length:
        value = value + ("x" * (min_length - len(value)))
    if max_length and len(value) > max_length:
        value = value[:max_length]
    return value


def _build_arn(param_name, service, region, account_id=PLACEHOLDER_ACCOUNT):
    lname = param_name.lower()
    resource = f"{MARKER}-resource"
    if "role" in lname:
        return f"arn:aws:iam::{account_id}:role/{MARKER}role"
    if "user" in lname:
        return f"arn:aws:iam::{account_id}:user/{MARKER}user"
    if "policy" in lname:
        return f"arn:aws:iam::{account_id}:policy/{MARKER}policy"
    if "key" in lname:
        return f"arn:aws:kms:{region}:{account_id}:key/00000000-0000-0000-0000-000000claude"
    if "topic" in lname:
        return f"arn:aws:sns:{region}:{account_id}:{MARKER}topic"
    if "secret" in lname:
        return f"arn:aws:secretsmanager:{region}:{account_id}:secret:{MARKER}secret"
    if "function" in lname or "lambda" in lname:
        return f"arn:aws:lambda:{region}:{account_id}:function:{MARKER}fn"
    if "cluster" in lname:
        return f"arn:aws:rds:{region}:{account_id}:cluster:{MARKER}cluster"
    if "bucket" in lname:
        return f"arn:aws:s3:::{MARKER}-bucket"
    if "certificate" in lname or "acm" in lname:
        return f"arn:aws:acm:{region}:{account_id}:certificate/00000000-0000-0000-0000-000000claude"
    if "table" in lname:
        return f"arn:aws:dynamodb:{region}:{account_id}:table/{MARKER}table"
    return f"arn:aws:{service}:{region}:{account_id}:resource/{resource}"


def generate_string_value(param_name, member, service, region, resource_arn=None):
    try:
        pattern = member.pattern
    except AttributeError:
        pattern = None
    min_length = getattr(member, "min_length", None)
    max_length = getattr(member, "max_length", None)
    enum = getattr(member, "enum", None)

    if enum:
        return enum[0]

    lname = param_name.lower()

    # Account / region / partition parameters identify context, not the
    # resource being acted on, so they must keep their real values (e.g.
    # QuickSight's AwsAccountId) and are never overwritten with the resource
    # ARN even though a name like "AwsAccountId" ends in "Id".
    is_context_field = any(h in lname for h in ("account", "region", "partition"))
    if resource_arn and not is_context_field:
        if "arn" in lname:
            return resource_arn
        # Name / Id / Identifier params, and path-style params (e.g. SSM's
        # "Path"), take the resource identifier derived from the policy's ARN.
        if IDENTIFIER_NAME_RE.search(param_name) or "path" in lname:
            from policy_resources import resource_name
            name = resource_name(resource_arn)
            if name:
                return _fit_length(name, min_length, max_length)

    if "arn" in lname:
        return _build_arn(param_name, service, region)

    if _matches_uuid_pattern(pattern) or "uuid" in lname:
        return "00000000-0000-0000-0000-000000claude"

    for frag, template in NAME_HEURISTICS:
        if frag in lname and template is not None:
            return _fit_length(template, min_length, max_length)

    value = _fit_length(MARKER, min_length, max_length)

    if pattern:
        try:
            if not re.fullmatch(pattern, value):
                # Last resort: a conservative alnum-only value that satisfies
                # most restrictive AWS name patterns.
                fallback = _fit_length("claudetest404x", min_length, max_length)
                if re.fullmatch(pattern, fallback):
                    return fallback
        except re.error:
            pass
    return value


def generate_value(param_name, member, service, region, resource_arn=None):
    type_name = member.type_name
    if type_name == "string":
        return generate_string_value(param_name, member, service, region, resource_arn)
    if type_name in ("integer", "long"):
        return 999999999
    if type_name in ("double", "float"):
        return 1.0
    if type_name == "boolean":
        return False
    raise ValueError(f"Unsupported scalar type for mocking: {type_name}")


def build_mock_params(operation_model, service, region, resource_arn=None):
    """
    Build a parameter dict covering every required member of the operation plus
    any optional top-level scalar that looks like a resource identifier (several
    Get/Describe APIs make their primary identifier optional, defaulting to the
    caller, which would otherwise skip the not-found path).

    resource_arn, when given, is a concrete ARN matching the calling policy's
    Resource constraint for this action; ARN / Name / Id / Path parameters are
    filled from it. Raises ValueError if a required member is not a scalar.
    """
    shape = operation_model.input_shape
    params = {}
    if not shape:
        return params

    required = set(shape.required_members)
    for pname in required:
        member = shape.members[pname]
        params[pname] = generate_value(pname, member, service, region, resource_arn)

    for pname, member in shape.members.items():
        if pname in required:
            continue
        if pname.lower() in EXCLUDED_OPTIONAL_NAMES:
            continue
        if member.type_name not in ("string", "integer", "long", "boolean", "double", "float"):
            continue
        if IDENTIFIER_NAME_RE.search(pname):
            params[pname] = generate_value(pname, member, service, region, resource_arn)

    return params
