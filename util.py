"""
Shared helpers and file locations for whatami.

Keeping the project-relative paths, the enumerate-iam -> IAM service-name
mapping, and the small action-format converters here keeps the main pipeline
(whatami.py) readable and lets every module agree on where the data lives.
All paths are resolved relative to this file, so the project works straight
after `git clone` with no machine-specific paths.
"""
import os

# --- project-relative locations -------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
ENUMERATE_IAM_DIR = os.path.join(BASE_DIR, "enumerate-iam")

# Worked brute-force actions found by enumerate-iam are written here, and the
# pipeline reads them back from here.
WORKED_ACTIONS_LOG = os.path.join(OUTPUT_DIR, "worked_actions.log")

# Per-policy action dictionaries (policy name -> list of action strings).
LIST_ACTIONS_NO_REQUIRED_PARAMS = os.path.join(DATA_DIR, "list_actions_no_required_params.json")
DATA_SENSITIVE_GET_ACTIONS = os.path.join(DATA_DIR, "data_sensitive_get_actions.json")
DATA_SENSITIVE_LIST_ACTIONS = os.path.join(DATA_DIR, "data_sensitive_list_actions.json")
DATA_SENSITIVE_DELETE_ACTIONS = os.path.join(DATA_DIR, "data_sensitive_delete_actions.json")

# Supporting datasets.
RUNNABLE_DELETE_ACTIONS = os.path.join(DATA_DIR, "runnable_delete_actions.json")
MANAGED_POLICY_DIRS = [
    os.path.join(DATA_DIR, "managed_policies"),
    os.path.join(DATA_DIR, "managed_policies_deprecated"),
]


# --- enumerate-iam action name -> IAM policy action name -------------------
# enumerate-iam uses boto3 client names, which differ from the IAM service
# prefix for some services. The "v2" boto3 clients (elbv2, connectcampaignsv2)
# collapse to the same IAM prefix as their non-v2 counterpart, since IAM gates
# both under one shared permission namespace. Services not listed here already
# match and pass through unchanged.
BRUTEFORCE_TO_POLICIES_SERVICE = {
    "accessanalyzer": "access-analyzer",
    "compute-optimizer-automation": "aco-automation",
    "devops-agent": "aidevops",
    "mwaa": "airflow",
    "mwaa-serverless": "airflow-serverless",
    "opensearchserverless": "aoss",
    "appintegrations": "app-integrations",
    "application-insights": "applicationinsights",
    "amp": "aps",
    "backupsearch": "backup-search",
    "connectcases": "cases",
    "cleanroomsml": "cleanrooms-ml",
    "codeguruprofiler": "codeguru-profiler",
    "connectcampaigns": "connect-campaigns",
    "connectcampaignsv2": "connect-campaigns",
    "efs": "elasticfilesystem",
    "elb": "elasticloadbalancing",
    "elbv2": "elasticloadbalancing",
    "emr": "elasticmapreduce",
    "elementalinference": "elemental-inference",
    "location": "geo",
    "connecthealth": "health-agent",
    "launch-wizard": "launchwizard",
    "migrationhuborchestrator": "migrationhub-orchestrator",
    "migrationhubstrategy": "migrationhub-strategy",
    "neptunedata": "neptune-db",
    "notificationscontacts": "notifications-contacts",
    "customer-profiles": "profile",
    "s3outposts": "s3-outposts",
    "supplychain": "scn",
    "socialmessaging": "social-messaging",
    "stepfunctions": "states",
    "workspaces-thin-client": "thinclient",
    "voice-id": "voiceid",
}


def bruteforce_actions_to_policies_format(actions):
    """
    Convert actions from enumerate-iam format ("elb.describe_load_balancers" or
    "elb:describe_load_balancers") to IAM policy format
    ("elasticloadbalancing:DescribeLoadBalancers").

    The service prefix is remapped via BRUTEFORCE_TO_POLICIES_SERVICE when it
    differs; the method is converted from snake_case to CamelCase.
    """
    result = []
    for action in actions:
        service, sep, method = action.partition(".")
        if not sep:
            service, sep, method = action.partition(":")
        policies_service = BRUTEFORCE_TO_POLICIES_SERVICE.get(service, service)
        camel_method = method.replace("_", " ").title().replace(" ", "")
        result.append(f"{policies_service}:{camel_method}")
    return result


def build_prefix_map(botocore_session):
    """
    Map every IAM/endpoint service prefix to its boto3 client name, so an IAM
    action like "elasticloadbalancing:..." can be resolved to the right client.
    Built once from the installed botocore and reused.
    """
    prefix_map = {}
    for svc in botocore_session.get_available_services():
        try:
            model = botocore_session.get_service_model(svc)
        except Exception:
            continue
        endpoint_prefix = model.metadata.get("endpointPrefix", svc)
        prefix_map.setdefault(endpoint_prefix, svc)
        prefix_map.setdefault(svc, svc)
    return prefix_map
