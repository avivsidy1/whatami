"""
IAM Account Enumerator

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.

Initial code from:

    https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e

Improvements:
    * Complete refactoring
    * Results returned in a programmatic way
    * Threads
    * Improved logging
    * Increased API call coverage
    * Export as a library
"""
import re
import sys
import json
import logging
import boto3
import botocore
import random

from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing.dummy import Pool as ThreadPool

from enumerate_iam.utils.remove_metadata import remove_metadata
from enumerate_iam.utils.json_utils import json_encoder
from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

# Concurrency sweet spot: high enough to be fast, low enough to stay under
# AWS's per-account/region request-rate limit. Going much higher (e.g. 30)
# drains the throttle bucket in a burst, after which adaptive retry clamps the
# send rate and every throttled call backs off -- which is SLOWER overall, not
# faster. The denial-retry fix in check_one_permission is what gives the real
# speedup; this stays moderate to avoid the throttling cliff.
MAX_THREADS = 15
CLIENT_POOL = {}


def report_arn(candidate):
    """
    Attempt to extract and slice up an ARN from the input string
    """
    logger = logging.getLogger()

    arn_search = re.search(r'.*(arn:aws:.*?) .*', candidate)

    if arn_search:
        arn = arn_search.group(1)

        arn_id = arn.split(':')[4]
        arn_path = arn.split(':')[5]

        logger.info('-- Account ARN : %s', arn)
        logger.info('-- Account Id  : %s', arn.split(':')[4])
        logger.info('-- Account Path: %s', arn.split(':')[5])

        return arn, arn_id, arn_path

    return None, None, None


def _render_progress(done, total, worked):
    """Draw a single-line progress bar on stderr (overwritten in place via \\r)."""
    width = 30
    frac = (done / total) if total else 1.0
    filled = int(width * frac)
    bar = '#' * filled + '-' * (width - filled)
    sys.stderr.write('\r  [%s] %d/%d (%.0f%%)  worked: %d' %
                     (bar, done, total, frac * 100, worked))
    sys.stderr.flush()


def enumerate_using_bruteforce(access_key, secret_key, session_token, region):
    """
    Attempt to brute-force common describe calls.
    """
    output = dict()

    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list brute force.')

    # Total number of (service, action) probes we will actually make (only
    # services reachable in this region), so the bar below has the right target.
    total = sum(len(BRUTEFORCE_TESTS[s]) for s in services_for_region(region))

    pool = ThreadPool(MAX_THREADS)
    args_generator = generate_args(access_key, secret_key, session_token, region)

    # imap_unordered yields each result as its thread finishes (map() blocks
    # until everything is done), so we can count and show progress live.
    done = 0
    try:
        for thread_result in pool.imap_unordered(check_one_permission, args_generator):
            done += 1
            if thread_result is not None:
                key, action_result = thread_result
                output[key] = action_result
            _render_progress(done, total, len(output))
        sys.stderr.write('\n')
    except KeyboardInterrupt:
        sys.stderr.write('\n')
        logger.info('Ctrl+C received, stopping all threads.')
        logger.info('Hit Ctrl+C again to force exit.')
        try:
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            print('')
        return output

    pool.close()
    pool.join()

    return output


def services_for_region(region):
    """BRUTEFORCE_TESTS services that actually have a reachable endpoint in
    `region`, so we don't waste the pass on slow connect timeouts to services
    that only live elsewhere.

    Kept when the service's endpoint list is empty/unknown (newer services the
    endpoint data doesn't enumerate) or already includes `region`. When the
    list is non-empty and excludes `region`, we keep it only if it still
    resolves to a non-regional (global) endpoint -- e.g. AWS Health resolves to
    global.health.amazonaws.com and is reachable from any region -- and skip it
    only when it resolves to a region-specific host that genuinely isn't served
    here (e.g. devicefarm, sagemaker-geospatial in us-west-2 only).
    """
    session = boto3.Session()
    names = []
    for service_name in BRUTEFORCE_TESTS:
        try:
            regions = session.get_available_regions(service_name)
        except Exception:
            regions = []
        if (not regions) or (region in regions):
            names.append(service_name)
            continue
        try:
            endpoint = session.client(service_name, region_name=region).meta.endpoint_url
        except Exception:
            continue  # can't even build a client here -> not reachable, skip
        if region not in endpoint:   # global endpoint (region not in the host)
            names.append(service_name)
    return names


def generate_args(access_key, secret_key, session_token, region):

    service_names = services_for_region(region)

    random.shuffle(service_names)

    for service_name in service_names:
        actions = list(BRUTEFORCE_TESTS[service_name])
        random.shuffle(actions)

        for action in actions:
            yield access_key, secret_key, session_token, region, service_name, action


def get_client(access_key, secret_key, session_token, service_name, region):
    key = '%s-%s-%s-%s-%s' % (access_key, secret_key, session_token, service_name, region)

    client = CLIENT_POOL.get(key, None)
    if client is not None:
        return client

    logger = logging.getLogger()
    logger.debug('Getting client for %s in region %s' % (service_name, region))

    # connect_timeout kept short: a reachable endpoint connects well under 2s,
    # so an unreachable one fails fast instead of stalling the pass. read_timeout
    # stays generous for genuinely slow-but-valid responses. Retries left high
    # (adaptive) so throttled calls are still re-tried -- integrity over speed.
    config = Config(connect_timeout=2,
                    read_timeout=5,
                    retries={'mode': 'adaptive', 'max_attempts': 3},
                    max_pool_connections=MAX_POOL_CONNECTIONS * 2)

    try:
        client = boto3.client(
            service_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
            verify=False,
            config=config,
        )
    except:
        # The service might not be available in this region
        return

    CLIENT_POOL[key] = client

    return client


def check_one_permission(arg_tuple):
    access_key, secret_key, session_token, region, service_name, operation_name = arg_tuple
    logger = logging.getLogger()

    service_client = get_client(access_key, secret_key, session_token, service_name, region)
    if service_client is None:
        return

    try:
        action_function = getattr(service_client, operation_name)
    except AttributeError:
        # The service might not have this action (this is most likely
        # an error with generate_bruteforce_tests.py)
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    logger.debug('Testing %s.%s() in region %s' % (service_name, operation_name, region))

    # Only a *transient* failure is ambiguous under the concurrent load this
    # tool generates (throttling / 5xx / network blip) -- retry those once
    # before concluding the action doesn't work. A definitive denial
    # (AccessDenied, auth failure, ...) is deterministic, so retrying it only
    # doubles the API calls without ever changing the result; treat it as
    # "doesn't work" on the first response. (botocore's own adaptive retry
    # already re-tries throttling/5xx internally before we ever see them.)
    NETWORK_EXCEPTIONS = (
        botocore.exceptions.EndpointConnectionError,
        botocore.exceptions.ConnectTimeoutError,
        botocore.exceptions.ReadTimeoutError,
    )
    TRANSIENT_CODES = (
        'Throttling', 'ThrottlingException', 'ThrottledException',
        'TooManyRequestsException', 'RequestThrottled', 'RequestThrottledException',
        'RequestLimitExceeded', 'SlowDown', 'PriorRequestNotComplete',
    )

    def _is_transient(client_error):
        err = client_error.response.get('Error', {})
        status = client_error.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
        return status >= 500 or err.get('Code', '') in TRANSIENT_CODES

    action_response = None
    for attempt in range(2):
        try:
            action_response = action_function()
            break
        except botocore.exceptions.ClientError as error:
            if attempt == 0 and _is_transient(error):
                logger.debug('%s.%s() transient failure, retrying...' % (service_name, operation_name))
                continue
            return
        except NETWORK_EXCEPTIONS:
            # botocore's own adaptive retry already retried the connection up to
            # max_attempts before raising, so a second manual cycle here just
            # doubles the stall on an unreachable endpoint. Treat as not-worked.
            return
        except botocore.exceptions.ParamValidationError:
            logger.error('Remove %s.%s action' % (service_name, operation_name))
            return
        except Exception as error:
            # Any other per-action failure (e.g. NoAuthTokenError for
            # bearer-token-only services like codecatalyst, or an unexpected
            # client/signing error): we can't test this action with these
            # credentials, so treat it as "doesn't work" and move on rather
            # than letting one service abort the whole enumeration.
            logger.debug('%s.%s() skipped: %s' % (service_name, operation_name, error))
            return

    msg = '-- %s.%s() worked!'
    args = (service_name, operation_name)
    logger.info(msg % args)

    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(process)d - [%(levelname)s] %(message)s',
    )

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # import botocore.vendored.requests.packages.urllib3 as urllib3
    urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)


def enumerate_iam(access_key, secret_key, session_token, region):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens.
    """
    output = dict()
    configure_logging()

    output['iam'] = enumerate_using_iam(access_key, secret_key, session_token, region)
    output['bruteforce'] = enumerate_using_bruteforce(access_key, secret_key, session_token, region)

    return output


def enumerate_using_iam(access_key, secret_key, session_token, region):
    output = dict()
    logger = logging.getLogger()

    # Connect to the IAM API and start testing.
    logger.info('Starting permission enumeration for access-key-id "%s"', access_key)
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    # Try for the kitchen sink.
    try:
        everything = iam_client.get_account_authorization_details()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ReadTimeoutError):
        pass
    else:
        logger.info('Run for the hills, get_account_authorization_details worked!')
        logger.info('-- %s', json.dumps(everything, indent=4, default=json_encoder))

        output['iam.get_account_authorization_details'] = remove_metadata(everything)

    enumerate_user(iam_client, output)
    enumerate_role(iam_client, output)

    return output


def enumerate_role(iam_client, output):
    logger = logging.getLogger()

    # This is the closest thing we have to a role ARN
    user_or_role_arn = output.get('arn', None)

    if user_or_role_arn is None:
        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return

    # Attempt to get role to start.
    try:
        role = iam_client.get_role(RoleName=user_or_role_arn)
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        if arn is not None:
            output['arn'] = arn
            output['arn_id'] = arn_id
            output['arn_path'] = arn_path

        if 'role' not in user_or_role_arn:
            # We did out best, but we got nothing from iam
            return
        else:
            role_name = user_or_role_arn

    else:
        output['iam.get_role'] = remove_metadata(role)
        role_name = role['Role']['RoleName']

    # Attempt to get policies attached to this user.
    try:
        role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d attached policies',
            role['Role']['RoleName'],
            len(role_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
    try:
        role_policies = iam_client.list_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            role['Role']['RoleName'],
            len(role_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in role_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    return output


def enumerate_user(iam_client, output):
    logger = logging.getLogger()
    output['root_account'] = False

    # Attempt to get user to start.
    try:
        user = iam_client.get_user()
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        output['arn'] = arn
        output['arn_id'] = arn_id
        output['arn_path'] = arn_path

        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return
    else:
        output['iam.get_user'] = remove_metadata(user)

    if 'UserName' not in user['User']:
        if user['User']['Arn'].endswith(':root'):
            # OMG
            logger.warn('Found root credentials!')
            output['root_account'] = True
            return
        else:
            logger.error('Unexpected iam.get_user() response: %s' % user)
            return
    else:
        user_name = user['User']['UserName']

    # Attempt to get policies attached to this user.
    try:
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d attached policies',
            user_name,
            len(user_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
    try:
        user_policies = iam_client.list_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            user_name,
            len(user_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    # Attempt to get the groups attached to this user.
    user_groups = dict()
    user_groups['Groups'] = []

    try:
        user_groups = iam_client.list_groups_for_user(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_groups_for_user'] = remove_metadata(user_groups)

        logger.info(
            'User "%s" has %0d groups associated',
            user_name,
            len(user_groups['Groups'])
        )

    # Attempt to get the group policies
    output['iam.list_group_policies'] = dict()

    for group in user_groups['Groups']:
        try:
            group_policy = iam_client.list_group_policies(GroupName=group['GroupName'])

            output['iam.list_group_policies'][group['GroupName']] = remove_metadata(group_policy)

            logger.info(
                '-- Group "%s" has %0d inline policies',
                group['GroupName'],
                len(group_policy['PolicyNames'])
            )

            # List all group policy names.
            for policy in group_policy['PolicyNames']:
                logger.info('---- Policy "%s"', policy)
        except botocore.exceptions.ClientError as err:
            pass

    return output

