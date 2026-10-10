"""
Regenerates bruteforce_tests.py.

Originally this parsed AWS SDK for JavaScript API definition files
(aws-sdk-js/apis/*.min.json) checked out as a sibling directory. That
directory isn't part of this project and the upstream aws-sdk-js repo
lags behind current AWS services, so the generated list was stuck at 138
services / 876 actions with several since-retired services (e.g. "a4b" /
Alexa for Business) still present and many current services missing
entirely.

This version sources directly from the installed botocore package's
service models instead -- the same models boto3 itself uses to build
clients -- which covers every service/operation botocore currently knows
about and stays current with `pip install --upgrade botocore`.

Filtering rules:
  - operation's snake_case name must contain "list_", "describe_", or
    "get_" (the tool only wants read-only enumeration calls)
  - operation must be callable with zero arguments (no required input
    members) -- main.py's check_one_permission() calls the method with no
    arguments at all

No other exclusions are applied: every current AWS service is covered, and
a service is only left out of the output entirely if it has zero
list/describe/get actions with no required parameters.
"""
import json

import botocore.session
from botocore import xform_name

OUTPUT_FMT = 'BRUTEFORCE_TESTS = %s'
OUTPUT_FILE = 'bruteforce_tests.py'

OPERATION_CONTAINS = {
    'list_',
    'describe_',
    'get_',
}


def is_dangerous(operation_name):
    for safe in OPERATION_CONTAINS:
        if safe in operation_name:
            return False

    return True


def extract_operations(service_model):
    operations = []

    for operation_name in service_model.operation_names:
        snake_name = xform_name(operation_name)

        if is_dangerous(snake_name):
            continue

        op_model = service_model.operation_model(operation_name)
        input_shape = op_model.input_shape

        if input_shape is None or not input_shape.required_members:
            operations.append(snake_name)

    operations = sorted(set(operations))
    return operations


def main():
    bruteforce_tests = dict()

    session = botocore.session.get_session()

    for service_name in sorted(session.get_available_services()):
        try:
            service_model = session.get_service_model(service_name)
        except Exception as e:
            print('%s could not be loaded: %s' % (service_name, e))
            continue

        operations = extract_operations(service_model)

        if not operations:
            continue

        bruteforce_tests[service_name] = operations

    output = OUTPUT_FMT % json.dumps(bruteforce_tests,
                                     indent=4,
                                     sort_keys=True)

    open(OUTPUT_FILE, 'w').write(output)

    total_actions = sum(len(v) for v in bruteforce_tests.values())
    print('Wrote %d services / %d actions to %s' % (
        len(bruteforce_tests), total_actions, OUTPUT_FILE))


if __name__ == '__main__':
    main()
