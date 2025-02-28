import argparse
import json
import requests
import subprocess
import sys
import time

from group_management.config import HOST_NAME
from group_management.utils import get_authorization, set_management_info

# Set up the argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-e', '--entity-id', required=True, help='Entity ID')
parser.add_argument('-g', '--group-info', required=True, help='Group information Path')
parser.add_argument('-s', '--service', required=True, help='Service ID')
parser.add_argument('-m', '--member-info', help='Member information Path')

# Parse the arguments
args = parser.parse_args()
entity_id = args.entity_id
management_info = {
    'group_info': json.loads(args.group_info),
    'service_id': args.service,
    'member_info': args.member_info
}

# Get the generated authorization URL
auth_result = get_authorization(entity_id)
if auth_result['result'] == 'Error':
    sys.exit(auth_result['value'])

# Set the management information in Redis
set_management_info(entity_id, management_info)

# Open the authorization URL in the browser
subprocess.Popen(['xdg-open', auth_result['value']])

# Wait for the task of creating the group to complete
while True:
    result = requests.get('https://{}/group-management/status?entity_id={}'.format(HOST_NAME, entity_id), verify=False)
    if not result.json().get('create_status'):
        break
    time.sleep(10)

# Check if the group was created successfully
if result.json().get('error'):
    sys.exit(result.json().get('error'))
else:
    print('Group created successfully')
