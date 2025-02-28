from celery.result import AsyncResult
import csv
import hashlib
import json
import requests
from requests.auth import HTTPBasicAuth
import time
from urllib.parse import urlencode, urlparse

from .config import AUTHORIZATION_BASE_URL, CERT_FILE, CLIENT_CERT_SUFFIX,CORE_BASE_URL, CREATE_GROUP_ERR_SUFFIX,\
    CREATE_GROUP_SUFFIX, KEY_FILE, MANAGEMENT_DB, MANAGEMENT_INFO_SUFFIX, REDIRECT_URL, USER_AUTHORIZATION
from .redis import RedisConnection

def get_authorization(entity_id):
    """Get the authorization URL
    
    Args:
        entity_id (str): Entity ID
        
    Returns:
        dict: Response
            result (str): Result
            value (str): Authorization URL or error message
    """
    try:
        # Connect to Redis
        redis = RedisConnection().connection(MANAGEMENT_DB)
        new_flg = False
        # Check if the group creation process is already running
        if redis.keys(entity_id):
            return {
                'result': 'Error',
                'value': 'Create group already running. Entity ID: {}'.format(entity_id)
            }
        
        # Save the entity ID to Redis
        new_flg = True
        redis.set(entity_id, '')
        # Get the client certificate
        replaced_entity_id = process_entity_id(entity_id)
        cert_key = replaced_entity_id + CLIENT_CERT_SUFFIX
        cert_dict = json.loads(redis.get(cert_key, {}))
        if not cert_dict:
            # if the client certificate does not exist, get it
            issue_params = {
                'entityid': entity_id,
                'redirect_uri': REDIRECT_URL
            }
            issue_url = '{}/sslauth/issue.php?{}'.format(AUTHORIZATION_BASE_URL, urlencode(issue_params))
            response = requests.get(issue_url, cert=(CERT_FILE.format(replaced_entity_id), KEY_FILE.format(replaced_entity_id)))
            response.raise_for_status()
            cert_dict = response.json()
            redis.set(cert_key, json.dumps(cert_dict))

        params = {
            'response_type': 'code',
            'client_id': cert_dict.get('client_id'),
            'state': entity_id,
            'redirect_uri': REDIRECT_URL
        }

        # Generate the authorization request URL
        authrequest_url = '{}/shib/authrequest.php?{}'.format(AUTHORIZATION_BASE_URL, urlencode(params))
        return {
            'result': 'Authrequest',
            'value': authrequest_url
        }
    except Exception as ex:
        if new_flg and redis.keys(entity_id):
            redis.delete(entity_id)
        raise ex
    finally:
        redis.close()

def set_management_info(entity_id, info):
    """Save the group creation information
    
    Args:
        entity_id (str): Entity ID
        info (dict): Group creation information
    """
    try:
        # Connect to Redis
        redis = RedisConnection().connection(MANAGEMENT_DB)
        # Save the group creation information to Redis
        replaced_entity_id = process_entity_id(entity_id)
        redis.set(replaced_entity_id + MANAGEMENT_INFO_SUFFIX, json.dumps(info))
    except Exception as ex:
        if redis.keys(entity_id):
            redis.delete(entity_id)
        raise ex
    finally:
        redis.close()

def get_access_token(entity_id, authorization_code):
    """Get the access token
    
    Args:
        entity_id (str): Entity ID
        authorization_code (str): Authorization code
        
    Returns:
        str: Access token
    """
    try:
        # Connect to Redis
        redis = RedisConnection().connection(MANAGEMENT_DB)
        # Get the client certificate
        replaced_entity_id = process_entity_id(entity_id)
        cert_key = replaced_entity_id + CLIENT_CERT_SUFFIX
        cert_dict = json.loads(redis.get(cert_key))
        # Get the access token
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': REDIRECT_URL
        }
        token_url = '{}/token.php'.format(AUTHORIZATION_BASE_URL)
        response = requests.post(token_url, data=data, auth=HTTPBasicAuth(cert_dict.get('client_id'), cert_dict.get('client_secret')))
        response.raise_for_status()
        response_json = response.json()
        return response_json.get('access_token')
    except Exception as ex:
        if redis.get(replaced_entity_id + MANAGEMENT_INFO_SUFFIX):
            redis.delete(replaced_entity_id + MANAGEMENT_INFO_SUFFIX)
        redis.set(replaced_entity_id + CREATE_GROUP_ERR_SUFFIX, str(ex))
        raise ex
    finally:
        redis.close()

def create_group(entity_id, access_token):
    """Create a group
    
    Args:
        entity_id (str): Entity ID
        access_token (str): Access token
    """
    try:
        # Connect to Redis
        redis = RedisConnection().connection(MANAGEMENT_DB)
        # Get the client certificate
        replaced_entity_id = process_entity_id(entity_id)
        management_info = json.loads(redis.get(replaced_entity_id + MANAGEMENT_INFO_SUFFIX))
        client_cert_key = replaced_entity_id + CLIENT_CERT_SUFFIX
        client_cert = json.loads(redis.get(client_cert_key))
        client_secret = client_cert.get('client_secret')
        # Get the group information to be created
        group_info = management_info.get('group_info')
        group_info_data = {
            'displayName': group_info.get('name'),
            'description': group_info.get('description'),
            'public': group_info.get('public')
        }
        data = generate_request_body(group_info_data, access_token, client_secret)
        create_group_url = '{}/Groups'.format(CORE_BASE_URL)
        headers = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        response = requests.post(create_group_url, data=data, headers=headers)
        response.raise_for_status()
        target_group_resource = response.json().get('Resources')[0]

        # Get the group members and administrators
        members = []
        administrators = []
        member_info_file = management_info.get('member_info')
        if member_info_file:
            with open(member_info_file, 'r') as f:
                member_info = csv.DictReader(f, delimiter='\t')
            for member in member_info:
                member_type = member.get('type')
                if member_type == 'user':
                    # Get the user information from mAP Core
                    time_stamp = str(time.time())
                    signature = generate_signature(access_token, time_stamp, client_secret)
                    eppn = member.get('eppn')
                    get_users_params = {
                        'filter': 'eduPersonPrincipalNames.eduPersonPrincipalName eq "{}"'.format(eppn),
                        'time_stamp': time_stamp,
                        'signature': signature
                    }
                    get_users_url = '{}/Users?{}'.format(CORE_BASE_URL, urlencode(get_users_params))
                    response = requests.get(get_users_url, headers=headers)
                    response.raise_for_status()
                    response_json = response.json()
                    if response_json.get('totalResults') == 0:
                        # Create a new user if the user does not exist
                        user_data = {
                            'userName': member.get('name'),
                            'emails': [
                                {
                                    'value': member.get('email')
                                }
                            ],
                            'eduPersonPrincipalNames': [
                                {
                                    'eduPersonPrincipalName': eppn
                                }
                            ]
                        }
                        data = generate_request_body(user_data, access_token, client_secret)
                        create_user_url = '{}/Users'.format(CORE_BASE_URL)
                        response = requests.post(create_user_url, data=data, headers=headers)
                        response.raise_for_status()
                        response_json = response.json()
                    user = {
                        'type': 'User',
                        'value': response_json.get('Resources')[0].get('id')
                    }
                    user_auth = member.get('auth')
                    # Add the user to the group with the authorization level
                    if user_auth == USER_AUTHORIZATION.get('member'):
                        members.append(user)
                    elif user_auth == USER_AUTHORIZATION.get('admin'):
                        user.pop('type')
                        administrators.append(user)
                    elif user_auth == USER_AUTHORIZATION.get('member_admin'):
                        members.append(user)
                        user.pop('type')
                        administrators.append(user)
                elif member_type == 'group':
                    # Get the group information from mAP Core
                    time_stamp = str(time.time())
                    signature = generate_signature(access_token, time_stamp, client_secret)
                    group_name = member.get('name')
                    get_groups_params = {
                        'filter': 'displayName eq "{}"'.format(group_name),
                        'time_stamp': time_stamp,
                        'signature': signature
                    }
                    get_groups_url = '{}/Groups?{}'.format(CORE_BASE_URL, urlencode(get_groups_params))
                    response = requests.get(get_groups_url, headers=headers)
                    response.raise_for_status()
                    response_json = response.json()
                    if response_json.get('totalResults') != 0:
                        order = member.get('order')
                        if order == 'higher':
                            # Add the target group to the group
                            resource = response_json.get('Resources')[0]
                            group = {
                                'type': 'Group',
                                'value': target_group_resource.get('id')
                            }
                            resource.get('members').append(group)
                            data = generate_request_body(resource, access_token, client_secret)
                            update_group_url = '{}/Groups/{}'.format(CORE_BASE_URL, resource.get('id'))
                            response = requests.put(update_group_url, data=data, headers=headers)
                            response.raise_for_status()
                        elif order == 'lower':
                            # Add the group to the target group
                            group = {
                                'type': 'Group',
                                'value': response_json.get('Resources')[0].get('id')
                            }
                            members.append(group)
        
        # Get the services
        service = management_info.get('service')
        service_list = []
        if service:
            service_list = [{'value': service}]
        
        # Update the group information
        target_group_resource['members'] = members
        target_group_resource['administrators'] = administrators
        target_group_resource['services'] = service_list
        data = generate_request_body(target_group_resource, access_token, client_secret)
        update_group_url = '{}/Groups/{}'.format(CORE_BASE_URL, target_group_resource.get('id'))
        response = requests.put(update_group_url, data=data, headers=headers)
        response.raise_for_status()
    except Exception as ex:
        if redis.get(replaced_entity_id + MANAGEMENT_INFO_SUFFIX):
            redis.delete(replaced_entity_id + MANAGEMENT_INFO_SUFFIX)
        redis.set(replaced_entity_id + CREATE_GROUP_ERR_SUFFIX, str(ex))
        raise ex
    finally:
        redis.close()

def process_entity_id(entity_id):
    """Replace the entity ID with an underscore
    
    Args:
        entity_id (str): Entity ID
        
    Returns:
        str: Replaced entity ID
    """
    # Replace the entity ID with an underscore
    entity_id_domain = urlparse(entity_id).netloc
    replaced_entity_id = entity_id_domain.replace('.', '_').replace('-', '_')
    return replaced_entity_id

def generate_request_body(data, access_token, client_secret):
    """Generate the request body
    
    Args:
        data (dict): Data
        access_token (str): Access token
        client_secret (str): Client secret
        
    Returns:
        dict: Request body
    """
    # Generate the request body
    time_stamp = str(time.time())
    signature = generate_signature(access_token, time_stamp, client_secret)
    generated_data = {
        'request': {
            'time_stamp': time_stamp,
            'signature': signature
        },
        'parameter': data
    }
    return generated_data

def generate_signature(access_token, time_stamp, client_secret):
    """Generate the signature

    Args:
        access_token (str): Access token
        time_stamp (str): Time stamp
        client_secret (str): Client secret

    Returns:
        str: Signature
    """
    # Generate the signature as a hash value
    return hashlib.sha256((client_secret + access_token + time_stamp).encode()).hexdigest()

def set_task_id(key, task_id, entity_id):
    """Save the task ID
    
    Args:
        key (str): Key
        task_id (str): Task ID
        entity_id (str): Entity ID
    """
    # Connect to Redis
    redis = RedisConnection().connection(MANAGEMENT_DB)
    # Save the task ID to Redis
    replaced_entity_id = process_entity_id(entity_id)
    redis.set(replaced_entity_id + key, task_id)
    redis.close()

def get_task_status(key, entity_id):
    """Get the task status

    Args:
        key (str): Key
        entity_id (str): Entity ID

    Returns:
        dict: Task status
            create_status (bool): Create group task status
            status (str): Task status
            error (str): Error message
    """
    try:
        # Connect to Redis
        redis = RedisConnection().connection(MANAGEMENT_DB)

        create_status = True
        status = None

        # Get the task status from Redis
        replaced_entity_id = process_entity_id(entity_id)
        task_id = redis.get(replaced_entity_id + key)
        if task_id:
            result = AsyncResult(task_id)
            status_cond = result.successful() or result.failed() or result.state == 'REVOKED'
            status = result.status
            create_status = True if not status_cond else False
        return {
            'create_status': create_status,
            'status': status,
            'error': redis.get(replaced_entity_id + CREATE_GROUP_ERR_SUFFIX)
        }
    except Exception as ex:
        raise ex
    finally: 
        redis.close()

def reset_redis(entity_id):
    """Reset Redis

    Args:
        entity_id (str): Entity ID
    """
    # Connect to Redis
    if not redis:
        redis = RedisConnection().connection(MANAGEMENT_DB)
    # Delete the keys in Redis
    replaced_entity_id = process_entity_id(entity_id)
    redis.delete(entity_id)
    redis.delete(replaced_entity_id + MANAGEMENT_INFO_SUFFIX)
    redis.delete(replaced_entity_id + CREATE_GROUP_SUFFIX)
    redis.delete(replaced_entity_id + CREATE_GROUP_ERR_SUFFIX)
    redis.close()