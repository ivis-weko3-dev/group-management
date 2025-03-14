import hashlib
import json
import time

import pytest
import requests
from mock import MagicMock, Mock, patch

from group_management.utils import (
    create_group,
    generate_request_body,
    generate_signature,
    get_access_token,
    get_authorization,
    get_task_status,
    process_entity_id,
    reset_redis,
    set_management_info,
    set_task_id,
)


def create_mock_response(status_code, response_json):
    response = requests.models.Response()
    response.status_code = status_code
    response.json = Mock(return_value=response_json)
    return response


def test_get_authorization(app, redis_connect):
    entity_id = "https://test-entity.org"
    cert_key = "test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX")
    cert_val = {
        "client_id": "test_client",
        "client_secret": "test_secret"
    }
    
    # cert_key in Redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)

        with patch("requests.get") as mockClient:
            redis_connect.set(cert_key, json.dumps(cert_val))
            result = get_authorization(entity_id)
            assert result == {
                "result": "Authrequest",
                "value": "https://dev2.cg.gakunin.jp/oauth/shib/authrequest.php?response_type=code&client_id=test_client&state=https%3A%2F%2Ftest-entity.org&redirect_uri=https%3A%2F%2Flocalhost%2Fgroup-management%2Fcreate"
            }
            mockClient.assert_not_called()

    # no cert_key in Redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)

        issue_response = {
            "client_id": "test_client",
            "client_secret": "test_secret"
        }
        with patch("requests.get") as mockClient:
            response = requests.models.Response()
            response.status_code = 200
            response.json = Mock(return_value=issue_response)
            mockClient.return_value = response
            result = get_authorization(entity_id)
            assert result == {
                "result": "Authrequest",
                "value": "https://dev2.cg.gakunin.jp/oauth/shib/authrequest.php?response_type=code&client_id=test_client&state=https%3A%2F%2Ftest-entity.org&redirect_uri=https%3A%2F%2Flocalhost%2Fgroup-management%2Fcreate"
            }

    # entity_id in Redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)

        redis_connect.set(entity_id, "work in progress")
        result = get_authorization(entity_id)
        result == {
            "result": "Error",
            "value": "Create group already running. Entity ID: https://test-entity.org"
        }

    # Redis keys() error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)
        with pytest.raises(Exception) as e:
            mockRedisDelete = patch("redis.client.Redis.delete")
            with patch("redis.client.Redis.keys") as mockRedis:
                mockRedis.side_effect = Exception("Redis keys error")
                result = get_authorization(entity_id)
            assert str(e) == "Redis error"
            mockRedisDelete.assert_not_called()


    # Redis set() error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)
        with pytest.raises(Exception) as e:
            mockRedisDelete = patch("redis.client.Redis.delete")
            with patch("redis.client.Redis.set") as mockRedis:
                mockRedis.side_effect = Exception("Redis set error")
                get_authorization(entity_id)
            assert str(e) == "Redis set error"
            mockRedisDelete.assert_not_called()

    # Redis get() error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(entity_id)
        with pytest.raises(Exception) as e:
            mockRedisDelete = patch("redis.client.Redis.delete")
            with patch("redis.client.Redis.get") as mockRedis:
                mockRedis.side_effect = Exception("Redis set error")
                get_authorization(entity_id)
            assert str(e) == "Redis set error"
            mockRedisDelete.assert_not_called()


def test_set_management_info(app, redis_connect, mocker):
    entity_id = "https://test-entity.org"
    management_info_key = "test_entity_org" + app.config.get("MANAGEMENT_INFO_SUFFIX")
    management_info_val = {
        "group_info": {
            "id": "jc_test_groups_test",
            "name": "test_group",
            "description": "test_description",
            "public": True
        },
        "service": "test_service",
        "member_info": "test_member.tsv"
    }

    # set management info
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        set_management_info(entity_id, management_info_val)
        actual = json.loads(redis_connect.get(management_info_key).decode())
        assert actual == management_info_val

    # Redis set() error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        mockRedisDelete = mocker.patch("redis.client.Redis.delete")
        with pytest.raises(Exception) as e:
            with patch("redis.client.Redis.set") as mockRedis:
                mockRedis.side_effect = Exception("Redis set error")
                set_management_info(entity_id, management_info_val)
        assert str(e.value) == "Redis set error"
        mockRedisDelete.assert_not_called()

    # Redis set() error (entity_id already exists)
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(entity_id)
        redis_connect.set(entity_id, "work in progress")
        with patch("redis.client.Redis.set", side_effect=Exception("Redis set error")):
            mockRedisDelete = mocker.patch("redis.client.Redis.delete")
            with pytest.raises(Exception) as e:
                set_management_info(entity_id, management_info_val)
            assert str(e.value) == "Redis set error"
            mockRedisDelete.assert_called_once()

def test_get_access_token(app, redis_connect, mocker):
    entity_id = "https://test-entity.org"
    cert_key = "test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX")
    cert_val = {
        "client_id": "test_client",
        "client_secret": "test_secret"
    }
    auth_code = "test_auth_code"
    response_mock_value = {
        "access_token": "test_token",
        "expires_in": 86400,
        "token_type": "Bearer",
        "scope": None,
        "refresh_token": "test_refresh_token"
    }
    management_info_key = "test_entity_org" + app.config.get("MANAGEMENT_INFO_SUFFIX")
    
    # get access token success
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.set(cert_key, json.dumps(cert_val))
        with patch("requests.post") as mockClient:
            response = requests.models.Response()
            response.status_code = 200
            response.json = Mock(return_value=response_mock_value)
            mockClient.return_value = response
            result = get_access_token(entity_id, auth_code)
            assert result == response_mock_value["access_token"]

    # no cert_key in Redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        with patch("requests.post") as mockClient:
            with pytest.raises(Exception) as e:
                get_access_token(entity_id, auth_code)
            assert str(e.value) == "Client certificate not found"

    # API error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(cert_key)
        redis_connect.delete(management_info_key)
        redis_connect.set(management_info_key, "work in progress")
        redis_connect.set(cert_key, json.dumps(cert_val))
        with patch("requests.post") as mockClient:
            mockRedisDelete = mocker.patch("redis.client.Redis.delete")
            response = requests.models.Response()
            response.status_code = 400
            response.json = Mock(return_value={"error": "invalid_request"})
            mockClient.return_value = response
            with pytest.raises(Exception):
                get_access_token(entity_id, auth_code)
            mockRedisDelete.assert_called_once()
            error_key = "test_entity_org" + app.config.get("CREATE_GROUP_ERR_SUFFIX")
            assert redis_connect.keys(error_key)


def test_create_group(app, redis_connect, mock_users_api, mock_groups_api, mocker):
    entity_id = "https://test-entity.org"
    management_info_key = "test_entity_org" + \
            app.config.get("MANAGEMENT_INFO_SUFFIX")
    service_name = "test_service"
    management_info_val_template = {
        "group_info": {
            "id": "jc_test_groups_test",
            "name": "test_group",
            "description": "test_description",
            "public": True
        },
        "service": service_name,
        "member_info": ""
    }
    access_token = "test_token"
    group_id = "test_group_id"
    create_group_err_key = "test_entity_org" + app.config.get("CREATE_GROUP_ERR_SUFFIX")
    create_group_key = "test_entity_org" + app.config.get("CREATE_GROUP_SUFFIX")
    create_group_url_response = {
        "totalResults": 1,
        "startIndex": 0,
        "itemPerPage": 10,
        "Resources": [{
            "id": group_id,
            "externalId": "jc_test_groups_test",
            "displayName": "test_group",
            "public": True,
            "description": "test_description",
            "meta": {
                "resourceType": "Group",
                "created": "2025-03-01T00:00:00Z",
                "lastModified": "2025-03-01T00:00:00Z"
            },
            "members": [],
            "administrators": [],
            "services": []
        }]
    }
    cert_val = {
        "client_id": "test_client",
        "client_secret": "test_secret"
    }
    mock_json_get = mock_users_api + mock_groups_api

    # create group success
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern1.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with patch("requests.post") as mockPostClient:
            mock_post_response = create_mock_response(200, create_group_url_response)
            mockPostClient.return_value = mock_post_response
            with patch("requests.get") as mockGetClient:
                get_responses = [
                    create_mock_response(200, get_mock_response)
                    for get_mock_response in mock_json_get
                ]
                mockGetClient.side_effect = get_responses
                with patch("requests.put",
                           return_value=create_mock_response(200, {})) as mockPutClient:
                    create_group(entity_id, access_token)
                    mockPutClient.call_count == 3
            # called only create-group
            mockPostClient.assert_called_once()
            
    # User not exists
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern2.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with patch("requests.post") as mockPostClient:
            mock_post_response = create_mock_response(200, create_group_url_response)
            mockPostClient.return_value = mock_post_response
            with patch("requests.get") as mockGetClient:
                mockGetClient.return_value = create_mock_response(200, {"totalResults": 0})
                with patch("requests.put",
                           return_value=create_mock_response(200, {})) as mockPutClient:
                    create_group(entity_id, access_token)
                    # called only update-group
                    mockPutClient.assert_called_once()
            mockPostClient.call_count == 4

    # create-group API error
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern2.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post") as mockPostClient:
                mock_post_response = create_mock_response(400, {"error": "invalid_request"})
                mockPostClient.return_value = mock_post_response
                create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)

    # Group creation information not found
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        with pytest.raises(Exception) as ex:
            create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)
    
    # Client certificate not found
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        redis_connect.delete("test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX"))
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with pytest.raises(Exception) as ex:
            create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)
    
    # Member type is invalid
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern3.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        redis_connect.set("test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX"), json.dumps(cert_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post"):
                create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)

    # Authorization level is invalid
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern4.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        redis_connect.set("test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX"), json.dumps(cert_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post"):
                with patch("requests.get") as mockGetClient:
                    get_responses = [
                        create_mock_response(200, get_mock_response)
                        for get_mock_response in mock_json_get
                    ]
                    mockGetClient.side_effect = get_responses
                    create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)
    
    # Order is invalid
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern5.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        redis_connect.set("test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX"), json.dumps(cert_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post"):
                with patch("requests.get") as mockGetClient:
                    get_responses = [
                        create_mock_response(200, get_mock_response)
                        for get_mock_response in mock_json_get
                    ]
                    mockGetClient.side_effect = get_responses
                    create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)

    # Member information file is not found
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/not_found.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post"):
                create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)

    # Member information file is invalid
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        redis_connect.delete(create_group_key)
        management_info_val = management_info_val_template.copy()
        management_info_val["member_info"] = "tests/member_mock_data/member_info_pattern1_csv.tsv"
        redis_connect.set(management_info_key, json.dumps(management_info_val))
        with pytest.raises(Exception) as ex:
            with patch("requests.post"):
                create_group(entity_id, access_token)
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.get(create_group_key).decode() == str(ex.value)

def test_process_entity_id():
    # process entity id
    actual = process_entity_id("https://test-entity.org")
    assert actual == "test_entity_org"
    
    # process entity id
    actual = process_entity_id("https://test_entity_org/test")
    assert actual == "test_entity_org"

def test_generate_request_body(app):
    data = {
        "externalId": "jc_test_groups_test",
        "displayName": "test_group",
        "description": "test_description",
        "public": True
    }
    access_token = "test_token"
    client_secret = "test_secret"
    current_time = time.time()
    mock_signature_value = "test_signature"

    # generate request body
    with app.test_request_context():
        with patch("time.time", return_value=current_time):
            with patch("group_management.utils.generate_signature", return_value=mock_signature_value):
                actual = generate_request_body(data, access_token, client_secret)
                assert actual == {
                    "request": {
                        "time_stamp": str(current_time),
                        "signature": mock_signature_value
                    },
                    "parameter": {
                        "externalId": "jc_test_groups_test",
                        "displayName": "test_group",
                        "description": "test_description",
                        "public": True
                    }
                }
                
def test_generate_signature(app):
    access_token = "test_token"
    time_stamp = str(1234567890.1234567)
    client_secret = "test_secret"

    # generate signature
    with app.test_request_context():
        actual = generate_signature(access_token, time_stamp, client_secret)
        expected = hashlib.sha256(f"{client_secret}{access_token}{time_stamp}".encode()).hexdigest()
        assert actual == expected

def test_set_task_id(app, redis_connect):
    entity_id = "https://test-entity.org"
    task_id = "1234567890"
    key = "test_key"

    # set task id
    with app.test_request_context():
        # Clear Redis
        target_key = "test_entity_org" + key
        redis_connect.delete(target_key)
        set_task_id(key, task_id, entity_id)
        actual = redis_connect.get(target_key)
        assert actual.decode() == task_id

def test_get_task_status(app, redis_connect):
    entity_id = "https://test-entity.org"
    task_id = "1234567890"
    key = "test_key"
    target_key = "test_entity_org" + key
    error_key = "test_entity_org" + app.config.get("CREATE_GROUP_ERR_SUFFIX")

    # get task status   
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)
        actual = get_task_status(key, entity_id)
        assert actual == {
            "create_status": True,
            "status": None,
            "error": None
        }
    
    # status is STARTED
    with app.test_request_context():
        # AsyncResultのモックを作成
        mock_async_result = MagicMock()
        mock_async_result.id = 1
        mock_async_result.status = "STARTED"
        mock_async_result.successful.return_value = False
        mock_async_result.failed.return_value = False
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)
        redis_connect.set(target_key, 1)
        with patch("group_management.utils.AsyncResult", return_value=mock_async_result):
            actual = get_task_status(key, entity_id)
            assert actual == {
                "create_status": True,
                "status": "STARTED",
                "error": None
            }
            
    # status is SUCCESS
    with app.test_request_context():
        # AsyncResultのモックを作成
        mock_async_result = MagicMock()
        mock_async_result.id = 1
        mock_async_result.status = "SUCCESS"
        mock_async_result.successful.return_value = True
        mock_async_result.failed.return_value = False
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)
        redis_connect.set(target_key, 1)
        with patch("group_management.utils.AsyncResult", return_value=mock_async_result):
            actual = get_task_status(key, entity_id)
            assert actual == {
                "create_status": False,
                "status": "SUCCESS",
                "error": None
            }
            
    # status is FAILURE
    with app.test_request_context():
        # AsyncResultのモックを作成
        mock_async_result = MagicMock()
        mock_async_result.id = 1
        mock_async_result.status = "FAILURE"
        mock_async_result.successful.return_value = False
        mock_async_result.failed.return_value = True
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)
        redis_connect.set(target_key, 1)
        redis_connect.set(error_key, "Test Error.")
        with patch("group_management.utils.AsyncResult", return_value=mock_async_result):
            actual = get_task_status(key, entity_id)
            assert actual == {
                "create_status": False,
                "status": "FAILURE",
                "error": "Test Error."
            }

    # status is REVOKED
    with app.test_request_context():
        # AsyncResultのモックを作成
        mock_async_result = MagicMock()
        mock_async_result.id = 1
        mock_async_result.status = "REVOKED"
        mock_async_result.state = "REVOKED"
        mock_async_result.successful.return_value = False
        mock_async_result.failed.return_value = False
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)
        redis_connect.set(target_key, 1)
        redis_connect.set(error_key, "Test Error.")
        with patch("group_management.utils.AsyncResult", return_value=mock_async_result):
            actual = get_task_status(key, entity_id)
            assert actual == {
                "create_status": False,
                "status": "REVOKED",
                "error": "Test Error."
            }

    # exception occurred
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(target_key)
        redis_connect.delete(error_key)

        with pytest.raises(Exception) as e:
            with patch("redis.client.Redis.get", side_effect=Exception("Redis get error")):
                get_task_status(key, entity_id)
        assert str(e.value) == "Redis get error"

def test_reset_redis(app, redis_connect):
    entity_id  = "https://test-entity.org"
    management_info_key = "test_entity_org" + app.config.get("MANAGEMENT_INFO_SUFFIX")
    create_group_key = "test_entity_org" + app.config.get("CREATE_GROUP_SUFFIX")
    create_group_err_key = "test_entity_org" + app.config.get("CREATE_GROUP_ERR_SUFFIX")
    
    # reset redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.set(entity_id, "work in progress")
        redis_connect.set(create_group_key, "work in progress")
        redis_connect.set(management_info_key, "work in progress")
        redis_connect.set(create_group_err_key, "work in progress")
        reset_redis(entity_id)
        assert redis_connect.keys(entity_id) == []
        assert redis_connect.keys(create_group_key) == []
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.keys(create_group_err_key) == []
        
    # reset redis
    with app.test_request_context():
        # Clear Redis
        redis_connect.delete(entity_id)
        redis_connect.delete(create_group_key)
        redis_connect.delete(management_info_key)
        redis_connect.delete(create_group_err_key)
        reset_redis(entity_id)
        assert redis_connect.keys(entity_id) == []
        assert redis_connect.keys(create_group_key) == []
        assert redis_connect.keys(management_info_key) == []
        assert redis_connect.keys(create_group_err_key) == []