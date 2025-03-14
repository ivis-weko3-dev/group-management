
import json

from flask import url_for
from mock import MagicMock, patch


def test_create_group(client):
    """Test create_group function""" 
    request_body = {
        "code": "authorization_code",
        "state": "entity_id",
        "shib_login": "shibboleth",
        "idp": "idp_entity_id",
        "eppn": "eppn"
    }
    create_group_url = url_for('group_management.create_group')

    # Test create_group function
    task = MagicMock()
    task.id = 1
    with patch("group_management.api.create_group_task.apply_async", return_value=task):
        actual = client.post(create_group_url, data=json.dumps(request_body),
                        content_type='application/json')
        expected = {
            'code': 200,
            'message': 'Create group task created successfully',
        }
        assert actual.status_code == 200
        assert actual.json == expected

def test_get_status(client, mocker):
    """Test get_status function"""
    entity_id = "https://test-entity.org"    
    get_status_url = url_for('group_management.get_status')

    # Test get_status function
    get_task_status_mock_value = {
        "create_status": True,
        "status": "STARTED",
        "error": ""
    }
    with patch("group_management.api.get_task_status", return_value=get_task_status_mock_value):
        mockResetRedis = mocker.patch("group_management.utils.reset_redis")
        actual = client.get(get_status_url, query_string={"entity_id": entity_id})
        assert actual.status_code == 200
        assert actual.json == get_task_status_mock_value
        mockResetRedis.assert_not_called()
        
    # Test get_status function (status is SUCCESS)
    get_task_status_mock_value2 = {
        "create_status": False,
        "status":"SUCCESS",
        "error": ""
    }
    with patch("group_management.api.get_task_status", return_value=get_task_status_mock_value2):
        mockResetRedis = mocker.patch("group_management.api.reset_redis")
        actual = client.get(get_status_url, query_string={"entity_id": entity_id})
        assert actual.status_code == 200
        assert actual.json == get_task_status_mock_value2
        mockResetRedis.assert_called_once()