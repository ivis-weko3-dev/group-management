import json
import subprocess

import pytest
import requests
from mock import Mock, patch

from group import main


def reset_test_cache(redis_connect, entity_id, cert_key, management_info_key, error_key, create_group_key):
    redis_connect.delete(entity_id)
    redis_connect.delete(cert_key)
    redis_connect.delete(management_info_key)
    redis_connect.delete(error_key)
    redis_connect.delete(create_group_key)


def test_main(app, redis_connect, capsys):
    entity_id = "https://test-entity.org"
    cert_key = "test_entity_org" + app.config.get("CLIENT_CERT_SUFFIX")
    management_info_key = "test_entity_org" + app.config.get("MANAGEMENT_INFO_SUFFIX")
    error_key = "test_entity_org" + app.config.get("CREATE_GROUP_ERR_SUFFIX")
    create_group_key = "test_entity_org" + app.config.get("CREATE_GROUP_SUFFIX")

    get_authorization_success_return_value = {
        "result": "Authrequest",
        "value": "https://dev2.cg.gakunin.jp/oauth/shib/authrequest.php" \
            "?response_type=code&client_id=test_client&state=https%3A%2F%2Ftest-entity.org&redirect_uri=https%3A%2F%2Flocalhost%2Fgroup-management%2Fcreate"
    }

    group_info = {
        "name": "test_group",
        "description": "test_description",
        "public": True,
    }
    service = "service_id"
    member_info = "module/group-management/tests/member_mock_data/member_info.tsv"

    # Test case 63: Test main function success
    with app.test_request_context():
        reset_test_cache(redis_connect, entity_id, cert_key, management_info_key, error_key, create_group_key)
        with patch("group.get_authorization", return_value=get_authorization_success_return_value):
            with patch("group.subprocess.Popen"):
                with patch("group.requests.get") as getMockClient:
                    response = requests.models.Response()
                    response.status_code = 200
                    response.json = Mock(return_value={"create_status": False, "error": ""})
                    getMockClient.return_value = response
                    main(entity_id, json.dumps(group_info), service, member_info)
                    captured = capsys.readouterr()
                    assert captured.out == "Group created successfully\n"
    
    # Test case 64: Test main function authorization error
    with app.test_request_context():
        reset_test_cache(redis_connect, entity_id, cert_key, management_info_key, error_key, create_group_key)
        with patch("group.get_authorization", return_value={"result": "Error", "value": "Authorization error"}):
            with pytest.raises(SystemExit) as sysExitInfo:
                main(entity_id, json.dumps(group_info), service, member_info)
                sysExitInfo.value.code == "Authorization error"

    # Test case 65: Test main function wait create group task
    with app.test_request_context():
        reset_test_cache(redis_connect, entity_id, cert_key, management_info_key, error_key, create_group_key)
        with patch("group.get_authorization", return_value=get_authorization_success_return_value):
            with patch("group.subprocess.Popen"):
                with patch("group.requests.get") as getMockClient:
                    response1 = requests.models.Response()
                    response1.status_code = 200
                    response1.json = Mock(return_value={"create_status": True, "error": ""})
                    response2 = requests.models.Response()
                    response2.status_code = 200
                    response2.json = Mock(return_value={"create_status": False, "error": ""})
                    getMockClient.side_effect = [response1, response2]
                    main(entity_id, json.dumps(group_info), service, member_info)
                    captured = capsys.readouterr()
                    assert captured.out == "Group created successfully\n"
                    assert getMockClient.call_count == 2
