"""Pytest configuration."""

import os
import shutil
import tempfile
from os.path import join

import pytest
from flask import Flask

from group_management.api import blueprint as group_management_blueprint
from group_management.mng_redis import RedisConnection


@pytest.fixture()
def instance_path():
    path = tempfile.mkdtemp()
    yield path
    shutil.rmtree(path)


@pytest.fixture()
def base_app(instance_path):
    """Flask application fixture."""
    app_ = Flask(
        "testapp",
        instance_path=instance_path,
        static_folder=join(instance_path, "static"),
    )

    app_.config.update(
        CLIENT_CERT_SUFFIX = "_test_cert",
        MANAGEMENT_INFO_SUFFIX = "_test_management",
        CREATE_GROUP_ERR_SUFFIX = "_test_error",
        CREATE_GROUP_SUFFIX = "_test_group",
        CELERY_ALWAYS_EAGER=True,
        CELERY_CACHE_BACKEND="memory",
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_RESULT_BACKEND="cache",
        CACHE_REDIS_URL="redis://redis:6379/0",
        CACHE_REDIS_DB=0,
        CACHE_REDIS_HOST="redis",
        REDIS_PORT="6379",
        JSONSCHEMAS_URL_SCHEME="http",
        SECRET_KEY="CHANGE_ME",
        SECURITY_PASSWORD_SALT="CHANGE_ME_ALSO",
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "SQLALCHEMY_DATABASE_URI", "sqlite:///test.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=True,
        SQLALCHEMY_ECHO=False,
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        DEPOSIT_SEARCH_API="/api/search",
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_PASSWORD_SCHEMES=["plaintext"],
        SECURITY_DEPRECATED_PASSWORD_SCHEMES=[],
        ACCOUNTS_JWT_ENABLE=False,
        INDEXER_FILE_DOC_TYPE="content",
        INDEX_IMG="indextree/36466818-image.jpg",
        I18N_LANGUAGE=[("ja", "Japanese"), ("en", "English")],
        SERVER_NAME="TEST_SERVER",
        SEARCH_ELASTIC_HOSTS="elasticsearch",
        SEARCH_INDEX_PREFIX="test-",
        OAISERVER_XSL_URL=None,
    )
    app_.register_blueprint(group_management_blueprint)
    return app_


@pytest.fixture()
def app(base_app):
    """Flask application fixture."""
    with base_app.app_context():
        yield base_app

@pytest.fixture()
def redis_connect(app):
    redis_connection = RedisConnection().connection(db=app.config['CACHE_REDIS_DB'])
    return redis_connection

@pytest.fixture()
def client(app):
    """Get test client."""
    with app.test_client() as client:
        yield client

@pytest.fixture()
def mock_users_api():
    """Mock user API."""
    def create_user_reponse(user_id, username, user_eppn, user_email):
        return {
            "status": {
                "error_code": 200,
                "error_msg": "Success",
            },
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 20,
            "Resources": [{
                "schemas": [
                    "urn:ietf:params:scim:schemas:mace:gakunin.jp:core:2.0:User"
                ],
                "id": str(user_id),
                "userName": str(username),
                "prefferedLanguage": "ja",
                "meta": {
                    "resourceType": "User",
                    "created": "2021-07-07T07:07:07Z",
                    "lastModified": "2021-07-07T07:07:07Z",
                    "createdBy": "admin",
                },
                "eduPersonPrincipalName": [{
                    "eduPersonPrincipalName": str(user_eppn),
                    "idpEntityId": "https://idp.example.org/idp/shibboleth",
                }],
                "emails": [{
                    "value": user_email
                }],
                "groups": [],
            }]
        }

    mock_data_users = [
        {"id": 1, "name": "testuser1", "email": "testuser1@example.org", "eppn": "testuser1-eppn"},
        {"id": 2, "name": "testuser2", "email": "testuser2@example.org", "eppn": "testuser2-eppn"},
        {"id": 3, "name": "testuser3", "email": "testuser3@example.org", "eppn": "testuser3-eppn"},
    ]
    return [
        create_user_reponse(user["id"], user["name"], user["eppn"], user["email"])
        for user in mock_data_users
    ]
    
@pytest.fixture()
def mock_groups_api():
    def create_group_response(gorup_id, group_name):
        return {
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 20,
            "Resources": [{
                "schemas": [
                    "urn:ietf:params:scim:schemas:mace:gakunin.jp:core:2.0:Group"
                ],
                "id": str(gorup_id),
                "displayName": str(group_name),
                "meta": {
                    "resourceType": "Group",
                    "created": "2021-07-07T07:07:07Z",
                    "lastModified": "2021-07-07T07:07:07Z",
                },
                "members": [],
            }]
        }

    mock_data_groups = [
        {"id": 1, "name": "testgroup1"},
        {"id": 2, "name": "testgroup2"},
    ]
    return [
        create_group_response(group["id"], group["name"])
        for group in mock_data_groups
    ]