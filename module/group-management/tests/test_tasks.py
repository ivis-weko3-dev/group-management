from mock import patch

from group_management.tasks import create_group_task


def test_create_group_task(app):
    """Test create_group function"""
    entity_id = "https://test-entity.org"
    authorization_code = "test_auth_code"

    with app.app_context():
        with patch("group_management.tasks.get_access_token", return_value="sample_access"):
            with patch("group_management.tasks.create_group"):
                create_group_task(entity_id, authorization_code)