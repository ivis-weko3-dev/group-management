from celery import shared_task

from .utils import create_group, get_access_token

@shared_task
def create_group_task(entity_id, authorization_code):
    """Task to create a group
    
    Args:
        entity_id (str): Entity ID
        authorization_code (str): Authorization code
    """
    # Get the access token
    access_token = get_access_token(entity_id, authorization_code)
    # Create the group
    create_group(entity_id, access_token)
