from flask import Blueprint, current_app, jsonify, request

from .config import CREATE_GROUP_SUFFIX
from .mng_celery import app as celery_app
from .tasks import create_group_task
from .utils import get_task_status, reset_redis, set_task_id

blueprint = Blueprint(
    'group_management',
    __name__,
    url_prefix='/group-management'
)

@blueprint.route('/create', methods=['GET'])
def create_group():
    """Create a group
    
    Returns:
        dict: Response
            code (int): Response code
            message (str): Response message
    """
    data = request.args.to_dict()
    create_task = create_group_task.apply_async(args=(data.get('state'), data.get('code')))
    create_group_suffix = current_app.config.get('CREATE_GROUP_SUFFIX', CREATE_GROUP_SUFFIX)
    set_task_id(create_group_suffix, create_task.id, data.get('state'))
    return jsonify({
        'code': 200,
        'message': 'Create group task created successfully',
    })

@blueprint.route('/status', methods=['GET'])
def get_status():
    """Get the status of a task
    
    Returns:
        dict: Response
            create_status (bool): Create group task status
            status (str): Task status
            error (str): Error message
    """
    create_group_suffix = current_app.config.get('CREATE_GROUP_SUFFIX', CREATE_GROUP_SUFFIX)
    result = get_task_status(create_group_suffix, request.args.get('entity_id'))
    if not result.get('create_status'):
        reset_redis(request.args.get('entity_id'))
    return jsonify(result)
