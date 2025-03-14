from celery import Celery

from .config import CELERY_BACKEND_DB, CELERY_BROKER_DB, REDIS_URL

app = Celery(
    'group_management_celery',
    broker=REDIS_URL + str(CELERY_BROKER_DB),
    backend=REDIS_URL + str(CELERY_BACKEND_DB),
    include=['group_management.tasks'])
