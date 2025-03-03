HOST_NAME='localhost'
CERT_FILE='/etc/pki/tls/{}/certs/server.crt'
KEY_FILE='/etc/pki/tls/{}/private/server.key'
AUTHORIZATION_BASE_URL='https://dev2.cg.gakunin.jp/oauth'
CORE_BASE_URL='https://sample.co.jp'
REDIRECT_URL='https://' + HOST_NAME + '/group-management/create'

# redis config
CACHE_TYPE = 'redis'
REDIS_HOST = 'localhost'
REDIS_URL = 'redis://' + REDIS_HOST + ':6379/'
REDIS_SENTINEL_MASTER = 'mymaster'
REDIS_SENTINELS = [("sentinel-service.re","26379")]
MANAGEMENT_DB=0
CELERY_BROKER_DB=1
CELERY_BACKEND_DB=2

MANAGEMENT_INFO_SUFFIX='_group_management_info'
CLIENT_CERT_SUFFIX='_client_cert'
CREATE_GROUP_SUFFIX='_create_group'
CREATE_GROUP_ERR_SUFFIX='_create_group_err'

USER_AUTHORIZATION={
    'member': 1,
    'admin': 2,
    'member_admin': 3
}