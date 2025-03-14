import redis
from flask import current_app
from redis import sentinel

from .config import CACHE_TYPE, REDIS_SENTINEL_MASTER, REDIS_SENTINELS, REDIS_URL

class RedisConnection:
    """Redis connection class

    Attributes:
        redis_type(str): redis type(redis or sentinel)

    Methods:
        connection(db): Establish Redis connection and return Redis store object
        redis_connection(db): Establish Redis connection and return Redis store object
        sentinel_connection(db): Establish Redis sentinel connection and return Redis store object
    """
    def __init__(self):
        self.redis_type = current_app.config.get("CACHE_TYPE", CACHE_TYPE)
    
    def connection(self, db):
        """Establish Redis connection and return Redis store object

        Arguments:
            db(int): Redis db number what connect to

        Returns:
            redis.Redis: Redis store object
        """
        store = None
        try:
            if self.redis_type == 'redis':
                store = self.redis_connection(db)
            elif self.redis_type == 'sentinel':
                store = self.sentinel_connection(db)
        except Exception as ex:
            raise ex

        return store

    def redis_connection(self, db):
        """Establish Redis connection and return Redis store object

        Arguments:
            db(int): Redis db number what connect to

        Returns:
            redis.Redis: Redis store object
        """
        store = None
        try:
            redis_url = current_app.config.get("REDIS_URL", REDIS_URL) + str(db)
            store = redis.StrictRedis.from_url(redis_url)
        except Exception as ex:
            raise ex

        return store

    def sentinel_connection(self, db):
        """Establish Redis sentinel connection and return Redis store object

        Arguments:
            db(int): Redis db number what connect to

        Returns:
            redis.Redis: Redis store object
        """
        store = None
        try:
            sentinel_config = current_app.config.get("REDIS_SENTINELS", REDIS_SENTINELS)
            master = current_app.config.get("REDIS_SENTINEL_MASTER", REDIS_SENTINEL_MASTER)
            sentinels = sentinel.Sentinel(sentinel_config, decode_responses=False)
            store = sentinels.master_for(master, db=db)
        except Exception as ex:
            raise ex
        
        return store
