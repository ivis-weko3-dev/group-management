import redis
from redis import sentinel

from .config import CACHE_REDIS_SENTINELS, CACHE_REDIS_SENTINEL_MASTER, CACHE_TYPE, REDIS_URL

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
        self.redis_type = CACHE_TYPE
    
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
            redis_url = REDIS_URL + str(db)
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
            sentinels = sentinel.Sentinel(CACHE_REDIS_SENTINELS, decode_responses=False)
            store = sentinels.master_for(CACHE_REDIS_SENTINEL_MASTER, db=db)
        except Exception as ex:
            raise ex
        
        return store
