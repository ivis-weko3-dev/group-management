import subprocess

import pytest
from mock import patch
from redis.client import Redis

from group_management.mng_redis import RedisConnection


def stop_redis_container():
    # Redisコンテナを停止する
    subprocess.run(["docker", "stop", "redis"], check=True)

def test_init_redis(app):
    """Test init_redis function"""
    
    # Test redis type is redis
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        assert obj.redis_type == "redis"
    
    # Test redis type is sentinel
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        assert obj.redis_type == "sentinel"
        
def test_connection(app):
    """Test connection function"""
    
    # Test redis type is redis
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.connection(0)
        assert store is not None
        assert type(store) == Redis
    
    # Test redis type is sentinel
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.connection(0)
        assert store is not None
        assert type(store) == Redis
        
    # Test redis type is invalid
    with app.app_context():
        app.config["CACHE_TYPE"] = "test"
        obj = RedisConnection()
        store = obj.connection(0)
        assert store is None

    # Test redis DB is 16
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.connection(16)
        assert store is not None
        assert type(store) == Redis
    
    # Exception is raised
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        with patch('group_management.mng_redis.RedisConnection.redis_connection', side_effect=Exception("Test Error")):
            obj = RedisConnection()
            with pytest.raises(Exception) as e:
                store = obj.connection(0)
            assert str(e.value) == "Test Error"

def test_redis_connection(app):
    """Test redis_connection function"""
    
    # connection is 0
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.redis_connection(0)
        assert store is not None
        assert type(store) == Redis
    
    # connection is 16
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.redis_connection(16)
        assert store is not None
        assert type(store) == Redis

    # Redis is not running
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.redis_connection(0)
        assert store is not None
        assert type(store) == Redis
        
    # Redis enviroment is sentinel
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.redis_connection(0)
        assert store is not None
        assert type(store) == Redis

    # REDIS_URL is invalid
    with app.app_context():
        app.config["REDIS_URL"] = "test"
        app.config["CACHE_TYPE"] = "redis"
        with pytest.raises(ValueError) as e:
            obj = RedisConnection()
            store = obj.redis_connection(0)
        assert str(e.value) == "Redis URL must specify one of the following schemes (redis://, rediss://, unix://)"
        
def test_sentinel_connection(app):
    """Test sentinel_connection function"""
    
    # connection is 0
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.sentinel_connection(0)
        assert store is not None
        assert type(store) == Redis
    
    # connection is 16
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.sentinel_connection(16)
        assert store is not None
        assert type(store) == Redis
															
    # Redis Sentinel is not running
    # note: stop all redis containers before running this test
    with app.app_context():
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.sentinel_connection(0)
        assert store is not None
        assert type(store) == Redis

    # Redis enviroment is redis
    with app.app_context():
        app.config["CACHE_TYPE"] = "redis"
        obj = RedisConnection()
        store = obj.sentinel_connection(0)
        assert store is not None
        assert type(store) == Redis
    
    # REDIS_SENTINELS is invalid
    with app.app_context():
        app.config["REDIS_SENTINELS"] = [("invalid-sentinel-service.re","2637")]
        app.config["CACHE_TYPE"] = "sentinel"
        obj = RedisConnection()
        store = obj.sentinel_connection(0)
        assert store is not None
        assert type(store) == Redis
    
    # Exception is raised
    with app.app_context():
        with patch('redis.sentinel.Sentinel.master_for', side_effect=Exception("Test Error")):
            app.config["CACHE_TYPE"] = "sentinel"
            obj = RedisConnection()
            with pytest.raises(Exception) as e:
                store = obj.sentinel_connection(0)
            assert str(e.value) == "Test Error"