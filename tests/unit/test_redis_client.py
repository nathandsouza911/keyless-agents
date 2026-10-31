"""Redis client construction (I-4, SD-011). No Redis server needed."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from clw.auth import redis as clw_redis
from clw.auth.redis import RedisUnavailable, get_redis, verify_redis_available_in_production
from tests.auth_fixtures import auth_env, closed_port_url  # noqa: F401 (fixture)


def test_importing_builds_no_client():
    # A fresh interpreter with no settings at all: import must not read them or connect.
    env = {k: v for k, v in os.environ.items() if k not in {"REDIS_URL", "DATABASE_URL"}}
    code = "import clw.auth.redis as r, clw.auth.denylist; assert not hasattr(r, 'redis_client')"
    subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=60)


def test_no_default_host(auth_env):
    with pytest.raises(RedisUnavailable):
        clw_redis.get_redis()


@pytest.mark.parametrize("url", ["http://user:pw-123@h:6379/0", "localhost:6379", "unix:///tmp/redis.sock"])
def test_non_redis_scheme_rejected_without_echoing_the_url(auth_env, url):
    auth_env(redis_url=url)
    with pytest.raises(RedisUnavailable) as info:
        clw_redis.get_redis()
    assert "pw-123" not in str(info.value) and url not in str(info.value)


def test_client_built_from_url(auth_env):
    auth_env(redis_url="redis://:pw-abc@127.0.0.1:6380/3")
    client = clw_redis.get_redis()
    kwargs = client.connection_pool.connection_kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["db"]) == ("127.0.0.1", 6380, 3)
    assert kwargs["socket_timeout"] == 5 and kwargs["socket_connect_timeout"] == 5
    assert kwargs["retry"].get_retries() == 0  # one attempt, then fail closed or fall back
    assert get_redis() is client


async def test_production_startup_check_fails_without_redis(auth_env):
    auth_env(environment="production", redis_url=closed_port_url())
    with pytest.raises(RuntimeError) as info:
        await verify_redis_available_in_production()
    assert "127.0.0.1" not in str(info.value)
    auth_env(environment="production")
    with pytest.raises(RuntimeError):
        await verify_redis_available_in_production()


async def test_startup_check_is_a_no_op_outside_production(auth_env):
    auth_env(environment="development", redis_url=closed_port_url())
    await verify_redis_available_in_production()
