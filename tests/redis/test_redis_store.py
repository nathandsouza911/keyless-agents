"""Revocation and rate limiting against a real Redis (SD-011, SD-027).

Needs the compose Redis: TEST_REDIS_URL (default matches .env.example) on
database 15. Only keys under the clw: prefix in that database are touched.
"""

from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest
from fastapi import Depends, FastAPI

from clw.api.middleware.rate_limit import RATE_LIMITS, enforce_rate_limit
from clw.auth import denylist
from clw.auth.redis import get_redis
from clw.auth.session_jwt import SessionInvalid, decode_session, issue_session
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)

pytestmark = pytest.mark.redis

REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://:change-me-local-only@127.0.0.1:6380/15")


@pytest.fixture
async def redis_env(auth_env):
    async def clean():
        client = get_redis()
        keys = [k async for k in client.scan_iter(match="clw:*")]
        if keys:
            await client.delete(*keys)

    def configure(environment: str = "production"):
        auth_env(environment=environment, redis_url=REDIS_URL)

    configure()
    try:
        await get_redis().ping()
    except Exception as exc:  # an environment failure, not a test result
        pytest.fail(f"Redis at TEST_REDIS_URL is unreachable ({type(exc).__name__}); run docker compose up -d")
    await clean()
    yield configure
    configure()
    await clean()
    await get_redis().aclose()


def _session() -> str:
    return issue_session(user_id=uuid.uuid4(), oid=str(uuid.uuid4()), tid=str(uuid.uuid4()), role="analyst")


# ---------------------------------------------------------------- revocation


async def test_revoked_session_rejected_in_production(redis_env):
    token = _session()
    claims = await decode_session(token)
    await denylist.revoke(claims.jti, claims.expires_at)
    with pytest.raises(SessionInvalid) as info:
        await decode_session(token)
    assert info.value.reason == "revoked"
    assert await decode_session(_session())  # other sessions unaffected


async def test_revocation_key_expires_with_the_session(redis_env):
    jti = str(uuid.uuid4())
    await denylist.revoke(jti, time.time() + 30.2)
    ttl = await get_redis().ttl(f"clw:denylist:{jti}")
    assert 30 <= ttl <= 31  # rounded up, never down
    assert denylist._fallback == {}


async def test_revocation_is_shared_through_redis_not_process_memory(redis_env):
    jti = str(uuid.uuid4())
    await denylist.revoke(jti, time.time() + 60)
    denylist._fallback.clear()
    assert await denylist.is_revoked(jti) is True
    assert await denylist.is_revoked(str(uuid.uuid4())) is False


async def test_store_eviction_policy_keeps_revocations(redis_env):
    # Revocations must not be evicted under memory pressure (SD-011 limit).
    policy = (await get_redis().config_get("maxmemory-policy"))["maxmemory-policy"]
    assert policy == "noeviction"


# ---------------------------------------------------------------- rate limiting


def _app() -> FastAPI:
    app = FastAPI(dependencies=[Depends(enforce_rate_limit)])

    @app.get("/auth/microsoft/start", name="auth_microsoft_start")
    async def start():
        return {"ok": True}

    return app


async def test_rate_limit_window_in_redis(redis_env):
    limit = RATE_LIMITS["auth_microsoft_start"].limit
    transport = httpx.ASGITransport(app=_app(), client=("203.0.113.9", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        codes = [(await client.get("/auth/microsoft/start")).status_code for _ in range(limit + 1)]
    assert codes == [200] * limit + [429]
    key = "clw:rate:ip:203.0.113.9:auth_microsoft_start"
    assert int(await get_redis().get(key)) == limit + 1
    assert 0 < await get_redis().ttl(key) <= 60


async def test_counter_left_without_expiry_gets_one(redis_env):
    # Legacy set the expiry only when INCR returned 1: a crash between INCR and
    # EXPIRE left a counter that never expired and blocked the client forever.
    key = "clw:rate:ip:203.0.113.10:auth_microsoft_start"
    await get_redis().set(key, 500)  # no TTL
    transport = httpx.ASGITransport(app=_app(), client=("203.0.113.10", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        assert (await client.get("/auth/microsoft/start")).status_code == 429
    assert 0 < await get_redis().ttl(key) <= 60
