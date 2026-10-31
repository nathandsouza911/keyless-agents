"""Session revocation list (I-5, SD-011). No Redis server: unavailable means
either REDIS_URL unset or a real refused connection on a closed local port.
Behaviour against a real Redis is in tests/redis/."""

from __future__ import annotations

import logging
import time
import uuid

import pytest

from clw.auth import denylist
from clw.auth.denylist import RevocationUnavailable, is_revoked, revoke
from tests.auth_fixtures import auth_env, closed_port_url  # noqa: F401 (fixture)


def _jti() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------- production: fail closed


@pytest.mark.parametrize("redis", ["unset", "refused"])
async def test_production_redis_down_reports_everything_revoked(auth_env, redis):
    auth_env(environment="production", redis_url=None if redis == "unset" else closed_port_url())
    assert await is_revoked(_jti()) is True


@pytest.mark.parametrize("redis", ["unset", "refused"])
async def test_production_redis_down_revoke_raises(auth_env, redis):
    auth_env(environment="production", redis_url=None if redis == "unset" else closed_port_url())
    with pytest.raises(RevocationUnavailable):
        await revoke(_jti(), time.time() + 60)
    assert denylist._fallback == {}  # never silently kept in memory in production


async def test_production_does_not_consult_memory_fallback(auth_env):
    auth_env(environment="production", redis_url=closed_port_url())
    denylist._fallback[_jti()] = time.time() + 60  # memory knows some other jti only
    assert await is_revoked(_jti()) is True  # memory would have said False


# ---------------------------------------------------------------- non-production: memory fallback


@pytest.mark.parametrize("environment,refused", [("development", True), ("test", False)])
async def test_memory_fallback_outside_production(auth_env, environment, refused):
    auth_env(environment=environment, redis_url=closed_port_url() if refused else None)
    jti, other = _jti(), _jti()
    await revoke(jti, time.time() + 60)
    assert await is_revoked(jti) is True
    assert await is_revoked(other) is False


async def test_entry_expires_with_the_session(auth_env):
    jti = _jti()
    await revoke(jti, time.time() + 60)
    denylist._fallback[jti] = time.time() - 1  # simulate the session's expiry passing
    assert await is_revoked(jti) is False
    assert jti not in denylist._fallback


async def test_already_expired_session_needs_no_entry(auth_env):
    jti = _jti()
    await revoke(jti, time.time() - 1)
    assert denylist._fallback == {}


async def test_sub_second_remaining_lifetime_is_still_revoked(auth_env):
    # Legacy truncated int(0.4) == 0 and skipped the revocation.
    jti = _jti()
    await revoke(jti, time.time() + 0.4)
    assert await is_revoked(jti) is True


# ---------------------------------------------------------------- input


@pytest.mark.parametrize("jti", [None, "", 42, "has space", "a" * 129, "denylist:*", "é"])
async def test_malformed_jti_counts_as_revoked(auth_env, jti):
    assert await is_revoked(jti) is True


@pytest.mark.parametrize("jti", [None, "", "has space", "a" * 129])
async def test_revoke_rejects_malformed_jti(auth_env, jti):
    with pytest.raises(ValueError):
        await revoke(jti, time.time() + 60)


# ---------------------------------------------------------------- hygiene


async def test_logs_do_not_contain_the_jti(auth_env, caplog):
    caplog.set_level(logging.DEBUG)
    jti = _jti()
    auth_env(environment="development")
    await revoke(jti, time.time() + 60)
    await is_revoked(jti)
    auth_env(environment="production")
    await is_revoked(jti)
    with pytest.raises(RevocationUnavailable):
        await revoke(jti, time.time() + 60)
    assert caplog.records
    assert jti not in " ".join(r.getMessage() for r in caplog.records)
