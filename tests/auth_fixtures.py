"""Shared environment for session, revocation and rate-limit tests.

Secrets are generated per test; nothing real is ever used. Caches are cleared
around every test so a Redis client is never reused across event loops (which
would fail and be mistaken for "Redis unavailable").
"""

from __future__ import annotations

import secrets
import socket

import pytest

PG = "postgresql+asyncpg://u:p@127.0.0.1:5433/clw"


def closed_port_url() -> str:
    """A redis:// URL on a local port nothing listens on: a real connection refusal."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"redis://127.0.0.1:{port}/0"


def _clear_caches() -> None:
    from clw.auth import denylist, redis as clw_redis
    from clw.common import config

    config.get_settings.cache_clear()
    clw_redis.get_redis.cache_clear()
    denylist._fallback.clear()
    try:
        from clw.api.middleware import rate_limit

        rate_limit._counters.clear()
    except ImportError:
        pass


@pytest.fixture
def auth_env(monkeypatch):
    """Configure the process environment; returns a setter. Default: test env, no Redis."""

    def configure(*, environment: str = "test", redis_url: str | None = None, secret: str | None = "generate"):
        monkeypatch.setenv("DATABASE_URL", PG)
        monkeypatch.setenv("ENVIRONMENT", environment)
        if redis_url is None:
            monkeypatch.delenv("REDIS_URL", raising=False)
        else:
            monkeypatch.setenv("REDIS_URL", redis_url)
        if secret is None:
            monkeypatch.delenv("SESSION_JWT_SECRET", raising=False)
        else:
            monkeypatch.setenv("SESSION_JWT_SECRET", secrets.token_urlsafe(48) if secret == "generate" else secret)
        _clear_caches()

    configure()
    yield configure
    _clear_caches()
