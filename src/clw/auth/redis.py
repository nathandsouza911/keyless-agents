"""Redis connection for session revocation and rate limiting (I-4, SD-011).

The client is built on first use, never at import. Without REDIS_URL there is
no default host: Redis counts as unavailable, so production callers fail
closed and other environments may fall back to process memory.
"""

from __future__ import annotations

from functools import lru_cache

import redis.asyncio as aioredis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff

from clw.common.config import get_settings

_SOCKET_TIMEOUT = 5
_CONNECT_TIMEOUT = 5


class RedisUnavailable(Exception):
    """Redis is not configured or the client cannot be built. Carries no URL."""


@lru_cache(maxsize=1)
def get_redis() -> aioredis.Redis:
    """The shared async client (bound to the running event loop on first use)."""
    url = get_settings().REDIS_URL
    if url is None:
        raise RedisUnavailable("REDIS_URL is not set")
    raw = url.get_secret_value()
    if not raw.startswith(("redis://", "rediss://")):
        raise RedisUnavailable("REDIS_URL must use redis:// or rediss://")
    try:
        return aioredis.Redis.from_url(
            raw,
            decode_responses=True,
            socket_connect_timeout=_CONNECT_TIMEOUT,
            socket_timeout=_SOCKET_TIMEOUT,
            # One attempt: a hung Redis costs at most the timeouts above per
            # request, then the caller fails closed (production) or falls back.
            retry=Retry(NoBackoff(), 0),
        )
    except Exception:
        raise RedisUnavailable("REDIS_URL is invalid") from None


async def verify_redis_available_in_production() -> None:
    """Startup check: production refuses to start without a reachable Redis."""
    if not get_settings().is_production:
        return
    try:
        await get_redis().ping()
    except Exception:
        raise RuntimeError(
            "Redis is required in production for session revocation and rate limiting; "
            "set REDIS_URL"
        ) from None
