"""Session revocation list, keyed by session `jti` (I-5, SD-011).

Production fails closed: if Redis cannot be read, every session counts as
revoked; if a revocation cannot be written, revoke() raises. Outside
production a per-process memory fallback is used instead, which is not
shared between processes and does not see revocations already in Redis.
"""

from __future__ import annotations

import logging
import math
import re
import time
from threading import Lock

from clw.auth.redis import get_redis
from clw.common.config import get_settings

logger = logging.getLogger(__name__)

_KEY_PREFIX = "clw:denylist:"
_JTI = re.compile(r"[A-Za-z0-9_-]{1,128}")

# Memory fallback (non-production only): jti -> expiry (epoch seconds).
_fallback: dict[str, float] = {}
_lock = Lock()


class RevocationUnavailable(Exception):
    """The revocation could not be recorded (production, Redis unavailable)."""


def _valid_jti(jti: object) -> bool:
    return isinstance(jti, str) and _JTI.fullmatch(jti) is not None


async def revoke(jti: str, expires_at: float) -> None:
    """Revoke a session until its expiry. A session already past expiry needs nothing."""
    if not _valid_jti(jti):
        raise ValueError("invalid jti")
    # Round up: a session with 0.4 s left is still accepted until exp.
    ttl = math.ceil(expires_at - time.time())
    if ttl <= 0:
        return
    try:
        await get_redis().set(_KEY_PREFIX + jti, "1", ex=ttl)
        return
    except Exception:
        if get_settings().is_production:
            logger.error("revocation_write_failed failing_closed")
            raise RevocationUnavailable("session revocation could not be recorded") from None
        logger.warning("revocation_write_failed using_memory_fallback")
    with _lock:
        _prune_unsafe()
        _fallback[jti] = expires_at


async def is_revoked(jti: str) -> bool:
    """True if revoked, if the jti is malformed, or (production) if Redis cannot answer."""
    if not _valid_jti(jti):
        return True
    try:
        return await get_redis().exists(_KEY_PREFIX + jti) == 1
    except Exception:
        if get_settings().is_production:
            logger.error("revocation_read_failed failing_closed")
            return True
        logger.warning("revocation_read_failed using_memory_fallback")
    with _lock:
        _prune_unsafe()
        return jti in _fallback


def _prune_unsafe() -> None:
    """Remove expired entries. Must be called while _lock is held."""
    now = time.time()
    for key in [k for k, v in _fallback.items() if v <= now]:
        del _fallback[key]
