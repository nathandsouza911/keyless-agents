"""Per-route rate limiting (I-3, SD-027).

Routes are matched by name (the FastAPI ``name=``), NOT by URL path: the
legacy path matching was bypassable when a router was mounted under several
prefixes. A route that is not in RATE_LIMITS is unlimited.

Installed as an app-level dependency, ``FastAPI(dependencies=[Depends(
enforce_rate_limit)])``, so it runs after routing and reads the matched route
from ``scope["route"]`` (set by Starlette). The legacy middleware re-matched
routes before routing; with FastAPI 0.143 included routers are no longer
flattened into ``app.router.routes``, so it found no name and limited
nothing. Routes in a mounted sub-application do not get app dependencies.

Counts use a fixed window in Redis: INCR and EXPIRE NX in one transaction, so
a counter always gets an expiry even if an earlier request died between the
two. Production fails closed (429 on limited routes) when Redis cannot
answer; other environments fall back to process memory. Logs never contain
the client IP or the session subject.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import NamedTuple

from fastapi import HTTPException, Request

from clw.auth.redis import get_redis
from clw.auth.session_jwt import SESSION_COOKIE_NAME, decode_session
from clw.common.config import get_settings

logger = logging.getLogger(__name__)


class RateLimitRule(NamedTuple):
    limit: int
    window_seconds: int = 60
    scope: str = "ip"  # "ip" or "user" (session subject; falls back to IP without a valid session)


# Route name -> rule. Names are the contract with the routes added in Task 6
# and later; a name with no matching route limits nothing.
RATE_LIMITS: dict[str, RateLimitRule] = {
    "auth_microsoft_start": RateLimitRule(limit=20),
    "auth_microsoft_callback": RateLimitRule(limit=20),
    "auth_logout": RateLimitRule(limit=30, scope="user"),
    "runs_create": RateLimitRule(limit=10, scope="user"),
    "scripts_submit": RateLimitRule(limit=10, scope="user"),
    "scripts_approve": RateLimitRule(limit=20, scope="user"),
    # The demo pages' form posts (SD-045): the same limits as the JSON routes
    # they call, counted separately.
    "ui_scripts_submit": RateLimitRule(limit=10, scope="user"),
    "ui_scripts_approve": RateLimitRule(limit=20, scope="user"),
    "ui_runs_create": RateLimitRule(limit=10, scope="user"),
    "ui_sign_out": RateLimitRule(limit=30, scope="user"),
}

_KEY_PREFIX = "clw:rate:"
_MAX_MEMORY_KEYS = 10_000

# Memory fallback (non-production only): key -> request timestamps in the window.
_counters: dict[str, list[float]] = {}
_lock = Lock()


def _client_ip(request: Request) -> str:
    """request.client.host as normalised by trusted-proxy middleware; forwarded headers are not parsed here."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def _session_subject(request: Request) -> str | None:
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
    else:
        token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        return str((await decode_session(token)).user_id)
    except Exception:
        return None


async def _rate_limit_key(request: Request, route_name: str, rule: RateLimitRule) -> str:
    if rule.scope == "user":
        subject = await _session_subject(request)
        if subject:
            return f"user:{subject}:{route_name}"
    return f"ip:{_client_ip(request)}:{route_name}"


async def _redis_blocked(key: str, rule: RateLimitRule) -> bool | None:
    """True if blocked, False if allowed, None if Redis is unavailable outside production."""
    redis_key = _KEY_PREFIX + key
    try:
        async with get_redis().pipeline(transaction=True) as pipe:
            pipe.incr(redis_key)
            pipe.expire(redis_key, rule.window_seconds, nx=True)
            count, _ = await pipe.execute()
        return count > rule.limit
    except Exception:
        if get_settings().is_production:
            logger.error("rate_limit_store_failed failing_closed")
            return True
        logger.warning("rate_limit_store_failed using_memory_fallback")
        return None


def _memory_blocked(key: str, rule: RateLimitRule) -> bool:
    now = time.time()
    with _lock:
        if len(_counters) > _MAX_MEMORY_KEYS:
            for stale in [k for k, ts in _counters.items() if not ts or now - ts[-1] >= rule.window_seconds]:
                del _counters[stale]
        window = [t for t in _counters.get(key, []) if now - t < rule.window_seconds]
        blocked = len(window) >= rule.limit
        if not blocked:
            window.append(now)
        _counters[key] = window
    return blocked


async def enforce_rate_limit(request: Request) -> None:
    """App-level dependency: 429 when the matched route's rule is exceeded."""
    route_name = getattr(request.scope.get("route"), "name", None)
    rule = RATE_LIMITS.get(route_name) if isinstance(route_name, str) else None
    if rule is None:
        return
    key = await _rate_limit_key(request, route_name, rule)
    blocked = await _redis_blocked(key, rule)
    if blocked is None:
        blocked = _memory_blocked(key, rule)
    if blocked:
        logger.warning("rate_limit_blocked route=%s scope=%s", route_name, rule.scope)
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
