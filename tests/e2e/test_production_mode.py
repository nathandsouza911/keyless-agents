"""The api in production mode, in its container (the A3 gap; SD-011, SD-027, SD-045).

The same api image with ENVIRONMENT=production and its own Redis (compose
profile `prod`), against the e2e database. One ordered sequence, because
each step depends on the last:

  1. without Redis it refuses to start;
  2. with Redis it starts, and its cookies are Secure, HttpOnly, SameSite=Lax;
  3. logging out revokes the session in Redis, and the revocation survives a
     Redis restart;
  4. with Redis down, it fails closed: sessions are refused, a rate-limited
     route is refused, and logout says it could not revoke; with Redis back,
     it serves again.

Offline: sign-in start only builds the Microsoft authorize URL, it contacts
nothing, and the sign-in values are placeholders. TLS in front of the api is
the deployment's; the cookie's Secure attribute is what is checked here.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest

pytestmark = pytest.mark.e2e


def _until(check, what: str, timeout: float = 90.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = check()
            if last:
                return last
        except Exception as exc:  # noqa: BLE001 - not ready yet
            last = exc
        time.sleep(1.0)
    raise AssertionError(f"{what}: not reached in time ({last!r})")


def _state(stack, service: str) -> str:
    out = stack.compose_run("ps", "-a", "--format", "json", service).stdout.strip()
    rows = [json.loads(line) for line in out.splitlines() if line.strip()] if out else []
    return rows[0]["State"] if rows else "absent"


def test_production_mode_secure_cookies_and_redis_fail_closed(stack):
    base = stack.prod_api_base
    try:
        # 1. Without Redis, production refuses to start.
        stack.compose_run("rm", "-sf", "redis", "api-prod")
        stack.compose_run("up", "-d", "--no-deps", "api-prod")
        _until(lambda: _state(stack, "api-prod") == "exited", "api-prod to exit without Redis")
        assert "Redis is required in production" in stack.compose_run("logs", "--no-color", "api-prod").stdout

        # 2. With Redis it starts; its cookies are Secure.
        stack.compose_run("up", "-d", "redis")
        stack.compose_run("up", "-d", "--no-deps", "--force-recreate", "api-prod")
        with httpx.Client(base_url=base, timeout=10.0, follow_redirects=False) as client:
            _until(lambda: client.get("/tasks").status_code == 401, "api-prod to serve")
            start = client.get("/auth/microsoft/start")
            assert start.status_code == 302 and start.headers["location"].startswith(
                "https://login.microsoftonline.com/")
            cookie = start.headers["set-cookie"].lower()
            assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie, cookie

            # 3. Logout revokes in Redis; the revocation survives a Redis restart.
            first = stack.session_cookie()
            statuses = [client.get("/tasks", headers=first).status_code,
                        client.post("/auth/logout", headers=first).status_code,
                        client.get("/tasks", headers=first).status_code]
            assert statuses == [200, 204, 401], statuses
            stack.compose_run("restart", "redis")
            second = stack.session_cookie()
            _until(lambda: client.get("/tasks", headers=second).status_code == 200, "Redis back after restart")
            assert client.get("/tasks", headers=first).status_code == 401

            # 4. Redis down: fail closed.
            stack.compose_run("stop", "redis")
            _until(lambda: client.get("/tasks", headers=second).status_code == 401, "sessions refused without Redis")
            # A rate-limited route is refused before anything runs: the limiter
            # fails closed (429) ahead of the session check (401).
            created = client.post("/runs", json={"task_id": "dormant-probe-demo", "params": {"inactive_days": 90}},
                                  headers=second).status_code
            assert created in (401, 429), created
            logout = client.post("/auth/logout", headers=second).status_code
            assert logout in (401, 429, 503), logout  # never a 204 that revoked nothing

            # Redis back: it serves again.
            stack.compose_run("start", "redis")
            _until(lambda: client.get("/tasks", headers=second).status_code == 200, "serving again with Redis")
    finally:
        stack.compose_run("rm", "-sf", "api-prod", "redis")
