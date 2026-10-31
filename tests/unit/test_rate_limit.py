"""Per-route rate limiting (I-3, SD-027). Memory fallback and fail-closed
paths; the Redis window itself is tested against a real Redis in tests/redis/."""

from __future__ import annotations

import ast
import logging
import uuid
from pathlib import Path

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI

from clw.api.middleware import rate_limit
from clw.api.middleware.rate_limit import RATE_LIMITS, RateLimitRule, enforce_rate_limit
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from tests.auth_fixtures import auth_env, closed_port_url  # noqa: F401 (fixture)

SRC = Path(__file__).resolve().parents[2] / "src" / "clw" / "api" / "middleware" / "rate_limit.py"
TID = str(uuid.uuid4())


def _app() -> FastAPI:
    router = APIRouter()

    @router.get("/auth/microsoft/start", name="auth_microsoft_start")
    async def start():
        return {"ok": True}

    @router.post("/auth/logout", name="auth_logout")
    async def logout():
        return {"ok": True}

    @router.get("/tasks", name="tasks_list")
    async def tasks():
        return {"ok": True}

    app = FastAPI(dependencies=[Depends(enforce_rate_limit)])
    # The same router under two prefixes: path matching was bypassable this way.
    app.include_router(router)
    app.include_router(router, prefix="/v2")
    return app


def _client(app: FastAPI, ip: str = "203.0.113.7") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 5000)), base_url="http://t")


def _cookie(token: str) -> dict:
    return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}


def _session(user_id: uuid.UUID | None = None) -> str:
    return issue_session(user_id=user_id or uuid.uuid4(), oid=str(uuid.uuid4()), tid=TID, role="analyst")


# ---------------------------------------------------------------- rule table


def test_rules_name_workbench_routes_only():
    assert RATE_LIMITS == {
        "auth_microsoft_start": RateLimitRule(limit=20),
        "auth_microsoft_callback": RateLimitRule(limit=20),
        "auth_logout": RateLimitRule(limit=30, scope="user"),
        "runs_create": RateLimitRule(limit=10, scope="user"),
        "scripts_submit": RateLimitRule(limit=10, scope="user"),   # SD-043
        "scripts_approve": RateLimitRule(limit=20, scope="user"),
        "ui_scripts_submit": RateLimitRule(limit=10, scope="user"),   # SD-045: the demo pages' posts
        "ui_scripts_approve": RateLimitRule(limit=20, scope="user"),
        "ui_runs_create": RateLimitRule(limit=10, scope="user"),
        "ui_sign_out": RateLimitRule(limit=30, scope="user"),
    }
    for rule in RATE_LIMITS.values():
        assert rule.limit > 0 and rule.window_seconds > 0 and rule.scope in {"ip", "user"}


# ---------------------------------------------------------------- matching by route name


async def test_limit_applies_by_route_name_across_prefixes(auth_env):
    async with _client(_app()) as client:
        for i in range(20):
            path = "/auth/microsoft/start" if i % 2 else "/v2/auth/microsoft/start"
            assert (await client.get(path)).status_code == 200
        assert (await client.get("/auth/microsoft/start")).status_code == 429
        assert (await client.get("/v2/auth/microsoft/start")).status_code == 429


async def test_unlisted_route_is_not_limited(auth_env):
    async with _client(_app()) as client:
        for _ in range(60):
            assert (await client.get("/tasks")).status_code == 200


async def test_unmatched_path_is_not_counted(auth_env):
    async with _client(_app()) as client:
        for _ in range(25):
            assert (await client.get("/auth/microsoft/start/extra")).status_code == 404
        assert (await client.get("/auth/microsoft/start")).status_code == 200


async def test_ip_scope_counts_each_client_separately(auth_env):
    app = _app()
    async with _client(app, "198.51.100.1") as a, _client(app, "198.51.100.2") as b:
        for _ in range(20):
            assert (await a.get("/auth/microsoft/start")).status_code == 200
        assert (await a.get("/auth/microsoft/start")).status_code == 429
        assert (await b.get("/auth/microsoft/start")).status_code == 200


async def test_429_body(auth_env):
    async with _client(_app()) as client:
        for _ in range(20):
            await client.get("/auth/microsoft/start")
        response = await client.get("/auth/microsoft/start")
    assert response.status_code == 429
    assert response.json() == {"detail": "rate_limit_exceeded"}


# ---------------------------------------------------------------- user scope


async def test_user_scope_counts_per_session_subject(auth_env):
    app = _app()
    alice, bob = _session(), _session()
    async with _client(app) as client:  # same IP for both
        for _ in range(30):
            assert (await client.post("/auth/logout", headers=_cookie(alice))).status_code == 200
        assert (await client.post("/auth/logout", headers=_cookie(alice))).status_code == 429
        assert (await client.post("/auth/logout", headers={"Authorization": f"Bearer {bob}"})).status_code == 200


async def test_user_scope_without_valid_session_falls_back_to_ip(auth_env):
    app = _app()
    async with _client(app) as client:
        for i in range(30):
            cookie = _cookie(f"forged-{i}")  # a fresh bogus token cannot buy a fresh bucket
            assert (await client.post("/auth/logout", headers=cookie)).status_code == 200
        assert (await client.post("/auth/logout", headers=_cookie("forged-x"))).status_code == 429


# ---------------------------------------------------------------- Redis unavailable


async def test_production_without_redis_blocks_limited_routes_only(auth_env):
    auth_env(environment="production", redis_url=closed_port_url())
    async with _client(_app()) as client:
        assert (await client.get("/auth/microsoft/start")).status_code == 429
        assert (await client.get("/tasks")).status_code == 200


async def test_memory_fallback_outside_production(auth_env):
    auth_env(environment="development", redis_url=closed_port_url())
    rate_limit._counters.clear()
    key = "ip:1.2.3.4:auth_microsoft_start"
    rule = RATE_LIMITS["auth_microsoft_start"]
    assert [rate_limit._memory_blocked(key, rule) for _ in range(21)] == [False] * 20 + [True]


def test_memory_fallback_prunes_stale_keys(monkeypatch):
    rate_limit._counters.clear()
    monkeypatch.setattr(rate_limit, "_MAX_MEMORY_KEYS", 5)
    rule = RateLimitRule(limit=1, window_seconds=60)
    for i in range(6):
        rate_limit._counters[f"old-{i}"] = [0.0]  # far outside the window
    rate_limit._memory_blocked("new", rule)
    assert set(rate_limit._counters) == {"new"}
    rate_limit._counters.clear()


# ---------------------------------------------------------------- hygiene


async def test_logs_do_not_contain_ip_or_subject(auth_env, caplog):
    caplog.set_level(logging.DEBUG)
    user_id = uuid.uuid4()
    token = _session(user_id)
    async with _client(_app(), "192.0.2.55") as client:
        for _ in range(31):
            await client.post("/auth/logout", headers=_cookie(token))
        for _ in range(21):
            await client.get("/auth/microsoft/start")
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "rate_limit_blocked" in logged
    assert "192.0.2.55" not in logged and str(user_id) not in logged and token not in logged


async def test_route_from_a_nested_router_is_limited(auth_env):
    inner = APIRouter()

    @inner.post("/runs", name="runs_create")
    async def create():
        return {"ok": True}

    outer = APIRouter()
    outer.include_router(inner, prefix="/api")
    app = FastAPI(dependencies=[Depends(enforce_rate_limit)])
    app.include_router(outer, prefix="/x")
    async with _client(app) as client:
        codes = [(await client.post("/x/api/runs")).status_code for _ in range(11)]
    assert codes == [200] * 10 + [429]


def test_middleware_does_not_decode_without_verification():
    source = SRC.read_text(encoding="utf-8")
    assert "verify_signature" not in source and "get_unverified" not in source
    names = {n.module for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ImportFrom)}
    assert "clw.auth.session_jwt" in names  # subjects come from the verifying decoder
