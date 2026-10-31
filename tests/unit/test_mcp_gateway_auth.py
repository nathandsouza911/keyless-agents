"""The MCP gateway's authentication (SD-048, SD-052): the SD-048 theft and replay set at the gateway.

The agent presents its session capability as `Authorization: Bearer` and
nothing else. The gateway asks the broker (POST /v1/agent/session) on every
request and keeps nothing; whatever the broker refuses, or cannot answer, the
agent gets 401. The broker here is a fake on an httpx MockTransport; the
broker's own refusals are tested in tests/db/test_broker_agent_ops.py.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from clw.mcp_gateway.app import BrokerClient, create_app

PUBLIC = "http://127.0.0.1:8090/mcp"
CAPABILITY = "c" * 43
OTHER = "d" * 43
PROTOCOL = "2026-07-28"


class FakeBroker:
    """POST /v1/agent/session: knows one capability; records every request it gets."""

    def __init__(self, *, status: int = 200, expires_in: timedelta = timedelta(hours=1), fail: bool = False):
        self.status, self.expires_in, self.fail = status, expires_in, fail
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            raise httpx.ConnectError("broker down")
        if request.headers.get("authorization") != f"Bearer {CAPABILITY}" or self.status != 200:
            return httpx.Response(401 if self.status == 200 else self.status,
                                  json={"status": "denied", "reason": "run_token_invalid"})
        expires = (datetime.now(timezone.utc) + self.expires_in).strftime("%Y-%m-%dT%H:%M:%SZ")
        return httpx.Response(200, json={"status": "ok", "session": {
            "id": "11111111-2222-3333-4444-555555555555", "expires_at": expires, "profile": "read-only-investigation",
            "profile_name": "Read-only investigation", "operations": ["users.list_with_sign_in_activity"]}})


def _initialize() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


async def _call(broker: FakeBroker, *, headers: dict | None = None, path: str = "/mcp", method: str = "POST",
                host: str = "127.0.0.1:8090") -> httpx.Response:
    client = BrokerClient("http://broker:8080", http=httpx.AsyncClient(transport=httpx.MockTransport(broker)))
    app = create_app(broker=client, public_url=PUBLIC)
    base = {"accept": "application/json, text/event-stream", "content-type": "application/json", "host": host}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8090") as c:
            return await c.request(method, path, headers=base | (headers or {}),
                                   content=json.dumps(_initialize()) if method == "POST" else None)


async def test_a_valid_capability_connects_and_reaches_the_broker_as_bearer_only():
    broker = FakeBroker()
    reply = await _call(broker, headers={"authorization": f"Bearer {CAPABILITY}"})
    assert reply.status_code == 200, reply.text
    assert broker.requests and all(r.url.path == "/v1/agent/session" for r in broker.requests)
    assert all(r.headers["authorization"] == f"Bearer {CAPABILITY}" for r in broker.requests)
    assert all(CAPABILITY not in str(r.url) and not r.content for r in broker.requests)


async def test_no_capability_is_401_with_the_resource_metadata():
    broker = FakeBroker()
    reply = await _call(broker)
    assert reply.status_code == 401
    assert "resource_metadata=" in reply.headers["www-authenticate"]
    assert not broker.requests


@pytest.mark.parametrize("path", [f"/mcp?access_token={CAPABILITY}", f"/mcp?capability={CAPABILITY}",
                                  f"/mcp?authorization=Bearer%20{CAPABILITY}"])
async def test_a_capability_in_the_url_is_never_accepted(path):
    broker = FakeBroker()
    assert (await _call(broker, path=path)).status_code == 401
    assert not broker.requests


@pytest.mark.parametrize("header", [f"RunToken {CAPABILITY}", f"Basic {CAPABILITY}", CAPABILITY, "Bearer ",
                                    f"Bearer {OTHER}", f"Bearer {CAPABILITY} extra"])
async def test_a_wrong_scheme_or_unknown_capability_is_401(header):
    assert (await _call(FakeBroker(), headers={"authorization": header})).status_code == 401


@pytest.mark.parametrize("status", [401, 403, 500, 503])
async def test_whatever_the_broker_refuses_is_401(status):
    reply = await _call(FakeBroker(status=status), headers={"authorization": f"Bearer {CAPABILITY}"})
    assert reply.status_code == 401


async def test_an_unreachable_broker_is_401_not_an_error():
    reply = await _call(FakeBroker(fail=True), headers={"authorization": f"Bearer {CAPABILITY}"})
    assert reply.status_code == 401


async def test_a_session_the_broker_says_has_expired_is_401():
    reply = await _call(FakeBroker(expires_in=timedelta(seconds=-5)), headers={"authorization": f"Bearer {CAPABILITY}"})
    assert reply.status_code == 401


async def test_every_request_is_checked_again_nothing_is_remembered():
    broker = FakeBroker()
    client = BrokerClient("http://broker:8080", http=httpx.AsyncClient(transport=httpx.MockTransport(broker)))
    app = create_app(broker=client, public_url=PUBLIC)
    headers = {"accept": "application/json, text/event-stream", "content-type": "application/json",
               "authorization": f"Bearer {CAPABILITY}"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8090") as c:
            assert (await c.post("/mcp", headers=headers, content=json.dumps(_initialize()))).status_code == 200
            broker.status = 401  # revoked meanwhile
            assert (await c.post("/mcp", headers=headers, content=json.dumps(_initialize()))).status_code == 401


async def test_the_protected_resource_metadata_names_this_resource():
    reply = await _call(FakeBroker(), path="/.well-known/oauth-protected-resource/mcp", method="GET")
    assert reply.status_code == 200
    assert reply.json()["resource"] == PUBLIC


async def test_a_foreign_host_header_is_refused():
    reply = await _call(FakeBroker(), headers={"authorization": f"Bearer {CAPABILITY}"}, host="evil.example:8090")
    assert reply.status_code in (400, 403, 421)


async def test_the_capability_is_never_logged(caplog):
    caplog.set_level(logging.DEBUG)
    for broker, header in ((FakeBroker(), f"Bearer {CAPABILITY}"), (FakeBroker(status=401), f"Bearer {CAPABILITY}"),
                           (FakeBroker(fail=True), f"Bearer {CAPABILITY}"), (FakeBroker(), f"Basic {CAPABILITY}")):
        await _call(broker, headers={"authorization": header})
    assert CAPABILITY not in caplog.text


@pytest.mark.parametrize("url", ["", "127.0.0.1:8090/mcp", "ftp://x/mcp", "http://user@127.0.0.1:8090/mcp",
                                 "http://127.0.0.1:8090/mcp?x=1", "http://127.0.0.1:8090/mcp#f"])
def test_a_malformed_public_url_stops_the_gateway(url):
    client = BrokerClient("http://broker:8080", http=httpx.AsyncClient())
    with pytest.raises(RuntimeError):
        create_app(broker=client, public_url=url)
