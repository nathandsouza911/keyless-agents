"""The facade proxy forwards the raw request line, undecided, and holds no credential (SD-041)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import httpx
import respx

from clw.facade_proxy.app import create_app

BROKER = "http://broker-facade:8080"
SOURCE = Path(__file__).resolve().parents[2] / "src" / "clw" / "facade_proxy" / "app.py"


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://graph.microsoft.com")


@respx.mock
async def test_the_raw_request_line_and_two_headers_are_forwarded():
    route = respx.post(BROKER + "/v1/facade").mock(return_value=httpx.Response(
        200, content=b'{"value":[]}', headers={"content-type": "application/json", "request-id": "r-1",
                                              "set-cookie": "x=1"}))
    app = create_app(broker_url=BROKER, client=httpx.AsyncClient())
    async with _client(app) as c:
        reply = await c.get("/beta/users?$select=id,%20displayName&$%09op=999",
                            headers={"Authorization": "Bearer cap", "ConsistencyLevel": "eventual", "X-Other": "1"})
    envelope = json.loads(route.calls.last.request.content)
    assert envelope == {"method": "GET", "target": "/beta/users?$select=id,%20displayName&$%09op=999",
                        "authorization": "Bearer cap", "consistency_level": "eventual", "body_length": 0}
    assert reply.status_code == 200 and reply.headers["request-id"] == "r-1" and "set-cookie" not in reply.headers


@respx.mock
async def test_a_body_is_counted_never_forwarded():
    route = respx.post(BROKER + "/v1/facade").mock(return_value=httpx.Response(403, content=b"{}"))
    app = create_app(broker_url=BROKER, client=httpx.AsyncClient())
    async with _client(app) as c:
        reply = await c.patch("/v1.0/users/1", content=b'{"accountEnabled":false}')
    envelope = json.loads(route.calls.last.request.content)
    assert envelope["method"] == "PATCH" and envelope["body_length"] == 24
    assert b"accountEnabled" not in route.calls.last.request.content and reply.status_code == 403


@respx.mock
async def test_an_unreachable_broker_is_a_graph_shaped_503():
    respx.post(BROKER + "/v1/facade").mock(side_effect=httpx.ConnectError("down"))
    app = create_app(broker_url=BROKER, client=httpx.AsyncClient())
    async with _client(app) as c:
        reply = await c.get("/v1.0/users")
    assert reply.status_code == 503 and reply.json()["error"]["innerError"]["clw-reason"] == "broker_unreachable"


def test_the_proxy_imports_no_broker_policy_or_credential_code():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not {m for m in imported if m and m.startswith("clw")}, imported
