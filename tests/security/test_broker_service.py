"""Broker service pieces that need no database (Task 12, SD-032): run tokens,
the Authorization header, the request body, the response record mapping,
the approved-target continuation rule and the HTTP surface. The end-to-end
behaviour against PostgreSQL is in tests/db/test_broker_ops.py and
tests/db/test_broker_fail_closed.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from clw.broker import capability
from clw.broker.app import create_app, load_catalog
from clw.broker.capability import RunRefused, issue_run_token, parse_authorization, run_token_sha256
from clw.broker.service import (
    INVALID_OPERATION, MAX_BODY_BYTES, BrokerService, continues, operation_label, parse_body, response_fields,
)
from clw.broker.transport import GraphAttempt

REPO = Path(__file__).resolve().parents[2]
BASE = "/v1.0/users?$select=id,signInActivity&$top=50"


# ------------------------------------------------------------------ run tokens


def test_run_tokens_are_256_random_bits_stored_as_sha256():
    tokens = [issue_run_token() for _ in range(500)]
    assert len({t.token for t in tokens}) == 500
    for issued in tokens[:20]:
        assert len(issued.token) == 43 and parse_authorization(f"RunToken {issued.token}") == issued.token
        assert issued.sha256 == hashlib.sha256(issued.token.encode()).hexdigest() == run_token_sha256(issued.token)
        assert issued.token not in repr(issued)
    assert capability.RUN_TOKEN_BYTES == 32


@pytest.mark.parametrize("header", [
    None, 1, b"RunToken " + b"a" * 43, "", "RunToken", "RunToken ", "Bearer " + "a" * 43, "runtoken " + "a" * 43,
    "RunToken  " + "a" * 43, "RunToken\t" + "a" * 43, "RunToken " + "a" * 42, "RunToken " + "a" * 44,
    "RunToken " + "a" * 42 + "=", "RunToken " + "a" * 42 + "+", "RunToken " + "a" * 42 + "/",
    "RunToken " + "a" * 43 + "\n", "RunToken " + "a" * 42 + "Ã©", "RunToken " + "a" * 43 + " x",
])
def test_authorization_header_must_be_exactly_runtoken_and_a_token(header):
    assert parse_authorization(header) is None


def test_authorization_header_accepts_the_url_safe_alphabet():
    token = "Az09-_" + "b" * 37
    assert parse_authorization(f"RunToken {token}") == token


@pytest.mark.parametrize("token", [None, "", "a" * 42, "a" * 44, "a" * 42 + "=", 43])
async def test_resolve_run_refuses_malformed_tokens_before_any_lookup(token):
    from datetime import datetime, timezone

    with pytest.raises(RunRefused) as info:
        await capability.resolve_run(None, token, catalog={}, now=datetime.now(timezone.utc))  # type: ignore[arg-type]
    assert info.value.reason == "run_token_invalid" and info.value.run is None


def test_run_refusals_carry_known_reasons_only():
    with pytest.raises(ValueError):
        RunRefused("tenant_mismatch")  # type: ignore[arg-type]
    refused = RunRefused("run_halted")
    assert str(refused) == "run_halted" and refused.run is None


# ------------------------------------------------------------------- the body


@pytest.mark.parametrize("raw, expected", [
    (b'{"op": "users.list_with_sign_in_activity", "params": {"select": ["id"]}}',
     ("users.list_with_sign_in_activity", "users.list_with_sign_in_activity", {"select": ["id"]}, None)),
    (b'{"params": {}, "op": "x"}', ("x", "x", {}, None)),
    (b'{"op": "x", "params": {}, "path": "/users"}', ("x", None, None, "unknown_field")),
    (b'{"op": "x", "params": {}, "Path": "/users"}', ("x", None, None, "unknown_field")),
    (b'{"op": "x", "params": {}, "tenant_id": "t"}', ("x", None, None, "unknown_field")),
    (b'{"params": {}}', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'{"op": "x"}', ("x", None, None, "invalid_request")),
    (b'{"op": "x", "params": null}', ("x", None, None, "invalid_request")),
    (b'{"op": "x", "params": "a"}', ("x", None, None, "invalid_request")),
    (b'{"op": true, "params": {}}', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'{"op": "x", "op": "x", "params": {}}', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'{"op": "x", "params": {"a": 1, "a": 2}}', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'{"op": "x", "params": {"top": Infinity}}', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'["op"]', (INVALID_OPERATION, None, None, "invalid_request")),
    (b'"op"', (INVALID_OPERATION, None, None, "invalid_request")),
    (b"", (INVALID_OPERATION, None, None, "invalid_request")),
    (b"\xff", (INVALID_OPERATION, None, None, "invalid_request")),
    (None, (INVALID_OPERATION, None, None, "invalid_request")),
])
def test_body_is_strict(raw, expected):
    parsed = parse_body(raw)
    assert (parsed.label, parsed.op, parsed.params, parsed.reason) == expected


def test_body_size_is_bounded():
    padding = "x" * (MAX_BODY_BYTES - len('{"op": "x", "params": {"p": ""}}'))
    exact = ('{"op": "x", "params": {"p": "' + padding + '"}}').encode()
    assert len(exact) == MAX_BODY_BYTES and parse_body(exact).reason is None
    assert parse_body(exact + b" ").reason == "invalid_request"


def test_deeply_nested_body_is_refused_not_crashed():
    raw = b'{"op": "x", "params": ' + b"[" * 30_000 + b"]" * 30_000 + b"}"
    assert len(raw) <= MAX_BODY_BYTES  # refused by the parser's recursion limit, not the size cap
    assert parse_body(raw).reason == "invalid_request"


@pytest.mark.parametrize("op, label", [
    ("users.list_with_sign_in_activity", "users.list_with_sign_in_activity"), ("A-z_0.9", "A-z_0.9"),
    ("x" * 128, "x" * 128), ("x" * 129, INVALID_OPERATION), ("", INVALID_OPERATION), ("a b", INVALID_OPERATION),
    ("users.update\n", INVALID_OPERATION), ("users/update", INVALID_OPERATION), ("Ð°", INVALID_OPERATION),
    (None, INVALID_OPERATION), (1, INVALID_OPERATION), (["users.update"], INVALID_OPERATION),
])
def test_operation_label(op, label):
    assert operation_label(op) == label


# ------------------------------------------------------------ response record


def _attempt(status, items=None):
    return GraphAttempt(3, "GET", BASE, status, "rid-1", 12, items)


@pytest.mark.parametrize("attempt, expected", [
    (_attempt(200, 5), {"status": "succeeded", "http_status": 200, "item_count": 5}),
    (_attempt(200, 0), {"status": "succeeded", "http_status": 200, "item_count": 0}),
    (_attempt(None), {"status": "failed", "reason": "no_response"}),
    (_attempt(200), {"status": "failed", "reason": "unusable_response", "details": {"received_http_status": 200}}),
    (_attempt(204), {"status": "failed", "reason": "unusable_response", "details": {"received_http_status": 204}}),
    (_attempt(299), {"status": "failed", "reason": "unusable_response", "details": {"received_http_status": 299}}),
    (_attempt(301), {"status": "failed", "reason": "http_301", "http_status": 301}),
    (_attempt(199), {"status": "failed", "reason": "http_199", "http_status": 199}),
    (_attempt(429), {"status": "failed", "reason": "http_429", "http_status": 429}),
    (_attempt(503), {"status": "failed", "reason": "http_503", "http_status": 503}),
])
def test_response_fields(attempt, expected):
    assert response_fields(attempt) == {"graph_request_id": "rid-1", "duration_ms": 12} | expected


# ------------------------------------------------------- approved continuation


@pytest.mark.parametrize("target, ok", [
    (BASE, True), (BASE + "&$skiptoken=abc", True), (BASE + "&$skiptoken=a%2Fb", True),
    (BASE + "&$top=1", False), (BASE + "$skiptoken=abc", False), (BASE + "&$skiptokenx=abc", False),
    (BASE + "&$SKIPTOKEN=abc", False), (BASE[:-1], False), (BASE + "0", False), ("/v1.0/groups", False),
    ("x" + BASE, False), (None, False), (b"/v1.0/users", False),
])
def test_attempt_target_must_continue_the_approved_target(target, ok):
    assert continues(target, BASE) is ok


def test_continuation_of_a_target_without_a_query():
    assert continues("/v1.0/users?$skiptoken=abc", "/v1.0/users")
    assert not continues("/v1.0/users&$skiptoken=abc", "/v1.0/users")


# ----------------------------------------------------------------- surface


def test_only_routes_are_post_v1_ops_the_facade_and_the_agent_routes():
    # SD-041 adds the facade proxy's route; SD-049 and SD-054 the MCP gateway's three. Nothing takes a URL.
    app = create_app(object())  # type: ignore[arg-type]
    routes = {(tuple(sorted(r.methods)), r.path) for r in app.routes if hasattr(r, "methods")}
    assert routes == {(("POST",), "/v1/ops"), (("POST",), "/v1/facade"), (("POST",), "/v1/agent/ops"),
                      (("POST",), "/v1/agent/session"), (("POST",), "/v1/agent/propose")}


async def test_handle_requires_a_resolved_run_context():
    svc = BrokerService(sessionmaker=None, writer=None, transport=None, credentials=None, catalog={})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        await svc.handle(capability.RunRef("r", "t"), "x", {})  # type: ignore[arg-type]


def test_catalog_loads_every_task_manifest_by_id():
    catalog = load_catalog()
    assert list(catalog) == ["dormant-account-investigation"]
    with pytest.raises(TypeError):
        catalog["x"] = catalog["dormant-account-investigation"]  # type: ignore[index]


def test_catalog_refuses_duplicate_ids_and_bad_manifests(tmp_path):
    source = (REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml").read_bytes()
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "manifest.yaml").write_bytes(source)
    with pytest.raises(RuntimeError):
        load_catalog(tmp_path)
    (tmp_path / "b" / "manifest.yaml").write_bytes(source.replace(b"mode: app_only", b"mode: delegated"))
    with pytest.raises(Exception):
        load_catalog(tmp_path)


def test_broker_service_modules_name_no_graph_host_and_take_no_url():
    for name in ("service", "capability", "app"):
        source = (REPO / "src" / "clw" / "broker" / f"{name}.py").read_text()
        assert "graph.microsoft.com" not in source and "httpx" not in source
    body = json.loads(json.dumps({"op": "x", "params": {}, "url": "https://graph.microsoft.com/v1.0/users"}))
    assert parse_body(json.dumps(body).encode()).reason == "unknown_field"
