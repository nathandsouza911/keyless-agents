"""Graph transport (Task 11): fixed destination, exact request, bounded
retries, timeouts and responses, no token disclosure.

All HTTP is mocked with respx; no test reaches the network. Behaviour of
the real Microsoft Graph (status codes, headers, error codes) is
unverified (A-02, A-14, A-15, A-16)."""

from __future__ import annotations

import asyncio
import dataclasses
import gzip
import json
import traceback
import zlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from clw.broker import operations, transport
from clw.broker.credentials import ValidatedToken
from clw.broker.operations import BuiltRequest, build_request
from clw.broker.transport import (
    GRAPH_ORIGIN,
    GraphAttempt,
    GraphError,
    Transport,
    new_graph_client,
    parse_retry_after,
)

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
DEADLINE = NOW + timedelta(minutes=5)
LIST = "users.list_with_sign_in_activity"
SECRET = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.SECRET-TOKEN-4f1a.sig"
TOKEN = ValidatedToken(access_token=SECRET, expires_at=NOW + timedelta(hours=1), permissions=frozenset({"User.Read.All"}))
REQUEST = build_request(operations.get(LIST), {"select": ["signInActivity", "id"], "top": 50})
TARGET = "/v1.0/users?$select=id,signInActivity&$top=50"
URL = GRAPH_ORIGIN + TARGET
USERS = [{"id": "1"}, {"id": "2"}]
LICENCE = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class Recorder:
    """before/after hooks and a fake sleep that advances the clock."""

    def __init__(self, clock):
        self.clock, self.events, self.sleeps = clock, [], []

    async def before(self, attempt: GraphAttempt):
        self.events.append(("before", attempt))

    async def after(self, attempt: GraphAttempt):
        self.events.append(("after", attempt))

    async def sleep(self, seconds: float):
        self.sleeps.append(seconds)
        self.clock.now += timedelta(seconds=seconds)


@pytest.fixture
def env():
    clock = Clock()
    rec = Recorder(clock)

    def make(**kwargs):
        return Transport(new_graph_client(), sleep=rec.sleep, clock=clock, **kwargs)

    return clock, rec, make


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


async def _run(make, rec, request=REQUEST, token=TOKEN, deadline=DEADLINE, **kwargs):
    return await make(**kwargs).execute(request, token, deadline=deadline, before_attempt=rec.before, after_attempt=rec.after)


async def _fail(make, rec, **kwargs) -> GraphError:
    with pytest.raises(GraphError) as info:
        await _run(make, rec, **kwargs)
    return info.value


def serve(mock, pages: dict[str, httpx.Response]):
    """Answer by exact request target; anything else is a test failure."""
    seen: list[str] = []

    def answer(request: httpx.Request):
        target = request.url.raw_path.decode()
        seen.append(target)
        assert target in pages, target
        return pages[target]

    mock.route(host="graph.microsoft.com").mock(side_effect=answer)
    return seen


def _ok(value=USERS, **extra):
    return httpx.Response(200, json={"value": value, **extra}, headers={"request-id": "aaaa-1111"})


# --- the approved request, exactly ---------------------------------------------------


async def test_approved_request_is_sent_exactly(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=_ok())
    assert await _run(make, rec) == USERS
    (call,) = route.calls
    req = call.request
    assert req.method == "GET"
    assert req.url.scheme == "https" and req.url.host == "graph.microsoft.com" and req.url.port is None
    assert req.url.raw_path.decode() == TARGET
    assert req.headers["authorization"] == f"Bearer {SECRET}"
    assert req.headers["accept-encoding"] == "identity"
    assert "content-length" not in req.headers or req.headers["content-length"] == "0"
    assert req.content == b""


async def test_attempt_records(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=_ok())
    await _run(make, rec)
    (kind1, before), (kind2, after) = rec.events
    assert (kind1, kind2) == ("before", "after")
    assert before == GraphAttempt(attempt=1, method="GET", request_target=TARGET, http_status=None,
                                  graph_request_id=None, duration_ms=0, item_count=None)
    assert (after.attempt, after.request_target, after.http_status, after.graph_request_id, after.item_count) == (
        1, TARGET, 200, "aaaa-1111", 2)
    assert type(after.duration_ms) is int and after.duration_ms >= 0


@pytest.mark.parametrize("changes", [
    {"method": "POST"}, {"method": "DELETE"}, {"method": "get"},
    {"path": "/users/../groups"}, {"path": "//evil.example/users"}, {"path": "/users%2F"}, {"path": "users"},
    {"path": "/groups"}, {"path_template": "/groups"}, {"path": "@evil.example/users"},
    {"query": (("$select", "id"), ("$expand", "manager x"))}, {"query": (("$select", "id&$expand=manager"),)},
    {"query": (("$select", "id"), ("$expand", "manager"))}, {"query": (("$filter", "x"),)},
    {"query": (("$select", "id#frag"),)}, {"query": (("$select", "id\r\nHost: evil"),)}, {"query": [("$select", "id")]},
])
async def test_altered_request_is_refused_before_anything_is_sent(env, mock, changes):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    err = await _fail(make, rec, request=dataclasses.replace(REQUEST, **changes))
    assert err.category == "invalid_request" and route.calls.call_count == 0 and rec.events == []


async def test_lookalike_request_type_is_refused(env, mock):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())

    @dataclasses.dataclass(frozen=True)
    class Lookalike:
        method: str
        path_template: str
        path: str
        query: tuple

    fake = Lookalike(REQUEST.method, REQUEST.path_template, REQUEST.path, REQUEST.query)
    assert (await _fail(make, rec, request=fake)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_non_executable_registry_request_is_refused(env, mock):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    write = BuiltRequest(method="DELETE", path_template="/users/{user_id}",
                         path="/users/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", query=())
    assert (await _fail(make, rec, request=write)).category == "invalid_request"
    get_write = dataclasses.replace(write, method="GET")
    assert (await _fail(make, rec, request=get_write)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_get_only_even_if_the_registry_had_an_executable_write(env, mock, monkeypatch):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    spec = dataclasses.replace(operations.get("users.delete"), executable=True, kind="read")
    monkeypatch.setattr(operations, "REGISTRY", {**operations.REGISTRY, "users.delete": spec})
    write = BuiltRequest(method="DELETE", path_template="/users/{user_id}",
                         path="/users/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", query=())
    assert (await _fail(make, rec, request=write)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_non_executable_read_is_refused(env, mock, monkeypatch):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    spec = dataclasses.replace(operations.get(LIST), executable=False)
    monkeypatch.setattr(operations, "REGISTRY", {**operations.REGISTRY, LIST: spec})
    assert (await _fail(make, rec)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_destination_is_rechecked_after_rendering(env, mock, monkeypatch):
    # If the origin constant were ever wrong, nothing would be sent.
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    monkeypatch.setattr(transport, "GRAPH_ORIGIN", "https://evil.example")
    assert (await _fail(make, rec)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_client_auth_added_after_construction_is_not_used(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=_ok())
    client = new_graph_client()
    t = Transport(client, sleep=rec.sleep, clock=clock)
    client.auth = ("user", "password")
    await t.execute(REQUEST, TOKEN, deadline=DEADLINE, before_attempt=rec.before, after_attempt=rec.after)
    assert route.calls.last.request.headers["authorization"] == f"Bearer {SECRET}"


async def test_request_cannot_carry_a_host_scheme_or_port(env, mock):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    for path in ("https://evil.example/users", ":8443/users", "/users:8443", "/users?x=1", "/users#x"):
        err = await _fail(make, rec, request=dataclasses.replace(REQUEST, path=path))
        assert err.category == "invalid_request"
    assert route.calls.call_count == 0


@pytest.mark.parametrize("token", [
    SECRET, None, {"access_token": SECRET},
    dataclasses.replace(TOKEN, access_token=""),
    dataclasses.replace(TOKEN, access_token=SECRET + "\r\nX-Evil: 1"),
    dataclasses.replace(TOKEN, access_token=SECRET + " extra"),
])
async def test_only_a_validated_token_is_accepted(env, mock, token):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    assert (await _fail(make, rec, token=token)).category == "invalid_request"
    assert route.calls.call_count == 0


async def test_expired_token_is_not_sent(env, mock):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    expired = dataclasses.replace(TOKEN, expires_at=NOW)
    assert (await _fail(make, rec, token=expired)).category == "token_expired"
    assert route.calls.call_count == 0 and rec.events == []


@pytest.mark.parametrize("deadline", [NOW, NOW - timedelta(seconds=1), datetime(2026, 10, 17, 12, 5)])
async def test_bad_or_passed_deadline_sends_nothing(env, mock, deadline):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())
    err = await _fail(make, rec, deadline=deadline)
    assert err.category in {"deadline_exceeded", "invalid_request"} and route.calls.call_count == 0


# --- hooks ----------------------------------------------------------------------------------


async def test_before_attempt_raising_sends_nothing(env, mock):
    clock, rec, make = env
    route = mock.route().mock(return_value=_ok())

    async def boom(attempt):
        raise RuntimeError("audit down")

    with pytest.raises(RuntimeError):
        await make().execute(REQUEST, TOKEN, deadline=DEADLINE, before_attempt=boom, after_attempt=rec.after)
    assert route.calls.call_count == 0


async def test_after_attempt_raising_returns_no_data(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=_ok())

    async def boom(attempt):
        raise RuntimeError("audit down")

    with pytest.raises(RuntimeError):
        await make().execute(REQUEST, TOKEN, deadline=DEADLINE, before_attempt=rec.before, after_attempt=boom)


async def test_after_attempt_is_called_for_failed_attempts(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(404, headers={"request-id": "r-404"}))
    err = await _fail(make, rec)
    assert err.category == "not_found" and err.http_status == 404 and err.graph_request_id == "r-404"
    assert [k for k, _ in rec.events] == ["before", "after"]
    assert rec.events[1][1].http_status == 404 and rec.events[1][1].item_count is None


# --- retries and throttling ----------------------------------------------------------------


async def test_429_with_retry_after_then_200(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(side_effect=[httpx.Response(429, headers={"Retry-After": "2"}), _ok()])
    assert await _run(make, rec) == USERS
    assert route.calls.call_count == 2 and rec.sleeps == [2.0]
    assert [a.attempt for k, a in rec.events] == [1, 1, 2, 2]
    assert [a.http_status for k, a in rec.events if k == "after"] == [429, 200]


async def test_retry_after_http_date(env, mock):
    clock, rec, make = env
    date = "Sat, 17 Oct 2026 12:00:07 GMT"
    mock.get(URL).mock(side_effect=[httpx.Response(429, headers={"Retry-After": date}), _ok()])
    await _run(make, rec)
    assert rec.sleeps == [7.0]


async def test_huge_retry_after_is_capped(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(side_effect=[httpx.Response(429, headers={"Retry-After": "99999"}), _ok()])
    await _run(make, rec, deadline=NOW + timedelta(minutes=10))
    assert rec.sleeps == [30.0]


async def test_retry_after_beyond_deadline_fails_fast(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(side_effect=[httpx.Response(429, headers={"Retry-After": "20"}), _ok()])
    err = await _fail(make, rec, deadline=NOW + timedelta(seconds=10))
    assert err.category == "deadline_exceeded" and rec.sleeps == [] and route.calls.call_count == 1


@pytest.mark.parametrize("status", [503, 504])
async def test_503_and_504_are_retried(env, mock, status):
    clock, rec, make = env
    route = mock.get(URL).mock(side_effect=[httpx.Response(status), _ok()])
    assert await _run(make, rec) == USERS
    assert route.calls.call_count == 2 and rec.sleeps == [1.0]   # backoff without Retry-After


@pytest.mark.parametrize("status,category", [
    (400, "bad_request"), (401, "unauthorized"), (403, "forbidden"), (404, "not_found"), (409, "client_error"),
    (500, "server"), (502, "server"),
])
async def test_other_errors_are_not_retried(env, mock, status, category):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=httpx.Response(status))
    err = await _fail(make, rec)
    assert err.category == category and err.http_status == status and route.calls.call_count == 1


async def test_retries_are_bounded(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
    err = await _fail(make, rec)
    assert err.category == "throttled" and route.calls.call_count == 4 and len(rec.sleeps) == 3
    assert [a.attempt for k, a in rec.events if k == "before"] == [1, 2, 3, 4]


async def test_backoff_doubles_without_retry_after(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(503))
    await _fail(make, rec, max_attempts=4)
    assert rec.sleeps == [1.0, 2.0, 4.0]


async def test_non_premium_403_maps_to_licence_required(env, mock):
    clock, rec, make = env
    body = {"error": {"code": LICENCE, "message": "Neither tenant is B2C or tenant doesn't have premium license"}}
    route = mock.get(URL).mock(return_value=httpx.Response(403, json=body))
    err = await _fail(make, rec)
    assert err.category == "licence_required" and err.graph_error_code == LICENCE and route.calls.call_count == 1
    assert "premium license" not in str(err) and "premium license" not in repr(err)


@pytest.mark.parametrize("body", [
    b"not json", b"[]", b'{"error": "x"}', b'{"error": {"code": 5}}', b'{"error": {"code": "bad code!"}}',
    b'{"error": {"code": "' + b"A" * 200 + b'"}}',
])
async def test_unparseable_error_body_gives_no_code(env, mock, body):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(403, content=body))
    err = await _fail(make, rec)
    assert err.category == "forbidden" and err.graph_error_code is None


# --- network errors and timeouts ------------------------------------------------------------


@pytest.mark.parametrize("exc,category", [
    (httpx.ConnectTimeout("t"), "timeout"), (httpx.ReadTimeout("t"), "timeout"), (httpx.PoolTimeout("t"), "timeout"),
    (httpx.ConnectError("c"), "network"), (httpx.ReadError("r"), "network"), (httpx.RemoteProtocolError("p"), "network"),
])
async def test_network_errors_are_retried_then_reported(env, mock, exc, category):
    clock, rec, make = env
    route = mock.get(URL).mock(side_effect=exc)
    err = await _fail(make, rec)
    assert err.category == category and err.http_status is None and route.calls.call_count == 4
    assert err.__context__ is None and err.__cause__ is None
    assert all(a.http_status is None for k, a in rec.events if k == "after")


async def test_network_error_then_success(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(side_effect=[httpx.ConnectError("c"), _ok()])
    assert await _run(make, rec) == USERS


async def test_timeouts_are_bounded_and_set_per_request(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=_ok())
    await _run(make, rec)
    timeout = route.calls.last.request.extensions["timeout"]
    assert set(timeout) == {"connect", "read", "write", "pool"}
    assert all(isinstance(v, float) and 0 < v <= 30 for v in timeout.values())


async def test_timeouts_never_exceed_the_remaining_run_time(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=_ok())
    await _run(make, rec, deadline=NOW + timedelta(seconds=3))
    assert all(v <= 3 for v in route.calls.last.request.extensions["timeout"].values())


async def test_slow_response_is_cut_at_the_deadline(env, mock):
    clock, rec, make = env

    async def slow(request):
        await asyncio.sleep(5)
        return _ok()

    mock.get(URL).mock(side_effect=slow)
    transport_ = Transport(new_graph_client(), sleep=rec.sleep, clock=clock)
    # Real time is used for the in-flight bound: 0.2 s remaining.
    err = None
    with pytest.raises(GraphError) as info:
        await transport_.execute(REQUEST, TOKEN, deadline=NOW + timedelta(seconds=0.2),
                                 before_attempt=rec.before, after_attempt=rec.after)
    err = info.value
    assert err.category == "deadline_exceeded"
    assert [k for k, _ in rec.events] == ["before", "after"]


# --- redirects ------------------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_redirects_are_not_followed(env, mock, status):
    clock, rec, make = env
    evil = mock.route(host="evil.example").mock(return_value=_ok())
    graph_other = mock.get(GRAPH_ORIGIN + "/v1.0/groups").mock(return_value=_ok())
    for location in ("https://evil.example/steal", GRAPH_ORIGIN + "/v1.0/groups"):
        mock.get(URL).mock(return_value=httpx.Response(status, headers={"Location": location}))
        err = await _fail(make, rec)
        assert err.category == "redirect" and err.http_status == status
    assert evil.calls.call_count == 0 and graph_other.calls.call_count == 0


async def test_client_that_follows_redirects_is_refused():
    for client in (httpx.AsyncClient(follow_redirects=True, trust_env=False), httpx.AsyncClient(),
                   httpx.AsyncClient(trust_env=False, auth=("u", "p")),
                   httpx.AsyncClient(trust_env=False, event_hooks={"request": [lambda r: None]})):
        with pytest.raises(ValueError):
            Transport(client)
    with pytest.raises(ValueError):
        Transport(object())  # type: ignore[arg-type]


def test_graph_client_is_hardened():
    client = new_graph_client()
    assert client.follow_redirects is False and client.trust_env is False and client.auth is None
    assert client.event_hooks == {"request": [], "response": []}
    t = client.timeout
    assert all(v is not None and v <= 30 for v in (t.connect, t.read, t.write, t.pool))


async def test_client_default_headers_are_not_sent(env, mock):
    clock, rec, make = env
    route = mock.get(URL).mock(return_value=_ok())
    client = new_graph_client()
    client.headers["X-Leak"] = "1"
    client.cookies.set("c", "1", domain="graph.microsoft.com")
    await Transport(client, sleep=rec.sleep, clock=clock).execute(
        REQUEST, TOKEN, deadline=DEADLINE, before_attempt=rec.before, after_attempt=rec.after)
    sent = route.calls.last.request.headers
    assert "x-leak" not in sent and "cookie" not in sent


# --- responses ------------------------------------------------------------------------------


async def test_oversized_response_is_refused(env, mock):
    clock, rec, make = env
    big = json.dumps({"value": [{"id": "x" * 1000}] * 200}).encode()
    mock.get(URL).mock(return_value=httpx.Response(200, content=big))
    err = await _fail(make, rec, max_response_bytes=64 * 1024)
    assert err.category == "response_too_large" and err.http_status == 200


async def test_oversized_response_without_content_length_is_refused(env, mock):
    clock, rec, make = env

    async def chunks():
        for _ in range(100):
            yield b"x" * 1024

    mock.get(URL).mock(return_value=httpx.Response(200, content=chunks()))
    err = await _fail(make, rec, max_response_bytes=16 * 1024)
    assert err.category == "response_too_large"


async def test_declared_oversize_is_refused_before_reading(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(200, content=b"{}", headers={"Content-Length": "999999999"}))
    assert (await _fail(make, rec, max_response_bytes=1024)).category == "response_too_large"


@pytest.mark.parametrize("encoding,body", [
    ("gzip", gzip.compress(b'{"value": []}')),
    ("deflate", zlib.compress(b'{"value": []}')),
    ("br", b'{"value": []}'),          # a plain JSON body under a compressed label
    ("x-unknown", b'{"value": []}'),
])
async def test_compressed_response_is_refused(env, mock, encoding, body):
    # Only identity is accepted, so no decompression happens at all.
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(200, content=body, headers={"Content-Encoding": encoding}))
    assert (await _fail(make, rec)).category == "invalid_response"


async def test_error_body_is_read_only_up_to_its_own_limit(env, mock):
    # A licence code beyond the first 64 KiB is not reached: the body is not read further.
    clock, rec, make = env
    body = b'{"pad": "' + b"x" * (70 * 1024) + b'", "error": {"code": "' + LICENCE.encode() + b'"}}'
    mock.get(URL).mock(return_value=httpx.Response(403, content=body))
    err = await _fail(make, rec)
    assert err.category == "forbidden" and err.graph_error_code is None


async def test_total_size_across_pages_is_bounded(env, mock):
    clock, rec, make = env
    page = [{"id": "x" * 500}] * 20
    serve(mock, {
        TARGET: _ok(page, **{"@odata.nextLink": URL + "&$skiptoken=abc"}),
        TARGET + "&$skiptoken=abc": _ok(page, **{"@odata.nextLink": URL + "&$skiptoken=abcd"}),
        TARGET + "&$skiptoken=abcd": _ok(page),
    })
    err = await _fail(make, rec, max_response_bytes=16 * 1024, max_total_bytes=24 * 1024)
    assert err.category == "response_too_large"


@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b'{"value": {}}', b'{"value": [1]}', b'{"value": ["x"]}', b'{"novalue": []}',
    b'{"value": [], "@odata.nextLink": 5}', b'{"value": [], "value": [{"id": "1"}]}', b"{bad json",
    b'{"value": [NaN]}', b'{"value": [], "x": NaN}', b'{"value": [], "x": Infinity}',
    "{\"value\": []}".encode("utf-16"),
])
async def test_malformed_success_body_is_invalid_response(env, mock, body):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(200, content=body))
    assert (await _fail(make, rec)).category == "invalid_response"


@pytest.mark.parametrize("status", [201, 202, 204, 206])
async def test_other_2xx_is_invalid_response(env, mock, status):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(status, json={"value": []}))
    assert (await _fail(make, rec)).category == "invalid_response"


@pytest.mark.parametrize("rid,expected", [
    ("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"),
    ("x" * 65, None), ("a b", None), ("<script>", None), ("", None),
])
async def test_request_id_is_kept_only_when_well_formed(env, mock, rid, expected):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(200, json={"value": []}, headers={"request-id": rid}))
    await _run(make, rec)
    assert rec.events[-1][1].graph_request_id == expected


async def test_non_paginated_response_with_next_link_is_refused(env, mock, monkeypatch):
    clock, rec, make = env
    spec = dataclasses.replace(operations.get(LIST), paginated=False)
    monkeypatch.setattr(operations, "REGISTRY", {**operations.REGISTRY, LIST: spec})
    mock.get(URL).mock(return_value=_ok(**{"@odata.nextLink": URL + "&$skiptoken=abc"}))
    assert (await _fail(make, rec)).category == "invalid_next_link"


# --- no disclosure --------------------------------------------------------------------------


async def test_token_never_appears_in_errors_or_attempts(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(side_effect=[httpx.Response(429, headers={"Retry-After": "1"}), httpx.ConnectError(SECRET),
                                    httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken", "message": SECRET}})])
    err = await _fail(make, rec)
    rendered = "".join(traceback.format_exception(err)) + repr(err) + str(vars(err)) + repr(rec.events)
    assert SECRET not in rendered and "SECRET-TOKEN" not in rendered
    assert err.category == "unauthorized" and err.graph_error_code == "InvalidAuthenticationToken"


async def test_response_body_is_not_in_errors(env, mock):
    clock, rec, make = env
    mock.get(URL).mock(return_value=httpx.Response(500, json={"error": {"code": "x", "message": "PRIVATE-DATA-77"}}))
    err = await _fail(make, rec)
    assert "PRIVATE-DATA-77" not in "".join(traceback.format_exception(err)) + str(vars(err))


def test_graph_error_holds_structured_fields_only():
    err = GraphError("throttled", http_status=429, graph_error_code="TooManyRequests", graph_request_id="r-1")
    assert str(err) == "throttled"
    assert (err.category, err.http_status, err.graph_error_code, err.graph_request_id) == (
        "throttled", 429, "TooManyRequests", "r-1")
    with pytest.raises(ValueError):
        GraphError("something_else")


# --- parse_retry_after -----------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("2", 2.0), ("0", 0.0), (" 5 ", 5.0), ("Sat, 17 Oct 2026 12:00:30 GMT", 30.0),
    ("Sat, 17 Oct 2026 11:59:00 GMT", 0.0), (None, None), ("", None), ("-1", None), ("1.5", None),
    ("soon", None), ("99999999999999", None), ("Sat, 17 Oct 2026 12:00:30", None),
])
def test_parse_retry_after(value, expected):
    assert parse_retry_after(value, now=NOW) == expected


def test_transport_bounds_are_validated():
    for kwargs in ({"max_attempts": 0}, {"max_attempts": 11}, {"max_pages": 0}, {"max_single_wait_s": -1},
                   {"max_response_bytes": 0}, {"max_total_bytes": 0}):
        with pytest.raises(ValueError):
            Transport(new_graph_client(), **kwargs)


def test_transport_module_exposes_no_general_http_api():
    public = {n for n in vars(transport) if not n.startswith("_")}
    assert not public & {"get", "post", "request", "send", "fetch", "AsyncClient"}
    # SD-041: fetch_target, the facade's page request, takes only a policy-approved canonical target.
    assert [n for n in vars(Transport) if not n.startswith("_")] == ["execute", "fetch_target"]
