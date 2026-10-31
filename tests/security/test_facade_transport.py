"""Transport.fetch_target, the facade's page request (SD-041): same hardening as
the named path, /beta allowed, only allowlisted headers, Graph errors returned."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from clw.broker.credentials import ValidatedToken
from clw.broker.transport import GRAPH_ORIGIN, GraphAttempt, GraphError, Transport, new_graph_client

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
SECRET = "eyJhbGciOiJub25lIn0.FACADE-SECRET-77.sig"
TOKEN = ValidatedToken(access_token=SECRET, expires_at=NOW + timedelta(hours=1), permissions=frozenset())
DEADLINE = NOW + timedelta(minutes=5)
TARGET = "/beta/users?$count=true&$select=id,displayname"


async def _no_sleep(_):
    return None


def transport() -> Transport:
    return Transport(new_graph_client(), sleep=_no_sleep, clock=lambda: NOW)


class Hooks:
    def __init__(self):
        self.before: list[GraphAttempt] = []
        self.after: list[GraphAttempt] = []

    async def b(self, attempt):
        self.before.append(attempt)

    async def a(self, attempt):
        self.after.append(attempt)


async def fetch(target=TARGET, *, template="/users", headers=(("ConsistencyLevel", "eventual"),), hooks=None):
    hooks = hooks or Hooks()
    page = await transport().fetch_target(target, template=template, headers=headers, token=TOKEN, deadline=DEADLINE,
                                          before_attempt=hooks.b, after_attempt=hooks.a)
    return page, hooks


@respx.mock
async def test_a_beta_page_is_fetched_with_only_the_allowed_headers():
    route = respx.get(GRAPH_ORIGIN + TARGET).mock(return_value=httpx.Response(
        200, json={"value": [{"id": "1"}, {"id": "2"}], "@odata.nextLink": GRAPH_ORIGIN + TARGET + "&$skiptoken=X"},
        headers={"request-id": "req-1"}))
    page, hooks = await fetch()
    sent = route.calls.last.request
    assert sent.url.raw_path.decode() == TARGET
    assert sent.headers["ConsistencyLevel"] == "eventual" and sent.headers["Authorization"] == f"Bearer {SECRET}"
    assert sent.headers["Accept-Encoding"] == "identity"
    assert (page.http_status, page.graph_request_id, page.next_link) == (200, "req-1", GRAPH_ORIGIN + TARGET + "&$skiptoken=X")
    assert json.loads(page.body)["value"][1] == {"id": "2"}
    assert [a.item_count for a in hooks.after] == [2] and hooks.before[0].request_target == TARGET


@respx.mock
async def test_a_single_entity_counts_as_one_item():
    target = "/v1.0/users/00000000-0000-0000-0000-000000000001?$select=id"
    respx.get(GRAPH_ORIGIN + target).mock(return_value=httpx.Response(200, json={"id": "x"}))
    page, hooks = await fetch(target, template="/users/{user_id}", headers=())
    assert page.http_status == 200 and hooks.after[0].item_count == 1


@respx.mock
@pytest.mark.parametrize("status", [400, 403, 404])
async def test_a_final_graph_error_is_returned_for_the_script(status):
    body = {"error": {"code": "Request_ResourceNotFound", "message": "gone"}}
    respx.get(GRAPH_ORIGIN + TARGET).mock(return_value=httpx.Response(status, json=body, headers={"request-id": "r"}))
    page, hooks = await fetch()
    assert (page.http_status, json.loads(page.body), page.next_link) == (status, body, None)
    assert hooks.after[0].http_status == status and hooks.after[0].item_count is None


@respx.mock
async def test_throttling_is_retried_with_an_audited_attempt_each():
    respx.get(GRAPH_ORIGIN + TARGET).mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(200, json={"value": []})])
    page, hooks = await fetch()
    assert page.http_status == 200 and [a.attempt for a in hooks.before] == [1, 2]


@respx.mock
@pytest.mark.parametrize("response, category", [
    (httpx.Response(302, headers={"Location": "https://evil.example/"}), "redirect"),
    (httpx.Response(200, content=b"not json"), "invalid_response"),
    (httpx.Response(200, json=[1, 2]), "invalid_response"),
    (httpx.Response(204), "invalid_response"),
])
async def test_anything_but_a_graph_answer_is_an_error(response, category):
    respx.get(GRAPH_ORIGIN + TARGET).mock(return_value=response)
    with pytest.raises(GraphError) as info:
        await fetch()
    assert info.value.category == category


@pytest.mark.parametrize("target, template, headers", [
    ("/v2.0/users", "/users", ()),
    ("/beta/groups", "/users", ()),
    ("https://evil.example/v1.0/users", "/users", ()),
    ("/beta/users?$select=a b", "/users", ()),
    (TARGET, "/users", (("X-Evil", "1"),)),
    (TARGET, "/users", (("ConsistencyLevel", "session"),)),
    (TARGET, "/users", [("ConsistencyLevel", "eventual")]),
    ("/beta/" + "u" * 5000, "/users", ()),
])
@pytest.mark.respx(assert_all_called=False)
async def test_nothing_is_sent_for_an_unacceptable_request(target, template, headers, respx_mock):
    route = respx_mock.route().mock(return_value=httpx.Response(200, json={"value": []}))
    with pytest.raises(GraphError) as info:
        await fetch(target, template=template, headers=headers)
    assert info.value.category == "invalid_request" and not route.called


@pytest.mark.respx(assert_all_called=False)
async def test_an_audit_hook_failure_sends_nothing(respx_mock):
    route = respx_mock.get(GRAPH_ORIGIN + TARGET).mock(return_value=httpx.Response(200, json={"value": []}))

    class Down(Hooks):
        async def b(self, attempt):
            raise RuntimeError("audit down")

    with pytest.raises(RuntimeError):
        await fetch(hooks=Down())
    assert not route.called
