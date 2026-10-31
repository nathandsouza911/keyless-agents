"""Facade pagination (SD-041): Graph's nextLink is validated, held by the broker,
and replaced by a single-use handle bound to its run."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from clw.audit.events import continues_approved_target
from clw.broker.facade.pages import Continuation, PageHandles, next_target, rewrite_next_link

APPROVED = "/beta/users?$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname"
TEMPLATE = "/users"
G = "https://graph.microsoft.com"
NOW = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)


def link(query: str, path: str = "/beta/users") -> str:
    return f"{G}{path}?{query}"


GOOD = link("$count=true&$filter=userType%20eq%20%27Member%27&$select=id,displayname&$skiptoken=RFNwdAI")


def test_a_valid_next_link_becomes_the_brokers_bound_continuation():
    target = next_target(GOOD, approved_target=APPROVED, template=TEMPLATE)
    assert target == APPROVED + "&$skiptoken=RFNwdAI"
    assert continues_approved_target(target, APPROVED)  # the audit chain's RR-5 rule accepts it


def test_reordered_parameters_and_graph_casing_are_accepted():
    reordered = link("$skiptoken=X&$select=id,displayname&$filter=userType%20eq%20'Member'&$count=true",
                     path="/beta/Users")
    assert next_target(reordered, approved_target=APPROVED, template=TEMPLATE) == APPROVED + "&$skiptoken=X"


@pytest.mark.parametrize("bad", [
    "https://evil.example/beta/users?$skiptoken=X",
    "http://graph.microsoft.com/beta/users?$skiptoken=X",
    "https://graph.microsoft.com:444/beta/users?$skiptoken=X",
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=X", path="/v1.0/users"),
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=X", path="/beta/groups"),
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname,mail&$skiptoken=X"),  # widened
    link("$count=true&$select=id,displayname&$skiptoken=X"),                                          # filter dropped
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname"),                      # no token
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken="),          # empty token
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=a&$skiptoken=b"),
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=X&$expand=manager"),
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=%FF"),
    link("$count=true&$filter=userType%20eq%20'Member'&$select=id,displayname&$skiptoken=a%20b"),
    None, 42, GOOD + "x" * 9000,
])
def test_any_other_next_link_stops_paging(bad):
    assert next_target(bad, approved_target=APPROVED, template=TEMPLATE) is None


def test_the_body_carries_only_the_facade_handle():
    body = json.dumps({"value": [{"id": "1"}], "@odata.nextLink": GOOD}).encode()
    rewritten = json.loads(rewrite_next_link(body, approved_target=APPROVED, handle="clw_abc"))
    assert rewritten == {"value": [{"id": "1"}], "@odata.nextLink": f"{G}/beta/users?$skiptoken=clw_abc"}
    assert "@odata.nextLink" not in json.loads(rewrite_next_link(body, approved_target=APPROVED, handle=None))


def _continuation(run_id: str = "run-1", expires: datetime = NOW + timedelta(minutes=5)) -> Continuation:
    return Continuation(run_id=run_id, approved_target=APPROVED, upstream_target=APPROVED + "&$skiptoken=X",
                        template=TEMPLATE, entry_id="e", headers=(), expires_at=expires)


def test_a_handle_is_single_use_and_bound_to_its_run():
    handles = PageHandles()
    handle = handles.issue(_continuation())
    assert handle.startswith("clw_") and len(handle) > 30
    assert handles.take(handle, run_id="run-2", now=NOW) is None      # another run's capability
    assert handles.take(handle, run_id="run-1", now=NOW) is not None  # ... does not consume it
    assert handles.take(handle, run_id="run-1", now=NOW) is None      # used once only


@pytest.mark.parametrize("handle", ["clw_unknown", "abc", None, "", "CLW_x"])
def test_unknown_handles_are_refused(handle):
    assert PageHandles().take(handle, run_id="run-1", now=NOW) is None


def test_a_handle_expires_with_the_run():
    handles = PageHandles()
    handle = handles.issue(_continuation(expires=NOW))
    assert handles.take(handle, run_id="run-1", now=NOW) is None


def test_ending_a_run_drops_its_handles():
    handles = PageHandles()
    handle = handles.issue(_continuation())
    handles.drop_run("run-1")
    assert handles.take(handle, run_id="run-1", now=NOW) is None
