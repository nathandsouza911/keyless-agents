"""Pagination (Task 11; threat model T15, Review Focus 3).

A nextLink is accepted only on the fixed origin, version and path of the
original request, with the original query parameters unchanged plus one
$skiptoken; the broker then sends its own canonical form of it. Anything
else is invalid_next_link and nothing is sent. The real shape of Graph's
nextLink is unverified (A-14)."""

from __future__ import annotations

import ast
import dataclasses
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from clw.audit.events import MAX_REQUEST_TARGET_BYTES, target_matches_template
from clw.broker import operations
from clw.broker.credentials import ValidatedToken
from clw.broker.operations import build_request
from clw.broker.pagination import validate_next_link
from clw.broker.transport import GRAPH_ORIGIN, GraphError, Transport, new_graph_client

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
SECRET = "eyJhbGciOiJub25lIn0.PAGINATION-SECRET-9b2.sig"
TOKEN = ValidatedToken(access_token=SECRET, expires_at=NOW + timedelta(hours=1), permissions=frozenset())
REQUEST = build_request(operations.get("users.list_with_sign_in_activity"), {"select": ["signInActivity", "id"], "top": 50})
TARGET = "/v1.0/users?$select=id,signInActivity&$top=50"
BASE = GRAPH_ORIGIN + "/v1.0/users"
SKIP = "RFNwdAIAAQAAAB8xMjM0NTY3ODkw"


def _invalid(link, original=REQUEST):
    with pytest.raises(GraphError) as info:
        validate_next_link(link, original=original)
    assert info.value.category == "invalid_next_link" and info.value.__context__ is None


# --- validate_next_link: accepted -----------------------------------------------------


def test_next_link_on_the_same_request_returns_the_canonical_target():
    link = f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken={SKIP}"
    assert validate_next_link(link, original=REQUEST) == f"{TARGET}&$skiptoken={SKIP}"


def test_nextlink_reordered_query_allowed():
    link = f"{BASE}?$skiptoken={SKIP}&$top=50&$select=id,signInActivity"
    assert validate_next_link(link, original=REQUEST) == f"{TARGET}&$skiptoken={SKIP}"


@pytest.mark.parametrize("link,token", [
    (f"{BASE}?%24select=id%2CsignInActivity&%24top=50&%24skiptoken={SKIP}", SKIP),   # percent-encoded names and values
    (f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=ab%2B%2Fc%3D%3D", "ab%2B%2Fc%3D%3D"),
    (f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=ab+/c==", "ab%2B%2Fc%3D%3D"),   # '+' is a plus, not a space
    (f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=a!b'c(d)*e:f@g", "a%21b%27c%28d%29%2Ae%3Af%40g"),
])
def test_skiptoken_encoding_variants_are_canonicalized(link, token):
    target = validate_next_link(link, original=REQUEST)
    assert target == f"{TARGET}&$skiptoken={token}"
    assert target_matches_template(target, REQUEST.path_template)


def test_request_without_query_gets_skiptoken_only():
    plain = build_request(operations.get("users.list_with_sign_in_activity"), {"select": ["id"]})
    assert validate_next_link(f"{BASE}?$select=id&$skiptoken=x", original=plain) == "/v1.0/users?$select=id&$skiptoken=x"


# --- validate_next_link: refused ----------------------------------------------------------


@pytest.mark.parametrize("link", [
    f"https://evil.example/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://graph.microsoft.com.evil.example/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://graph.microsoft.com@evil.example/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://user@graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://graph.microsoft.com:443/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://graph.microsoft.com:8443/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"https://GRAPH.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"http://graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"HTTPS://graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"//graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/beta/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/groups?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/Users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/V1.0/users?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/users/?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/users/delta?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/users/../groups?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/users%2F..%2Fgroups?$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"{GRAPH_ORIGIN}/v1.0/users",
    f"{GRAPH_ORIGIN}/v1.0/users?",
])
def test_wrong_origin_scheme_version_or_path_is_refused(link):
    _invalid(link)


@pytest.mark.parametrize("query", [
    "$select=id,signInActivity&$top=50",                                   # no skiptoken
    f"$skiptoken={SKIP}",                                                   # original params dropped
    f"$select=id&$top=50&$skiptoken={SKIP}",                                # $select changed
    f"$select=id,signInActivity,mail&$top=50&$skiptoken={SKIP}",
    f"$select=*&$top=50&$skiptoken={SKIP}",
    f"$select=signInActivity,id&$top=50&$skiptoken={SKIP}",                 # value reordered: not the approved value
    f"$select=id,signInActivity&$top=999&$skiptoken={SKIP}",                # $top changed
    f"$select=id,signInActivity&$top=50&$expand=manager&$skiptoken={SKIP}",
    f"$select=id,signInActivity&$top=50&$filter=x&$skiptoken={SKIP}",
    f"$select=id,signInActivity&$top=50&$skiptoken={SKIP}&$skiptoken=x",   # duplicate
    f"$select=id,signInActivity&$select=id,signInActivity&$top=50&$skiptoken={SKIP}",
    f"$select=id,signInActivity&$top=50&$skipToken={SKIP}",                 # name case (A-14)
    f"$select=id,signInActivity&$top=50&$skiptoken=",
    f"$select=id,signInActivity&$top=50&$skiptoken",
    f"$select=id,signInActivity&$top=50&&$skiptoken={SKIP}",
    f"$select=id,signInActivity&$top=50;$skiptoken={SKIP}",
    f"$select=id,signInActivity&$top=50&$skiptoken={SKIP}#frag",
    f"$select=id,signInActivity&$top=50&$skiptoken=%ZZ",
    f"$select=id,signInActivity&$top=50&$skiptoken=%FF%FE",
    f"$select=id,signInActivity&$top=50&$skiptoken=a%20b",                   # decoded space
    f"$select=id,signInActivity&$top=50&$skiptoken=a%0Ab",
    f"$select=id,signInActivity&$top=50&$skiptoken=a b",
    f"$select=id,signInActivity&$top=50&$skiptoken=a\\b",
    f"$select=id,signInActivity&$top=50&$skiptoken=é",
    f"$select=id,signInActivity&$top=50&$skiptoken=" + "A" * 4097,
    f"$select=id,signInActivity&$top=50&$skiptoken=x&x=1",
    f"$select=id,signInActivity&$top=50&$skiptoken=x?y=1",
])
def test_query_must_be_the_original_plus_one_skiptoken(query):
    _invalid(f"{BASE}?{query}")


@pytest.mark.parametrize("link", [None, 1, b"https://graph.microsoft.com/v1.0/users", "", "x" * 9000,
                                  f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=a\tb",
                                  f" {BASE}?$select=id,signInActivity&$top=50&$skiptoken=x"])
def test_non_string_empty_long_or_spaced_links_are_refused(link):
    _invalid(link)


def test_link_over_the_length_cap_is_refused_even_if_it_decodes_short():
    # "%41" decodes to "A": 2800 of them are 8400 characters raw, 2800 decoded.
    _invalid(f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=" + "%41" * 2800)
    assert validate_next_link(f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=" + "%41" * 2600, original=REQUEST)


def test_original_without_query_gets_question_mark():
    # No Phase 1 operation has an empty query; the rule still holds generally.
    bare = dataclasses.replace(REQUEST, query=())
    assert validate_next_link(f"{BASE}?$skiptoken=x", original=bare) == "/v1.0/users?$skiptoken=x"


def test_canonical_target_over_the_audit_limit_is_refused():
    # Each '!' becomes %21, tripling it: 1500 characters exceed 4096 bytes encoded.
    _invalid(f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=" + "!" * 1500)
    assert MAX_REQUEST_TARGET_BYTES == 4096


def test_original_must_be_a_built_request():
    _invalid(f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=x", original=None)


# --- pagination through the transport --------------------------------------------------------


class Hooks:
    def __init__(self):
        self.events = []

    async def before(self, a):
        self.events.append(("before", a))

    async def after(self, a):
        self.events.append(("after", a))


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _serve(mock, pages):
    seen = []

    def answer(request):
        seen.append((request.url.host, request.url.raw_path.decode(), request.headers.get("authorization")))
        target = request.url.raw_path.decode()
        assert request.url.host == "graph.microsoft.com" and target in pages, target
        return pages[target]

    mock.route().mock(side_effect=answer)
    return seen


def _page(ids, next_link=None):
    body = {"value": [{"id": i} for i in ids]}
    if next_link:
        body["@odata.nextLink"] = next_link
    return httpx.Response(200, json=body)


async def _execute(hooks, **kwargs):
    t = Transport(new_graph_client(), clock=lambda: NOW, **kwargs)
    return await t.execute(REQUEST, TOKEN, deadline=NOW + timedelta(minutes=5),
                           before_attempt=hooks.before, after_attempt=hooks.after)


async def test_three_pages_one_attempt_each_auth_only_to_graph(mock):
    hooks = Hooks()
    seen = _serve(mock, {
        TARGET: _page(["1", "2"], f"{BASE}?$skiptoken=p2&$select=id,signInActivity&$top=50"),
        f"{TARGET}&$skiptoken=p2": _page(["3"], f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=p3"),
        f"{TARGET}&$skiptoken=p3": _page(["4"]),
    })
    assert await _execute(hooks) == [{"id": i} for i in "1234"]
    assert [t for _, t, _ in seen] == [TARGET, f"{TARGET}&$skiptoken=p2", f"{TARGET}&$skiptoken=p3"]
    assert all(host == "graph.microsoft.com" and auth == f"Bearer {SECRET}" for host, _, auth in seen)
    befores = [a for k, a in hooks.events if k == "before"]
    assert [a.attempt for a in befores] == [1, 2, 3]
    assert [a.request_target for a in befores] == [t for _, t, _ in seen]
    assert all(target_matches_template(a.request_target, REQUEST.path_template) for a in befores)
    assert [a.item_count for k, a in hooks.events if k == "after"] == [2, 1, 1]


@pytest.mark.parametrize("bad_link", [
    "https://evil.example/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken=x",
    f"{GRAPH_ORIGIN}/beta/users?$select=id,signInActivity&$top=50&$skiptoken=x",
    f"{GRAPH_ORIGIN}/v1.0/groups?$select=id,signInActivity&$top=50&$skiptoken=x",
    f"{GRAPH_ORIGIN}/v1.0/Users?$select=id,signInActivity&$top=50&$skiptoken=x",
    "http://graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken=x",
    f"{BASE}?$select=id,signInActivity,mail&$top=50&$skiptoken=x",
])
async def test_invalid_next_link_sends_nothing_and_returns_no_data(mock, bad_link):
    hooks = Hooks()
    seen = _serve(mock, {TARGET: _page(["1"], bad_link)})
    with pytest.raises(GraphError) as info:
        await _execute(hooks)
    assert info.value.category == "invalid_next_link"
    assert [t for _, t, _ in seen] == [TARGET]          # nothing sent after the first page
    assert len([k for k, _ in hooks.events if k == "before"]) == 1


async def test_page_cap(mock):
    hooks = Hooks()
    pages = {TARGET: _page(["0"], f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=p1")}
    for i in range(1, 5):
        pages[f"{TARGET}&$skiptoken=p{i}"] = _page([str(i)], f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=p{i + 1}")
    seen = _serve(mock, pages)
    with pytest.raises(GraphError) as info:
        await _execute(hooks, max_pages=3)
    assert info.value.category == "page_cap" and len(seen) == 3


async def test_last_page_within_the_cap_is_returned(mock):
    hooks = Hooks()
    _serve(mock, {
        TARGET: _page(["1"], f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=p2"),
        f"{TARGET}&$skiptoken=p2": _page(["2"]),
    })
    assert len(await _execute(hooks, max_pages=2)) == 2


async def test_failed_later_page_returns_no_data(mock):
    hooks = Hooks()
    _serve(mock, {
        TARGET: _page(["1"], f"{BASE}?$select=id,signInActivity&$top=50&$skiptoken=p2"),
        f"{TARGET}&$skiptoken=p2": httpx.Response(403),
    })
    with pytest.raises(GraphError) as info:
        await _execute(hooks)
    assert info.value.category == "forbidden"


# --- boundaries ----------------------------------------------------------------------------------

SRC = Path(__file__).resolve().parents[2] / "src" / "clw"


def _importers(target_modules: set[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in SRC.rglob("*.py"):
        mod = "clw." + ".".join(p for p in path.relative_to(SRC).with_suffix("").parts if p != "__init__")
        names = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
                names.update(f"{node.module}.{a.name}" for a in node.names)
        hits = {t for t in target_modules for n in names if n == t or n.startswith(t + ".")}
        if hits:
            found[mod] = hits
    return found


def test_only_broker_modules_import_the_transport_or_credentials():
    importers = _importers({"clw.broker.transport", "clw.broker.pagination", "clw.broker.credentials"})
    # SD-051: the demo broker factory wires the real transport and provider, as clw.broker.app does.
    assert all(mod.startswith("clw.broker.") or mod == "clw.demo.broker" for mod in importers), importers


def test_httpx_is_imported_only_by_sign_in_and_the_transport():
    importers = set(_importers({"httpx"}))
    # The facade proxy (SD-041) and the MCP gateway (SD-052) use httpx only to call the broker;
    # neither names Graph (test_only_transport_names_graph_host, test_the_gateway_never_names_the_graph_host).
    assert importers <= {"clw.auth.oidc", "clw.auth.signin", "clw.broker.transport", "clw.facade_proxy.app",
                         "clw.mcp_gateway.app",
                         "clw.demo.broker"}, importers  # SD-051: a Graph client trusting only the demo CA
    assert "clw.broker.transport" in importers


def test_pagination_and_policy_do_not_import_credentials_or_msal():
    importers = _importers({"clw.broker.credentials", "msal"})
    assert "clw.broker.pagination" not in importers and "clw.broker.policy" not in importers
