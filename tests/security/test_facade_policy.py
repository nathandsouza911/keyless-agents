"""Facade policy and script manifests (SD-041): deny by default, every option
explicit, writes never approvable."""

from __future__ import annotations

import pytest

from clw.audit.events import target_matches_template
from clw.broker.facade.canonical import FacadeRequest, canonicalize
from clw.broker.facade.policy import evaluate, filter_properties
from clw.broker.facade.rules import ManifestRefused, load_script_manifest

GUID = "00000000-0000-0000-0000-000000000001"

# What the demo script (Redmond, Report-LastSuccessfulSignIn.PS1) needs.
DEMO = {
    "schema_version": 1,
    "profile": "directory-read-auditlog-read",
    "entries": [
        {"id": "list-users-signin", "method": "GET", "versions": ["beta"], "path": "/users",
         "select": ["id", "displayName", "userType", "signInActivity"],
         "filter": {"allowed": True, "properties": ["assignedLicenses", "userType"]},
         "top": 999, "count": True, "consistency_level": True},
        {"id": "user-memberof", "method": "GET", "versions": ["v1.0"], "path": "/users/{user_id}/memberOf",
         "select": ["id", "displayName"]},
    ],
}
MANIFEST = load_script_manifest(DEMO)
DEMO_TARGET = ("/beta/users?$count=true&$filter=(assignedLicenses/$count%20ne%200%20and%20userType%20eq%20'Member')"
               "&$select=id,%20displayName,%20usertype,%20signInActivity")
# The script as published also sends a garbled "$<TAB>op=999" (its $`top typo).
PUBLISHED_TARGET = DEMO_TARGET + "&$%09op=999"


def request(target: str, headers: dict | None = None) -> FacadeRequest:
    result = canonicalize("GET", target, headers or {}, 0)
    assert isinstance(result, FacadeRequest), result
    return result


def decide(target: str, headers: dict | None = None):
    return evaluate(MANIFEST, request(target, headers))


def test_the_demo_scripts_request_is_allowed():
    decision = decide(DEMO_TARGET, {"ConsistencyLevel": "eventual"})
    assert decision.allowed and decision.entry.id == "list-users-signin"
    assert decision.path_template == "/users"
    assert target_matches_template(decision.target, decision.path_template, versions=("/v1.0", "/beta"))


def test_the_published_script_with_its_typo_is_refused_naming_the_parameter():
    # D1 (owner decision 2026-10-25): refuse, never strip silently.
    from clw.broker.facade.canonical import Refused

    result = canonicalize("GET", PUBLISHED_TARGET, {"ConsistencyLevel": "eventual"}, 0)
    assert isinstance(result, Refused) and (result.reason, result.parameter) == ("unknown_query_parameter", "$\\x09op")


@pytest.mark.parametrize("target, reason", [
    ("/v1.0/users?$select=id", "not_in_manifest"),                 # v1.0 not allowed for this entry
    ("/beta/groups?$select=id", "not_in_manifest"),
    ("/beta/users", "select_required"),
    ("/beta/users?$select=id,mail", "select_not_allowed"),
    ("/beta/users?$select=id&$filter=department%20eq%20'x'", "filter_property_not_allowed"),
    ("/beta/users?$select=id&$top=1000", "top_out_of_bounds"),
    ("/beta/users?$select=id&$top=0", "top_out_of_bounds"),
    ("/beta/users?$select=id&$expand=manager", "expand_not_allowed"),
    ("/beta/users?$select=id&$skip=5", "option_not_allowed"),
    ("/beta/users?$select=id&$orderby=displayName", "orderby_not_allowed"),
    ("/beta/users?$select=id&$search=%22a%22", "search_not_allowed"),
    ("/beta/users?$select=id&$skiptoken=abc", "continuation_not_expected"),
    ("/beta/users?$select=id&$count=maybe", "count_not_allowed"),
    (f"/v1.0/users/{GUID}/memberOf?$select=id&$top=5", "top_not_allowed"),
    ("/v1.0/users/alice@contoso.test/memberOf?$select=id", "not_in_manifest"),  # placeholders take GUIDs only
    (f"/v1.0/users/{GUID}/memberOf/extra?$select=id", "not_in_manifest"),
])
def test_denials(target, reason):
    decision = decide(target)
    assert (decision.allowed, decision.reason) == (False, reason)


def test_consistency_level_needs_the_entry_to_allow_it():
    assert decide(f"/v1.0/users/{GUID}/memberOf?$select=id", {"ConsistencyLevel": "eventual"}).reason == \
        "consistency_level_not_allowed"


def test_a_placeholder_entry_allows_a_guid_and_records_the_lowercased_template():
    decision = decide(f"/V1.0/Users/{GUID}/MemberOf?$select=ID")
    assert decision.allowed and decision.path_template == "/users/{user_id}/memberof"
    assert decision.target == f"/v1.0/users/{GUID}/memberof?$select=id"


@pytest.mark.parametrize("expression, names", [
    ("(assignedLicenses/$count ne 0 and userType eq 'Member')", {"assignedlicenses", "usertype"}),
    ("startswith(displayName,'a') and accountEnabled eq true", {"displayname", "accountenabled"}),
    ("signInActivity/lastSignInDateTime le 2026-01-01T00:00:00Z", {"signinactivity"}),
    ("assignedLicenses/any(x:x/skuId eq 00000000-0000-0000-0000-000000000001)", {"assignedlicenses"}),
    ("userType eq 'it''s'", {"usertype"}),
])
def test_filter_property_extraction(expression, names):
    assert filter_properties(expression) == names


def test_an_unterminated_filter_string_cannot_be_read():
    assert filter_properties("userType eq 'Member") is None


def test_a_path_call_other_than_a_lambda_cannot_be_read():
    assert filter_properties("manager/microsoft_graph_user(x) eq 1") is None


def test_a_filter_the_reader_cannot_read_is_denied():
    assert decide("/beta/users?$select=id&$filter=userType%20eq%20'Member").reason == "filter_property_not_allowed"


# --------------------------------------------------------------- manifests


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_a_write_entry_can_never_be_approved(method):
    document = {**DEMO, "entries": [{**DEMO["entries"][0], "method": method}]}
    with pytest.raises(ManifestRefused, match="only GET"):
        load_script_manifest(document)


@pytest.mark.parametrize("change", [
    {"expand": True}, {"path": "/$batch"}, {"path": "users"}, {"path": "/users/{ID}"}, {"versions": []},
    {"versions": ["v2.0"]}, {"select": ["bad name"]}, {"top": 0}, {"top": 5000}, {"extra": 1},
    {"select": [], "select_required": True},
])
def test_malformed_entries_are_refused(change):
    document = {**DEMO, "entries": [{**DEMO["entries"][0], **change}]}
    with pytest.raises(ManifestRefused):
        load_script_manifest(document)


def test_duplicate_entry_ids_are_refused():
    with pytest.raises(ManifestRefused, match="unique"):
        load_script_manifest({**DEMO, "entries": [DEMO["entries"][0], DEMO["entries"][0]]})


def test_the_manifest_digest_is_stable_and_changes_with_any_rule():
    assert load_script_manifest(DEMO).sha256 == MANIFEST.sha256
    widened = {**DEMO, "entries": [{**DEMO["entries"][0], "top": 500}, DEMO["entries"][1]]}
    assert load_script_manifest(widened).sha256 != MANIFEST.sha256


def test_top_is_bounded_by_the_entrys_own_maximum():
    narrow = load_script_manifest({**DEMO, "entries": [{**DEMO["entries"][0], "top": 100}]})
    assert evaluate(narrow, request("/beta/users?$select=id&$top=100")).allowed
    assert evaluate(narrow, request("/beta/users?$select=id&$top=500")).reason == "top_out_of_bounds"
