"""Canonical form of facade requests (SD-041): every refusal, D1 stripping,
normalization, and rendered targets inside the audit chain's rules."""

from __future__ import annotations

import pytest

from clw.audit.events import target_matches_template
from clw.broker.facade.canonical import FacadeRequest, Refused, canonicalize

GUID = "00000000-0000-0000-0000-000000000001"


def ok(target: str, *, method: str = "GET", headers: dict | None = None, body: int = 0) -> FacadeRequest:
    result = canonicalize(method, target, headers or {}, body)
    assert isinstance(result, FacadeRequest), result
    return result


def refused(target: str, *, method: str = "GET", body: int = 0) -> str:
    result = canonicalize(method, target, {}, body)
    assert isinstance(result, Refused), result
    return result.reason


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS", "get", "", None])
def test_only_get_is_accepted(method):
    assert refused("/v1.0/users", method=method) == "method_not_allowed"


def test_a_get_with_a_body_is_refused():
    assert refused("/v1.0/users", body=1) == "body_not_allowed"


@pytest.mark.parametrize("target", [
    "", "v1.0/users", "https://graph.microsoft.com/v1.0/users", "//v1.0/users", "/v1.0//users", "/v1.0/users/",
    "/v1.0/./users", "/v1.0/users/..", "/v1.0/users/%2e%2e", "/v1.0/users%2Fabc", "/v1.0/users%2fabc",
    "/v1.0/users%5Cx", "/v1.0/users\\x", "/v1.0/users#frag", "/v1.0/us ers", "/v1.0/users\t", "/v1.0/us%25ers",
    "/v1.0/users%252e%252e", "/v1.0/us%FFers", "/v1.0/ü", "/" + "a" * 4096,
])
def test_malformed_targets_are_refused(target):
    assert refused(target) in ("malformed_target", "version_not_allowed")


@pytest.mark.parametrize("target", ["/v2.0/users", "/users", "/v1/users", "/Beta2/users", "/v1.0"])
def test_only_v1_and_beta_are_versions(target):
    assert refused(target) in ("version_not_allowed", "malformed_target")


@pytest.mark.parametrize("target, reason", [
    ("/v1.0/$batch", "batch_not_allowed"), ("/beta/$BATCH", "batch_not_allowed"),
    ("/v1.0/me", "alias_not_allowed"), ("/v1.0/ME/messages", "alias_not_allowed"),
    ("/v1.0/users/delta", "function_not_allowed"), ("/v1.0/users/microsoft.graph.delta()", "function_not_allowed"),
    ("/v1.0/reports/getOffice365ActiveUserDetail(period='D7')", "function_not_allowed"),
])
def test_batch_aliases_and_functions_are_refused(target, reason):
    assert refused(target) == reason


def test_version_and_segments_are_case_insensitive():
    request = ok(f"/V1.0/Users/{GUID.upper()}/MemberOf")
    assert (request.version, request.segments) == ("v1.0", ("users", GUID, "memberof"))


def test_one_decoding_only():
    assert ok("/v1.0/%75sers").segments == ("users",)


@pytest.mark.parametrize("query, reason", [
    ("$sELect=id&$select=displayName", "duplicate_query_option"),
    ("$expandx=manager", "unknown_query_option"),
    ("$levels=2", "unknown_query_option"),
    ("$select=%FF", "malformed_query"),
    ("$filter=a%0Ab", "malformed_query"),
])
def test_query_refusals(query, reason):
    assert refused(f"/v1.0/users?{query}") == reason


@pytest.mark.parametrize("query, name", [
    # The demo script's real typo: $`top in a PowerShell string sends "$<TAB>op".
    ("$count=true&$%09op=999&$select=id", "$\\x09op"),
    ("$select=id&api-version=1", "api-version"),
    ("$select=id&x=%22secret%22", "x"),
])
def test_unknown_parameters_are_refused_by_name_never_dropped_d1(query, name):
    result = canonicalize("GET", f"/beta/users?{query}", {}, 0)
    assert isinstance(result, Refused) and (result.reason, result.parameter) == ("unknown_query_parameter", name)
    assert "secret" not in repr(result) and "999" not in repr(result)  # the value is never carried


def test_a_refused_odata_word_is_named_too():
    result = canonicalize("GET", "/beta/users?$levels=2", {}, 0)
    assert (result.reason, result.parameter) == ("unknown_query_option", "$levels")


def test_select_is_trimmed_lowercased_and_deduplicated():
    request = ok("/beta/users?$select=id,%20displayName,%20usertype,%20signInActivity,%20ID")
    assert request.option("$select") == "id,displayname,usertype,signinactivity"


def test_option_names_are_case_insensitive_and_sorted():
    request = ok("/v1.0/users?$TOP=5&$Select=id&$COUNT=TRUE")
    assert request.options == (("$count", "true"), ("$select", "id"), ("$top", "5"))


def test_only_consistency_level_eventual_is_forwarded():
    assert ok("/v1.0/users", headers={"ConsistencyLevel": "Eventual", "X-Evil": "1"}).headers == (
        ("ConsistencyLevel", "eventual"),)
    assert ok("/v1.0/users", headers={"consistencylevel": "session"}).headers == ()


@pytest.mark.parametrize("target, template", [
    ("/beta/users?$count=true&$filter=(assignedLicenses/$count%20ne%200%20and%20userType%20eq%20'Member')"
     "&$select=id,%20displayName", "/users"),
    (f"/v1.0/users/{GUID}?$select=id", "/users/{user_id}"),
    ("/v1.0/users?$search=%22displayName:a%26b%22&$top=10", "/users"),
])
def test_rendered_targets_satisfy_the_audit_target_rule(target, template):
    rendered = ok(target).target()
    assert target_matches_template(rendered, template, versions=("/v1.0", "/beta")), rendered
    assert ok(rendered).target() == rendered  # canonical form is a fixed point


def test_rendering_encodes_separators_inside_values():
    rendered = ok("/v1.0/users?$filter=a%26b%3Dc%2Bd").target()
    assert rendered == "/v1.0/users?$filter=a%26b%3Dc%2Bd"


def test_rendering_can_leave_out_an_option():
    assert ok("/v1.0/users?$skiptoken=clw_x&$top=5").target(without=frozenset({"$skiptoken"})) == "/v1.0/users?$top=5"
