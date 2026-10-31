"""Keyed hashing of $filter/$search values in the audit form of a target (SD-042)."""

from __future__ import annotations

from clw.audit.events import continues_approved_target, target_matches_template
from clw.broker.facade.hashing import ValueKey, audit_target, value_digest

KEY = ValueKey("0a1b2c3d", b"k" * 32)
OTHER = ValueKey("ffffffff", b"o" * 32)
TARGET = "/beta/users?$count=true&$filter=displayName%20eq%20'Ada%20Lovelace'&$select=id&$top=5"


def test_only_filter_and_search_values_are_hashed():
    audited = audit_target(TARGET, KEY)
    assert "Ada" not in audited and "Lovelace" not in audited
    assert audited.startswith("/beta/users?$count=true&$filter=clwhash.0a1b2c3d.")
    assert audited.endswith("&$select=id&$top=5")
    assert audit_target("/v1.0/users?$search=%22displayName:Ada%22&$select=id", KEY).count("clwhash.") == 1


def test_the_digest_is_of_the_decoded_value_and_keyed():
    digest = value_digest(KEY, "$filter", "displayName eq 'Ada Lovelace'")
    assert f"$filter={digest}" in audit_target(TARGET, KEY)
    assert audit_target(TARGET, KEY) == audit_target(TARGET, KEY)
    assert audit_target(TARGET, KEY) != audit_target(TARGET, OTHER)
    assert value_digest(KEY, "$filter", "x") != value_digest(KEY, "$search", "x")


def test_the_audit_form_keeps_rr5_binding_and_the_audit_target_rule():
    approved = audit_target(TARGET, KEY)
    continued = audit_target(TARGET + "&$skiptoken=RFNw", KEY)
    assert continues_approved_target(continued, approved)
    assert target_matches_template(approved, "/users", versions=("/v1.0", "/beta"))


def test_a_target_without_free_text_is_unchanged():
    assert audit_target("/v1.0/users?$select=id&$top=5", KEY) == "/v1.0/users?$select=id&$top=5"
    assert audit_target("/v1.0/users", KEY) == "/v1.0/users"


def test_the_key_never_appears_in_a_repr():
    assert "k" * 32 not in repr(KEY)
