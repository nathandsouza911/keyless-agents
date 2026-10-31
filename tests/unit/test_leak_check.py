"""The identity-leak scanner used by the dev-tenant tests finds a planted
identity and never repeats it in its report (tests/integration/leaks.py)."""

from __future__ import annotations

import logging

from tests.integration.leaks import describe, find_leaks, identities

REAL = {"id": "7B0D2E9A-1111-4222-8333-944455556666", "userPrincipalName": "Ada.Lovelace@contoso.test",
        "displayName": "Ada Lovelace"}
TEST = {"id": "aaaaaaaa-0000-4000-8000-000000000001", "userPrincipalName": "clw-test-active@contoso.test",
        "displayName": "clw-test-active"}


def test_only_non_test_users_are_looked_for():
    needles = identities([REAL, TEST], exclude_ids={TEST["id"]})
    assert needles == {REAL["id"].lower(), "ada.lovelace@contoso.test", "ada lovelace"}


def test_short_one_word_names_are_not_used():
    assert identities([{"id": "x", "displayName": "Admin"}], exclude_ids=set()) == {"x"}


def test_a_planted_identity_in_a_log_record_is_found_and_not_repeated(caplog):
    with caplog.at_level(logging.INFO):
        logging.getLogger("clw.test").info("processed user %s", REAL["userPrincipalName"])
    places = {"logs": "\n".join(r.getMessage() for r in caplog.records), "stdout": "nothing here"}
    leaks = find_leaks(identities([REAL], exclude_ids=set()), places)
    assert leaks == {"logs": 1}
    message = describe(leaks)
    assert "logs (1)" in message
    assert all(value.lower() not in message.lower() for value in REAL.values())


def test_matching_ignores_case():
    assert find_leaks({"ada lovelace"}, {"audit": "ADA LOVELACE"}) == {"audit": 1}


def test_nothing_to_look_for_finds_nothing():
    assert find_leaks(set(), {"logs": "anything"}) == {}


def test_placeholder_names_are_not_used_but_their_ids_are():
    placeholder = {"id": "y", "userPrincipalName": "testuser@contoso.test", "displayName": "Test User"}
    assert identities([placeholder], exclude_ids=set()) == {"y", "testuser@contoso.test"}


def test_a_name_with_one_real_word_is_still_used():
    assert "ada test" in identities([{"id": "z", "displayName": "Ada Test"}], exclude_ids=set())
