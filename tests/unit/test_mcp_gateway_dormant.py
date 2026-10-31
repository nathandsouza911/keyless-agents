"""The gateway's dormancy rules equal the built-in task's (tasks/dormant_account_investigation/classify.py)."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from clw.mcp_gateway.dormant import REPORTED, classify, summarise
from tasks.dormant_account_investigation.classify import classify as task_classify

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_ago: float | None) -> str | None:
    if days_ago is None:
        return None
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


AGES = [None, 0, 29.5, 30, 30.0001, 89, 90, 91, 400]
ACTIVITY = [None, "missing", {}, "both", "successful_only", "interactive_only"]


def _users():
    for enabled, created, signed, activity in itertools.product((True, False), AGES, AGES, ACTIVITY):
        user = {"id": "u", "accountEnabled": enabled, "createdDateTime": _iso(created)}
        if activity == "both":
            user["signInActivity"] = {"lastSuccessfulSignInDateTime": _iso(signed),
                                      "lastSignInDateTime": _iso(None if signed is None else signed / 2)}
        elif activity == "successful_only":
            user["signInActivity"] = {"lastSuccessfulSignInDateTime": _iso(signed)}
        elif activity == "interactive_only":
            user["signInActivity"] = {"lastSignInDateTime": _iso(signed)}
        elif activity == {}:
            user["signInActivity"] = {}
        elif activity is None:
            user["signInActivity"] = None
        yield user


@pytest.mark.parametrize("days", [30, 90])
def test_the_gateway_classifies_exactly_as_the_task_does(days):
    users = list(_users())
    assert len(users) > 500
    for user in users:
        assert classify(user, now=NOW, days=days) == task_classify(user, now=NOW, inactive_days=days), user


@pytest.mark.parametrize("bad", [
    {"accountEnabled": "true"}, {"accountEnabled": True, "createdDateTime": "2026-01-01"},
    {"accountEnabled": True, "signInActivity": "x"}, "not a user",
])
def test_malformed_users_are_refused_as_the_task_refuses_them(bad):
    with pytest.raises(ValueError):
        classify(bad, now=NOW, days=90)
    with pytest.raises(ValueError):
        task_classify(bad, now=NOW, inactive_days=90)


def test_the_summary_lists_only_reported_properties():
    users = [{"id": "1", "displayName": "D", "userPrincipalName": "d@x.test", "accountEnabled": True,
              "createdDateTime": _iso(400), "userType": "Member", "signInActivity": {"lastSignInDateTime": _iso(200)},
              "mail": "secret@x.test", "otherMails": ["x"], "extra": {"deep": 1}}]
    summary = summarise(users, now=NOW, days=90)
    assert summary["counts"]["dormant"] == 1
    assert set(summary["dormant"][0]) == {*REPORTED, "lastSignIn"}
