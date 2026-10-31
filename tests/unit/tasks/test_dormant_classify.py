"""Dormant-account classification (Task 13; Review Focus 1; A-03, A-17, A-25).

Pure function, no network. The user shapes follow the signInActivity shape
assumed in A-03 and A-17; nothing here shows real Microsoft Graph output.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from typing import get_args

import pytest

from tasks.dormant_account_investigation.classify import Classification, classify, last_sign_in

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
DAYS = 90
WINDOW = timedelta(days=DAYS)
OLD = NOW - timedelta(days=400)
MISSING = object()


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def user(*, enabled=True, created=OLD, success=MISSING, interactive=MISSING, activity=MISSING, **extra) -> dict:
    record = {"id": "u-1", "accountEnabled": enabled, **extra}
    if created is not MISSING:
        record["createdDateTime"] = iso(created) if isinstance(created, datetime) else created
    if activity is MISSING:
        activity = {}
        for key, value in (("lastSuccessfulSignInDateTime", success), ("lastSignInDateTime", interactive)):
            if value is not MISSING:
                activity[key] = iso(value) if isinstance(value, datetime) else value
    if activity is not MISSING:
        record["signInActivity"] = activity
    return record


def judge(record: dict, *, now: datetime = NOW, days: int = DAYS) -> str:
    return classify(record, now=now, inactive_days=days)


# ------------------------------------------------------------ Review Focus 1


@pytest.mark.parametrize("record", [
    user(activity=None),                                   # signInActivity: null (A-17)
    {k: v for k, v in user().items() if k != "signInActivity"},  # property omitted
    user(activity={}),
    user(success=None, interactive=None),
    user(success=None),
    user(interactive=None),
], ids=["null", "omitted", "empty", "both-null", "success-null", "interactive-null"])
def test_classify_null_sign_in_activity(record):
    assert judge(record) == "never_signed_in"


@pytest.mark.parametrize("age", [timedelta(0), timedelta(days=10), WINDOW - timedelta(microseconds=1)])
@pytest.mark.parametrize("activity", [None, {}], ids=["null", "empty"])
def test_classify_recent_account_not_dormant(age, activity):
    assert judge(user(created=NOW - age, activity=activity)) == "too_new_to_judge"


def test_recent_account_with_old_sign_in_is_too_new_not_dormant():
    # Inconsistent data (a sign-in before creation) is not called dormant either.
    assert judge(user(created=NOW - timedelta(days=5), success=NOW - timedelta(days=200))) == "too_new_to_judge"


def test_recent_account_that_signed_in_is_active():
    assert judge(user(created=NOW - timedelta(days=5), success=NOW - timedelta(days=1))) == "active"


def test_account_exactly_window_old_is_judged():
    assert judge(user(created=NOW - WINDOW, activity=None)) == "never_signed_in"
    assert judge(user(created=NOW - WINDOW, success=NOW - WINDOW)) == "dormant"


@pytest.mark.parametrize("created", [MISSING, None], ids=["omitted", "null"])
def test_unknown_creation_date_is_judged_on_sign_ins(created):
    # A-25: createdDateTime may be null for old objects; the age is then unknown, not "new".
    assert judge(user(created=created, activity=None)) == "never_signed_in"
    assert judge(user(created=created, success=NOW - timedelta(days=200))) == "dormant"
    assert judge(user(created=created, success=NOW - timedelta(days=1))) == "active"


# ------------------------------------------------------------ disabled accounts


@pytest.mark.parametrize("record", [
    user(enabled=False, success=NOW - timedelta(days=400)),
    user(enabled=False, success=NOW - timedelta(days=1)),
    user(enabled=False, activity=None),
    user(enabled=False, created=NOW - timedelta(days=1), activity=None),
], ids=["old-sign-in", "recent-sign-in", "never", "new"])
def test_disabled_accounts_reported_separately(record):
    assert judge(record) == "disabled"


# ------------------------------------------------------------ the boundary


def test_exactly_inactive_days_ago_is_dormant():
    assert judge(user(success=NOW - WINDOW)) == "dormant"
    assert judge(user(interactive=NOW - WINDOW)) == "dormant"


def test_just_inside_the_window_is_active():
    assert judge(user(success=NOW - WINDOW + timedelta(microseconds=1))) == "active"


@pytest.mark.parametrize("days", [1, 30, 365])
def test_threshold_is_the_one_given(days):
    window = timedelta(days=days)
    assert judge(user(success=NOW - window), days=days) == "dormant"
    assert judge(user(success=NOW - window + timedelta(seconds=1)), days=days) == "active"


# ------------------------------------------------------------ which timestamp (A-03)


def test_successful_sign_in_preferred_over_last_sign_in():
    assert judge(user(success=NOW - timedelta(days=200), interactive=NOW - timedelta(days=1))) == "dormant"
    assert judge(user(success=NOW - timedelta(days=1), interactive=NOW - timedelta(days=200))) == "active"


@pytest.mark.parametrize("success", [MISSING, None], ids=["omitted", "null"])
def test_last_sign_in_used_when_no_successful_sign_in(success):
    assert judge(user(success=success, interactive=NOW - timedelta(days=1))) == "active"
    assert judge(user(success=success, interactive=NOW - timedelta(days=200))) == "dormant"


def test_non_interactive_sign_in_is_not_used():
    # The plan names two timestamps only (A-03); lastNonInteractiveSignInDateTime is ignored.
    record = user(activity={"lastNonInteractiveSignInDateTime": iso(NOW - timedelta(days=1))})
    assert judge(record) == "never_signed_in"


def test_last_sign_in_helper():
    assert last_sign_in(user(activity=None)) is None
    assert last_sign_in(user(success=NOW - timedelta(days=3))) == NOW - timedelta(days=3)
    assert last_sign_in(user(success=None, interactive=NOW - timedelta(days=4))) == NOW - timedelta(days=4)


# ------------------------------------------------------------ timestamp forms (A-25)


@pytest.mark.parametrize("text, expected", [
    ("2026-07-03T12:00:00Z", "dormant"),            # 90 days before NOW
    ("2026-07-03T12:00:00.0000019Z", "active"),      # seven fractional digits (cut to microseconds)
    ("2026-07-03T12:00:00.0000009Z", "dormant"),     # under a microsecond: cut to the boundary
    ("2026-07-03T11:59:59.999Z", "dormant"),
    ("2026-07-03T17:30:00+05:30", "dormant"),        # == 12:00Z
    ("2026-07-03T17:30:01+05:30", "active"),
    ("2026-07-03T07:00:00-05:00", "dormant"),
    ("0001-01-01T00:00:00Z", "dormant"),
    ("2027-01-01T00:00:00Z", "active"),             # in the future (clock skew)
])
def test_timestamp_forms(text, expected):
    assert judge(user(success=text)) == expected


def test_future_creation_is_too_new():
    assert judge(user(created=NOW + timedelta(days=1), activity=None)) == "too_new_to_judge"


@pytest.mark.parametrize("bad", [
    "", "2026-07-03", "2026-07-03T12:00:00", "20260703T120000Z", "2026-07-03 12:00:00Z",
    "2026-07-03T12:00Z", "2026-13-03T12:00:00Z", "2026-07-03T12:00:00.12345678Z", "2026-07-03T12:00:00Z\n",
    "٢٠٢٦-07-03T12:00:00Z", "2026-07-03T12:00:00+0530", 1700000000, 1.5, True, [], {},
])
@pytest.mark.parametrize("field", ["success", "interactive", "created"])
def test_malformed_timestamps_raise(bad, field):
    with pytest.raises(ValueError):
        judge(user(**{field: bad}))


@pytest.mark.parametrize("field", ["success", "interactive", "created"])
def test_malformed_timestamps_raise_for_disabled_accounts_too(field):
    # No class hides a malformed value: everything is parsed before deciding.
    with pytest.raises(ValueError):
        judge(user(enabled=False, **{field: "2026-07-03"}))
    with pytest.raises(ValueError):
        judge(user(enabled=False, activity="none"))


@pytest.mark.parametrize("activity", ["", "none", [], 0, False])
def test_malformed_sign_in_activity_raises(activity):
    with pytest.raises(ValueError):
        judge(user(activity=activity))


@pytest.mark.parametrize("enabled", [None, "false", "true", 0, 1, MISSING])
def test_account_enabled_must_be_boolean(enabled):
    record = user(enabled=enabled, activity=None)
    if enabled is MISSING:
        del record["accountEnabled"]
    with pytest.raises(ValueError):
        judge(record)


@pytest.mark.parametrize("record", [None, [], "user", 1])
def test_user_must_be_an_object(record):
    with pytest.raises(ValueError):
        judge(record)


@pytest.mark.parametrize("now", [datetime(2026, 10, 1), "2026-10-01T00:00:00Z", None])
def test_now_must_be_aware(now):
    with pytest.raises(ValueError):
        judge(user(), now=now)


@pytest.mark.parametrize("days", [0, -1, True, 1.5, "90", None])
def test_inactive_days_must_be_positive_int(days):
    with pytest.raises(ValueError):
        judge(user(), days=days)


def test_input_is_not_modified():
    record = user(success=NOW - timedelta(days=1))
    snapshot = repr(record)
    judge(record)
    assert repr(record) == snapshot


def test_every_combination_lands_in_exactly_one_known_class():
    stamps = [MISSING, None, NOW - timedelta(days=1), NOW - WINDOW, NOW - timedelta(days=500)]
    created = [MISSING, None, NOW - timedelta(days=1), NOW - WINDOW, OLD]
    seen = set()
    for enabled, made, success, interactive in itertools.product([True, False], created, stamps, stamps):
        seen.add(judge(user(enabled=enabled, created=made, success=success, interactive=interactive)))
    assert seen == set(get_args(Classification))
