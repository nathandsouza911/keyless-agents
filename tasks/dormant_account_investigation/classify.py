"""Dormant-account classification (Task 13; Review Focus 1; A-03, A-17, A-18, A-25).

classify() puts one Graph user into exactly one class, checked in this order:

  disabled          accountEnabled is false. Reported separately, whatever the
                    sign-in data says.
  active            the last sign-in is less than inactive_days before now.
  too_new_to_judge  created less than inactive_days before now: not dormant,
                    whether or not it has signed in.
  never_signed_in   no sign-in recorded: signInActivity null, omitted, or with
                    neither timestamp (A-17).
  dormant           the last sign-in is inactive_days or more before now
                    (exactly inactive_days ago is dormant).

The last sign-in is signInActivity.lastSuccessfulSignInDateTime when it is
present, else lastSignInDateTime (A-03). lastNonInteractiveSignInDateTime is
not used. A null or omitted createdDateTime means the age is unknown (A-25),
and the account is judged on its sign-ins alone.

A value that is present but not of the expected shape raises ValueError
rather than being guessed at: accountEnabled must be a boolean, and every
timestamp must be ISO 8601 with seconds and an explicit offset (A-25).
Fractions beyond microseconds are cut off.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Literal

Classification = Literal["active", "dormant", "never_signed_in", "too_new_to_judge", "disabled"]

_TIMESTAMP = re.compile(
    r"(?P<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,7}))?(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


def parse_timestamp(value: object) -> datetime | None:
    """None for null; a timezone-aware datetime for a Graph timestamp; else ValueError."""
    if value is None:
        return None
    match = _TIMESTAMP.match(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("timestamp is not ISO 8601 with seconds and an offset")
    fraction = (match["fraction"] or "")[:6].ljust(6, "0")
    offset = "+00:00" if match["offset"] == "Z" else match["offset"]
    return datetime.fromisoformat(f"{match['base']}.{fraction}{offset}")


def _record(user: object) -> Mapping[str, object]:
    if not isinstance(user, Mapping):
        raise ValueError("user is not an object")
    return user


def last_sign_in(user: object) -> datetime | None:
    activity = _record(user).get("signInActivity")
    if activity is None:
        return None
    if not isinstance(activity, Mapping):
        raise ValueError("signInActivity is not an object")
    successful = parse_timestamp(activity.get("lastSuccessfulSignInDateTime"))
    interactive = parse_timestamp(activity.get("lastSignInDateTime"))
    return successful if successful is not None else interactive


def classify(user: object, *, now: datetime, inactive_days: int) -> Classification:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    if type(inactive_days) is not int or inactive_days < 1:
        raise ValueError("inactive_days must be a positive integer")
    record = _record(user)
    enabled = record.get("accountEnabled")
    if type(enabled) is not bool:
        raise ValueError("accountEnabled is not a boolean")
    # Parse everything before deciding, so a malformed value is never hidden by an earlier class.
    last = last_sign_in(record)
    created = parse_timestamp(record.get("createdDateTime"))
    window = timedelta(days=inactive_days)

    if not enabled:
        return "disabled"
    if last is not None and now - last < window:
        return "active"
    if created is not None and now - created < window:
        return "too_new_to_judge"
    if last is None:
        return "never_signed_in"
    return "dormant"
