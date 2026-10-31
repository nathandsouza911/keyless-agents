"""Dormant-account classification for the MCP tool (v0.1).

The same rules as the built-in task's classifier
(tasks/dormant_account_investigation/classify.py). The gateway cannot import
it: tasks never import clw, and the gateway image carries no tasks. A parity
test (tests/unit/test_mcp_gateway_dormant.py) runs both on the same cases.

One user falls in exactly one class, checked in this order: disabled; active
(last sign-in under `days` ago); too_new_to_judge (created under `days` ago);
never_signed_in (no sign-in recorded); dormant. The last sign-in is
lastSuccessfulSignInDateTime when present, else lastSignInDateTime. A value of
the wrong shape raises ValueError rather than being guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta

_TIMESTAMP = re.compile(
    r"(?P<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,7}))?(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
CLASSES = ("active", "dormant", "never_signed_in", "too_new_to_judge", "disabled")
# What the tool returns about each listed account: these properties and no others.
REPORTED = ("id", "displayName", "userPrincipalName", "userType", "createdDateTime")


def parse_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    match = _TIMESTAMP.match(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("timestamp is not ISO 8601 with seconds and an offset")
    fraction = (match["fraction"] or "")[:6].ljust(6, "0")
    offset = "+00:00" if match["offset"] == "Z" else match["offset"]
    return datetime.fromisoformat(f"{match['base']}.{fraction}{offset}")


def last_sign_in(user: Mapping[str, object]) -> datetime | None:
    activity = user.get("signInActivity")
    if activity is None:
        return None
    if not isinstance(activity, Mapping):
        raise ValueError("signInActivity is not an object")
    successful = parse_timestamp(activity.get("lastSuccessfulSignInDateTime"))
    interactive = parse_timestamp(activity.get("lastSignInDateTime"))
    return successful if successful is not None else interactive


def classify(user: object, *, now: datetime, days: int) -> str:
    if not isinstance(user, Mapping):
        raise ValueError("user is not an object")
    enabled = user.get("accountEnabled")
    if type(enabled) is not bool:
        raise ValueError("accountEnabled is not a boolean")
    last = last_sign_in(user)
    created = parse_timestamp(user.get("createdDateTime"))
    if not enabled:
        return "disabled"
    threshold = now - timedelta(days=days)
    if last is not None and last > threshold:
        return "active"
    if created is not None and created > threshold:
        return "too_new_to_judge"
    if last is None:
        return "never_signed_in"
    return "dormant"


def _entry(user: Mapping[str, object]) -> dict:
    entry = {key: user.get(key) for key in REPORTED}
    last = last_sign_in(user)
    entry["lastSignIn"] = last.isoformat().replace("+00:00", "Z") if last is not None else None
    return entry


def summarise(users: list, *, now: datetime, days: int) -> dict:
    """Counts per class, and the dormant and never-signed-in accounts (sorted by UPN)."""
    counts = dict.fromkeys(CLASSES, 0)
    listed: dict[str, list[dict]] = {"dormant": [], "never_signed_in": []}
    for user in users:
        kind = classify(user, now=now, days=days)
        counts[kind] += 1
        if kind in listed:
            listed[kind].append(_entry(user))
    for entries in listed.values():
        entries.sort(key=lambda e: (str(e.get("userPrincipalName") or ""), str(e.get("id") or "")))
    return {"days": days, "counts": counts, **listed}
