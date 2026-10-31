"""Dormant Account Investigation (Task 13).

Reads every user with sign-in activity through the broker (one named
operation, users.list_with_sign_in_activity), classifies each one
(classify.py) and emits one result line: the dormant and never-signed-in
accounts, the count per class and the threshold used. Disabled and too-new
accounts are counted, not listed.

    python -m tasks.dormant_account_investigation.task [--inactive-days N]

N defaults to the manifest's default and must be within its bounds (checked
against manifest.yaml by the tests). The runner passes the run's
`inactive_days` this way (Task 14). The environment holds only the run
token and the broker URL.

Exit codes: 0 result emitted; 1 the broker gave no usable data (denied,
failed, halted, unreachable, or a user record that cannot be classified);
2 bad arguments or environment. Nothing but the result goes to stdout, and
error messages carry the reason only, never user data or the token.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Protocol, get_args

from clw_task_sdk.client import BrokerError, GraphSecurityClient
from clw_task_sdk.result import emit_result
from tasks.dormant_account_investigation.classify import Classification, classify, last_sign_in, parse_timestamp

TASK_ID = "dormant-account-investigation"
DEFAULT_INACTIVE_DAYS, MIN_INACTIVE_DAYS, MAX_INACTIVE_DAYS = 90, 30, 365
CLASSES: tuple[Classification, ...] = get_args(Classification)
NOTE = ("Candidates for review, not proof of disuse: sign-in times come from Microsoft Graph signInActivity, "
        "which can lag recent sign-ins.")  # A-18


class UserSource(Protocol):
    def list_users_with_sign_in_activity(self) -> list[dict]: ...


def _utc(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(user: Mapping[str, object], key: str) -> str | None:
    value = user.get(key)
    return value if isinstance(value, str) else None


def _identity(user: Mapping[str, object]) -> dict[str, str | None]:
    return {key: _text(user, key) for key in ("id", "userPrincipalName", "displayName")}


def _order(entry: dict) -> tuple[str, str]:
    return (entry["userPrincipalName"] or "", entry["id"] or "")


def investigate(client: UserSource, *, now: datetime, inactive_days: int) -> dict:
    users = client.list_users_with_sign_in_activity()
    counts = dict.fromkeys(CLASSES, 0)
    dormant, never = [], []
    for user in users:
        verdict = classify(user, now=now, inactive_days=inactive_days)
        counts[verdict] += 1
        if verdict == "dormant":
            dormant.append(_identity(user) | {"last_sign_in": _utc(last_sign_in(user))})
        elif verdict == "never_signed_in":
            never.append(_identity(user) | {"created": _utc(parse_timestamp(user.get("createdDateTime")))})
    return {
        "task_id": TASK_ID,
        "inactive_days": inactive_days,
        "evaluated_at": _utc(now),
        "users_evaluated": len(users),
        "counts": counts,
        "dormant": sorted(dormant, key=_order),
        "never_signed_in": sorted(never, key=_order),
        "note": NOTE,
    }


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _inactive_days(argv: Sequence[str] | None) -> int:
    parser = _Parser(prog=TASK_ID, add_help=False, allow_abbrev=False)
    parser.add_argument("--inactive-days", type=int, default=DEFAULT_INACTIVE_DAYS)
    days = parser.parse_args(argv).inactive_days
    if not MIN_INACTIVE_DAYS <= days <= MAX_INACTIVE_DAYS:
        raise _UsageError(f"--inactive-days must be {MIN_INACTIVE_DAYS} to {MAX_INACTIVE_DAYS}")
    return days


def main(argv: Sequence[str] | None = None, *, client: UserSource | None = None,
         now: datetime | None = None) -> int:
    try:
        days = _inactive_days(argv)
        source = client if client is not None else GraphSecurityClient.from_env()
    except (_UsageError, ValueError) as exc:
        print(f"{TASK_ID}: {exc}", file=sys.stderr)
        return 2
    try:
        result = investigate(source, now=now or datetime.now(timezone.utc), inactive_days=days)
    except BrokerError as exc:
        print(f"{TASK_ID}: broker refused or failed: {exc.reason}", file=sys.stderr)
        return 1
    except ValueError:
        print(f"{TASK_ID}: a user record from the broker could not be classified", file=sys.stderr)
        return 1
    emit_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
