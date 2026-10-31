"""Offline E2E demo task (Task 17A; test-only, never shipped).

One run that exercises both halves of the broker's policy against a real
(fake) Graph:

  1. the allowed named operation (users.list_with_sign_in_activity), paged by
     the broker, classified by the shipped Dormant Account classifier; then
  2. a prohibited write (users.update) through the SDK, which the broker must
     deny before any request reaches Graph.

It reuses the shipped task's `investigate` and classifier unchanged, so the
dormant/never-signed-in result is the real one. The result adds a
`write_probe` section recording that the write was denied and its reason. If
the write is NOT denied, `write_probe.denied` is false and the demo test
fails (and the fake Graph's request log would show the stray write).

    python -m tasks.dormant_probe_demo.task [--inactive-days N]

Exit codes match the shipped task: 0 result emitted; 1 the broker gave no
usable data; 2 bad arguments or environment.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime, timezone

from clw_task_sdk.client import BrokerError, GraphSecurityClient, OperationDenied
from clw_task_sdk.result import emit_result
from tasks.dormant_account_investigation.task import investigate

TASK_ID = "dormant-probe-demo"
DEFAULT_INACTIVE_DAYS, MIN_INACTIVE_DAYS, MAX_INACTIVE_DAYS = 90, 30, 365
PROHIBITED_OP = "users.update"
PROBE_USER_ID = "11111111-1111-4111-8111-111111111111"


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


def _probe_write(client: GraphSecurityClient) -> dict:
    """Attempt a prohibited write; the broker must deny it (no Graph request)."""
    try:
        client.call(PROHIBITED_OP, {"user_id": PROBE_USER_ID})
    except OperationDenied as exc:
        return {"op": PROHIBITED_OP, "denied": True, "reason": exc.reason}
    # Reached only if the broker did NOT deny the write: a defect the test catches.
    return {"op": PROHIBITED_OP, "denied": False, "reason": None}


def main(argv: Sequence[str] | None = None, *, client: GraphSecurityClient | None = None,
         now: datetime | None = None) -> int:
    try:
        days = _inactive_days(argv)
        source = client if client is not None else GraphSecurityClient.from_env()
    except (_UsageError, ValueError) as exc:
        print(f"{TASK_ID}: {exc}", file=sys.stderr)
        return 2
    try:
        result = investigate(source, now=now or datetime.now(timezone.utc), inactive_days=days)
        write_probe = _probe_write(source)
    except BrokerError as exc:
        print(f"{TASK_ID}: broker refused or failed: {exc.reason}", file=sys.stderr)
        return 1
    except ValueError:
        print(f"{TASK_ID}: a user record from the broker could not be classified", file=sys.stderr)
        return 1
    result["task_id"] = TASK_ID
    result["write_probe"] = write_probe
    emit_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
