"""Named test groups for the audit subsystem (see docs/testing.md).

Run:  uv run python scripts/run_tests.py <group> [extra pytest args]

Groups run one after another, never in parallel: the PostgreSQL tests share
one test database, and running groups side by side would only add memory.

  quick      unit and security tests, no database          (~50 s)
  focused    writer, recovery, timestamp, checkpoint and
             schema-guard tests, unit and PostgreSQL        (~1 min)
  db         all PostgreSQL tests, admin sessions           (~1 min)
  db-app     all PostgreSQL tests, every writer session as
             the least-privileged app role                  (~1 min)
  redis      revocation and rate limiting against Redis   (~5 s)
  full       quick + db + db-app + redis                    (~2.5 min)

Mutation testing is separate (scripts/audit_mutation_check.py); see
docs/testing.md for when each is required.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

FOCUSED_UNIT = [
    "tests/unit/audit/test_timestamp_durability.py",
    "tests/unit/audit/test_wait_target.py",
    "tests/unit/audit/test_checkpoint.py",
    "tests/unit/audit/test_text_limits.py",
    "tests/unit/audit/test_write_ahead.py",
    "tests/unit/audit/test_malformed.py",
    "tests/unit/test_timeutil.py",
    "tests/unit/test_mutation_check.py",
]
FOCUSED_DB = [
    "tests/db/test_audit_cache_recovery.py",
    "tests/db/test_audit_anchor.py",
    "tests/db/test_audit_writer.py",
    "tests/db/test_audit_poisoning.py",
    "tests/db/test_audit_time_size.py",
    "tests/db/test_audit_timeouts.py",
    "tests/db/test_audit_session_settings.py",
    "tests/db/test_schema_guard.py",
    "tests/db/test_schema_guard_wiring.py",
]

GROUPS: dict[str, list[tuple[list[str], dict[str, str]]]] = {
    "quick": [(["tests/unit", "tests/security"], {})],
    "focused": [(FOCUSED_UNIT + FOCUSED_DB, {})],
    "db": [(["tests/db"], {})],
    "db-app": [(["tests/db"], {"CLW_TEST_SESSION_ROLE": "app"})],
    "redis": [(["tests/redis"], {})],
}
GROUPS["full"] = GROUPS["quick"] + GROUPS["db"] + GROUPS["db-app"] + GROUPS["redis"]


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in GROUPS:
        print(__doc__)
        return 2
    group, extra = argv[0], argv[1:]
    worst = 0
    for paths, env in GROUPS[group]:
        label = " ".join(paths) + (f" [{' '.join(f'{k}={v}' for k, v in env.items())}]" if env else "")
        started = time.monotonic()
        rc = subprocess.call([sys.executable, "-m", "pytest", *paths, "-q", "-p", "no:cacheprovider", *extra],
                             env={**os.environ, **env})
        print(f"--- {group}: {label}: exit {rc} in {time.monotonic() - started:.0f}s", flush=True)
        worst = worst or rc
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
