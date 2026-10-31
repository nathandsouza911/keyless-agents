"""The autouse schema guard really fails a test that leaves a change behind
(final review I-1).

Runs a separate pytest session with the real fixtures from tests/db/conftest.py
against its own database (CLW_TEST_DB), never the shared one: the inner
session drops and recreates that database, and the test drops it afterwards.
The inner tests reach the guard exactly as every PostgreSQL test does, so a
guard that is skipped, compares the wrong thing or swallows its result makes
this test fail.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import asyncpg
import pytest

from tests.db.conftest import ADMIN_DSN, APP_ROLE, REPO

pytestmark = pytest.mark.pg
INNER_DB = "clw_test_guard_wiring"

INNER = f'''
import pytest

from tests.db.conftest import _schema_stays_production_shaped, admin_conn, app_role_dsn, pg_dsn  # noqa: F401

pytestmark = pytest.mark.pg


async def test_1_leaves_nothing_behind(admin_conn):
    await admin_conn.execute("SELECT 1")


async def test_2_leaves_a_grant_behind(admin_conn):
    await admin_conn.execute("GRANT UPDATE ON audit_events TO {APP_ROLE}")


async def test_3_later_test_on_the_changed_database(admin_conn):
    await admin_conn.execute("SELECT 1")
'''


async def _drop_inner() -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{INNER_DB}" WITH (FORCE)')
    finally:
        await conn.close()


def test_guard_fails_a_test_that_leaves_the_schema_changed(tmp_path):
    test_file = tmp_path / "test_inner_guard.py"
    test_file.write_text(INNER, encoding="utf-8")
    report = tmp_path / "report.xml"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-c", str(REPO / "pyproject.toml"),
             "--rootdir", str(REPO), "-p", "no:cacheprovider", "-q", f"--junitxml={report}"],
            cwd=REPO, capture_output=True, text=True, timeout=300,
            env={**os.environ, "CLW_TEST_DB": INNER_DB},
        )
    finally:
        asyncio.run(_drop_inner())
    assert report.exists(), result.stdout + result.stderr
    cases = {case.get("name"): case for case in ET.parse(report).getroot().iter("testcase")}
    assert set(cases) == {"test_1_leaves_nothing_behind", "test_2_leaves_a_grant_behind",
                          "test_3_later_test_on_the_changed_database"}, result.stdout

    def errors(name: str) -> list[str]:
        return [(e.get("message") or "") + (e.text or "") for e in cases[name] if e.tag in ("error", "failure")]

    assert errors("test_1_leaves_nothing_behind") == [], result.stdout
    # The test body passed; the guard fails it at teardown and names the change.
    left = errors("test_2_leaves_a_grant_behind")
    assert len(left) == 1, result.stdout
    assert "test left the audit schema changed" in left[0] and "relations:" in left[0], left[0]
    assert APP_ROLE in left[0], left[0]
    # The change is still there for the next test, and the guard says so again.
    assert any("test left the audit schema changed" in e for e in errors("test_3_later_test_on_the_changed_database"))
    assert result.returncode != 0
