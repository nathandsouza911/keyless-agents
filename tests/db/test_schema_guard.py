"""The schema guard detects security-relevant changes, not just changed counts
(targeted review I-c, final review L-1).

Every change runs on the shared test database inside a transaction that is
always rolled back (PostgreSQL DDL, GRANT and ALTER ... SET are
transactional), so nothing is ever committed, even when an assertion fails
or the connection drops. Each test then checks the schema is back to the
reference, and the autouse guard checks it again from a new connection.
"""

from __future__ import annotations

import re

import asyncpg
import pytest

from tests.db.conftest import _REFERENCE, APP_ROLE, TEST_DB
from tests.db.schema_fingerprint import production_shaped, schema_differences, schema_fingerprint

pytestmark = pytest.mark.pg

# (label, statements, a fingerprint section that must report the change;
# some changes also show in another section, e.g. a dropped index in relations).
# Each keeps object counts where it can: the guard must see the definition.
STEPS = [
    ("function body replaced",
     ["CREATE OR REPLACE FUNCTION public.clw_valid_created_at(t text) RETURNS boolean "
      "LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp "
      "AS $$ BEGIN RETURN true; END; $$"], "functions"),
    ("validator made non-STRICT", ["ALTER FUNCTION public.clw_valid_created_at(text) CALLED ON NULL INPUT"],
     "functions"),
    ("EXECUTE on the trigger function granted to PUBLIC",
     ["GRANT EXECUTE ON FUNCTION public.clw_audit_events_check_append() TO PUBLIC"], "functions"),
    ("function added to schema public (not clw_)",
     ["CREATE FUNCTION public.octet_length(text) RETURNS int LANGUAGE sql AS $$ SELECT 0 $$"], "functions"),
    ("trigger disabled", ["ALTER TABLE audit_events DISABLE TRIGGER audit_events_check_append"], "triggers"),
    ("constraint left NOT VALID",
     ["ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_created_at_valid",
      "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_created_at_valid "
      "CHECK (public.clw_valid_created_at(created_at)) NOT VALID"], "constraints"),
    ("table privilege granted to the app role", [f"GRANT UPDATE ON audit_events TO {APP_ROLE}"], "relations"),
    ("column privilege granted to the app role", [f"GRANT UPDATE (reason) ON audit_events TO {APP_ROLE}"],
     "columns"),
    ("column default added", ["ALTER TABLE audit_events ALTER COLUMN reason SET DEFAULT 'x'"], "columns"),
    ("rule added", ["CREATE RULE r AS ON INSERT TO audit_events DO INSTEAD NOTHING"], "rules"),
    ("index dropped", ["DROP INDEX ix_audit_events_run_id"], "indexes"),
    ("row security policy added",
     ["ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY",
      f"CREATE POLICY p ON audit_events FOR SELECT TO {APP_ROLE} USING (false)"], "policies"),
    ("table added to schema public", ["CREATE TABLE public.shadow (x int)"], "relations"),
    ("TEMP on the database granted to the app role",
     [f'GRANT TEMPORARY ON DATABASE "{TEST_DB}" TO {APP_ROLE}'], "database"),
    ("TEMP on the database granted to PUBLIC",
     [f'GRANT TEMPORARY ON DATABASE "{TEST_DB}" TO PUBLIC'], "database"),
    ("CREATE on the database granted to PUBLIC", [f'GRANT CREATE ON DATABASE "{TEST_DB}" TO PUBLIC'], "database"),
    ("CREATE on schema public granted to PUBLIC", ["GRANT CREATE ON SCHEMA public TO PUBLIC"], "schemas"),
    ("database-level setting", [f"ALTER DATABASE \"{TEST_DB}\" SET timezone = 'Europe/London'"], "settings"),
    ("role-level setting (every database)", [f"ALTER ROLE {APP_ROLE} SET timezone = 'Europe/London'"],
     "settings"),
    ("default privileges for new tables",
     [f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT UPDATE ON TABLES TO {APP_ROLE}"], "default_privileges"),
    ("app role given BYPASSRLS", [f"ALTER ROLE {APP_ROLE} BYPASSRLS"], "roles"),
    ("app role made a member of a privileged role", [f"GRANT pg_write_all_data TO {APP_ROLE}"], "roles"),
    ("event trigger added",
     ["CREATE FUNCTION public.clw_evt() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END; $$",
      "CREATE EVENT TRIGGER clw_evt ON ddl_command_start EXECUTE FUNCTION public.clw_evt()"], "event_triggers"),
]


async def _differences_under(conn, statements: list[str]) -> tuple[list[str], dict]:
    """Apply the statements in a transaction, fingerprint, always roll back."""
    tx = conn.transaction()
    await tx.start()
    try:
        for sql in statements:
            await conn.execute(sql)
        current = await schema_fingerprint(conn)
    finally:
        await tx.rollback()
    return schema_differences(_REFERENCE["fingerprint"], current), current


async def _assert_restored(conn) -> None:
    assert schema_differences(_REFERENCE["fingerprint"], await schema_fingerprint(conn)) == []


async def test_guard_detects_a_changed_constraint_definition(pg_dsn):
    """Same constraint name, same count, weaker expression."""
    conn = await asyncpg.connect(pg_dsn)
    try:
        differences, _ = await _differences_under(conn, [
            "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_text_bounds",
            "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_text_bounds "
            "CHECK (octet_length(coalesce(reason, '')) <= 1000000)",
        ])
        await _assert_restored(conn)
    finally:
        await conn.close()
    changed = [d for d in differences if d.startswith("constraints:") and "ck_audit_events_text_bounds" in d]
    assert len(changed) == 2, differences  # the old definition missing, the new one present
    assert any("missing or changed" in d and "4096" in d for d in changed), changed
    assert any("new or changed" in d and "1000000" in d for d in changed), changed


# ids are word characters only, so pytest -k (and the mutation check) can select them
@pytest.mark.parametrize(("label", "statements", "section"), STEPS,
                         ids=[re.sub(r"\W+", "_", s[0]).strip("_") for s in STEPS])
async def test_guard_detects(pg_dsn, label, statements, section):
    conn = await asyncpg.connect(pg_dsn)
    try:
        differences, _ = await _differences_under(conn, statements)
        await _assert_restored(conn)
    finally:
        await conn.close()
    assert differences, f"guard missed: {label}"
    assert any(d.startswith(f"{section}:") for d in differences), (label, differences)


async def test_production_shape_flags_what_is_never_acceptable(pg_dsn):
    conn = await asyncpg.connect(pg_dsn)
    try:
        step = {label: statements for label, statements, _ in STEPS}
        _, current = await _differences_under(conn, [
            *step["trigger disabled"], *step["constraint left NOT VALID"], *step["rule added"],
            *step["database-level setting"], *step["role-level setting (every database)"],
            "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'ix_audit_events_run_id'::regclass",
        ])
        await _assert_restored(conn)
    finally:
        await conn.close()
    problems = production_shaped(current)
    for expected in ("trigger not enabled", "constraint not validated", "rule on audit_events",
                     "<this database>", APP_ROLE, "index not usable"):
        assert any(expected in p for p in problems), (expected, problems)
