"""Postgres fixtures for pg-marked tests.

A fresh database (clw_test) is created per test session and migrated with
Alembic. If Postgres is unreachable the tests ERROR rather than skip, so a
missing database can never look like a pass.

Admin DSN: TEST_PG_ADMIN_DSN (default matches .env.example).
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from pathlib import Path

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

REPO = Path(__file__).resolve().parents[2]
ADMIN_DSN = os.environ.get("TEST_PG_ADMIN_DSN", "postgresql://clw:change-me-local-only@127.0.0.1:5433/clw")
# CLW_TEST_DB exists for the guard-wiring test, which runs an inner pytest
# session against its own database. Only clw_test* names: this database is
# dropped and recreated, so it must never be pointed at a real one.
TEST_DB = os.environ.get("CLW_TEST_DB", "clw_test")
if not re.fullmatch(r"clw_test[a-z0-9_]{0,40}", TEST_DB):
    raise RuntimeError(f"CLW_TEST_DB must be clw_test or clw_test_<suffix>, not {TEST_DB!r}")
APP_ROLE = "clw_app_test"
APP_ROLE_PASSWORD = "app-role-test-only"
RUNNER_ROLE = "clw_runner_test"
RUNNER_ROLE_PASSWORD = "runner-role-test-only"


def _dsn_for(db: str, *, user: str | None = None, password: str | None = None) -> str:
    base, _, _ = ADMIN_DSN.rpartition("/")
    if user:
        scheme, _, rest = base.partition("://")
        host = rest.split("@", 1)[1]
        base = f"{scheme}://{user}:{password}@{host}"
    return f"{base}/{db}"


def _sqlalchemy_url(dsn: str) -> str:
    return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)


async def _recreate_database() -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{TEST_DB}"')
        exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", APP_ROLE)
        if not exists:
            await conn.execute(f"CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOINHERIT PASSWORD '{APP_ROLE_PASSWORD}'")
        if not await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", RUNNER_ROLE):
            await conn.execute(
                f"CREATE ROLE {RUNNER_ROLE} LOGIN NOSUPERUSER NOINHERIT PASSWORD '{RUNNER_ROLE_PASSWORD}'")
    finally:
        await conn.close()


async def _grant_app_role() -> None:
    """The test roles get the deployment's grants (clw.db.roles, SD-038): the
    app role is the api and the broker together, the runner role the runner."""
    from clw.db.roles import grant_statements

    conn = await asyncpg.connect(_dsn_for(TEST_DB))
    try:
        for component, role in (("api", APP_ROLE), ("broker", APP_ROLE), ("runner", RUNNER_ROLE)):
            for statement in grant_statements(component, role=role, database=TEST_DB):
                await conn.execute(statement)
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    asyncio.run(_recreate_database())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(TEST_DB))
    command.upgrade(cfg, "head")
    asyncio.run(_grant_app_role())
    _REFERENCE["fingerprint"] = asyncio.run(_capture_fingerprint(_dsn_for(TEST_DB)))
    return _dsn_for(TEST_DB)


_REFERENCE: dict[str, dict] = {}


async def _capture_fingerprint(dsn: str) -> dict:
    from tests.db.schema_fingerprint import production_shaped, schema_fingerprint

    conn = await asyncpg.connect(dsn)
    try:
        fingerprint = await schema_fingerprint(conn)
    finally:
        await conn.close()
    assert production_shaped(fingerprint) == [], production_shaped(fingerprint)
    return fingerprint


@pytest.fixture(scope="session")
def app_role_dsn(pg_dsn) -> str:
    return _dsn_for(TEST_DB, user=APP_ROLE, password=APP_ROLE_PASSWORD)


@pytest.fixture
async def sessionmaker(pg_dsn, app_role_dsn):
    # CLW_TEST_SESSION_ROLE=app runs every writer/verifier session in the suite
    # as the least-privileged application role (admin_conn stays admin for the
    # attack set-up steps that need it).
    dsn = app_role_dsn if os.environ.get("CLW_TEST_SESSION_ROLE") == "app" else pg_dsn
    engine = create_async_engine(_sqlalchemy_url(dsn))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def runner_sessionmaker(pg_dsn):
    # CLW_TEST_SESSION_ROLE=app: the runner works as its own least-privileged role.
    dsn = (_dsn_for(TEST_DB, user=RUNNER_ROLE, password=RUNNER_ROLE_PASSWORD)
           if os.environ.get("CLW_TEST_SESSION_ROLE") == "app" else pg_dsn)
    engine = create_async_engine(_sqlalchemy_url(dsn))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def app_sessionmaker(app_role_dsn):
    engine = create_async_engine(_sqlalchemy_url(app_role_dsn))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def unreachable_sessionmaker():
    # Nothing listens on port 1; connection attempts fail immediately.
    engine = create_async_engine("postgresql+asyncpg://x:y@127.0.0.1:1/none", connect_args={"timeout": 2})
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def chain_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
async def admin_conn(pg_dsn):
    conn = await asyncpg.connect(pg_dsn)
    yield conn
    await conn.close()


@pytest.fixture
async def app_conn(app_role_dsn):
    conn = await asyncpg.connect(app_role_dsn)
    yield conn
    await conn.close()


@pytest.fixture(autouse=True)
async def _schema_stays_production_shaped(request):
    """No pg test may leave the shared test database different from the
    freshly migrated schema, as compared by tests/db/schema_fingerprint.py
    (fifth review I-2, targeted review I-c, final review L-1). A test that
    leaves a change behind errors at teardown; tests/db/test_schema_guard_wiring.py
    proves that by running an inner session against its own database."""
    if request.node.get_closest_marker("pg") is None or "pg_dsn" not in request.fixturenames:
        yield
        return
    from tests.db.schema_fingerprint import schema_differences, schema_fingerprint

    yield
    reference = _REFERENCE["fingerprint"]  # captured by pg_dsn right after migration
    conn = await asyncpg.connect(request.getfixturevalue("pg_dsn"))
    try:
        current = await schema_fingerprint(conn)
    finally:
        await conn.close()
    differences = schema_differences(reference, current)
    assert differences == [], "test left the audit schema changed: " + "; ".join(differences[:10])
