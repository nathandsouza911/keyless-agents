"""Dev-tenant integration fixtures (marker `tenant`; Task 17C).

These tests talk to real Entra and real Microsoft Graph in the dev tenant. They
run only when CLW_RUN_TENANT_TESTS=1 and every required dev-tenant variable is
set (from the environment, or from the repository's git-ignored .env, read here
and nowhere else; the application's Settings never parse .env). Otherwise every
test here is skipped. CI never sets CLW_RUN_TENANT_TESTS and also excludes the
`tenant` marker.

They use the pg test database (tests/db fixtures) and the least-privileged test
roles: the api and broker as the app role, the runner as the runner role.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.db.conftest import admin_conn, app_role_dsn, pg_dsn  # noqa: F401  (pg fixtures, reused)

REPO = Path(__file__).resolve().parents[2]
REQUIRED = ("CLW_DEV_TENANT_ID", "CLW_PROFILE_DIRREAD_CLIENT_ID", "CLW_PROFILE_DIRREAD_CERT_THUMBPRINT",
            "CLW_PROFILE_DIRREAD_CERT_PATH", "SESSION_JWT_SECRET")
# Object IDs of the dev tenant's test accounts (docs/runbooks/dev-tenant-setup.md, section 5). Each test
# that needs one skips while it is unset.
TEST_USERS = ("CLW_DEV_TEST_ACTIVE_ID", "CLW_DEV_TEST_NEVER_ID", "CLW_DEV_TEST_DISABLED_ID")


def _dotenv() -> dict[str, str]:
    path = REPO / ".env"
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def pytest_collection_modifyitems(config, items):
    here = [item for item in items if Path(str(item.fspath)).is_relative_to(Path(__file__).parent)]
    if not here:
        return
    if os.environ.get("CLW_RUN_TENANT_TESTS") != "1":
        reason = "dev-tenant tests run only with CLW_RUN_TENANT_TESTS=1"
    else:
        env = _dotenv() | dict(os.environ)
        missing = [name for name in REQUIRED if not env.get(name)]
        reason = f"dev-tenant variables not set: {', '.join(missing)}" if missing else None
    if reason:
        for item in here:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture(scope="session")
def dev_env() -> dict[str, str]:
    env = _dotenv() | dict(os.environ)
    key_path = Path(env["CLW_PROFILE_DIRREAD_CERT_PATH"])
    env["CLW_PROFILE_DIRREAD_CERT_PATH"] = str(key_path if key_path.is_absolute() else (REPO / key_path).resolve())
    return env
