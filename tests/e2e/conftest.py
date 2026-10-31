"""Offline Phase 1 E2E harness (Task 17A).

Brings up the real stack in containers — postgres, broker, runner, api — plus
a fake Graph aliased as graph.microsoft.com on the egress network, and drives
it from the host. The database schema and the one tenant/member are created
from the host (the repo has Alembic and the migrations; the images do not).

Nothing here changes production code or images: the broker/runner/task images
are the real ones with a thin test layer adding one test-only demo task, and
every E2E-only detail is a mount, command or environment value.

Skips (never passes) if Docker is unavailable.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import asyncpg
import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.e2e import certs as e2e_certs
from tests.e2e.e2e_broker import FAKE_AGENT_CLIENT_ID, FAKE_CLIENT_ID

REPO = Path(__file__).resolve().parents[2]
E2E_DIR = Path(__file__).resolve().parent
COMPOSE = E2E_DIR / "compose.e2e.yml"
ARTIFACTS = E2E_DIR / ".artifacts"

PG_USER, PG_PASSWORD, PG_DB = "clw", "e2e-only-password", "clw"
READY_TIMEOUT = 180.0


def _posix(path: Path) -> str:
    # Docker Desktop on Windows accepts forward-slash absolute paths (E:/...).
    return path.resolve().as_posix()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


def _run(cmd: list[str], *, env: dict | None = None, timeout: float = 600.0) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, **(env or {})})
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stdout}\n{result.stderr}")
    return result


def _build_images() -> None:
    builds = [
        ("docker/broker.Dockerfile", "clw-broker-base:latest"),
        ("docker/runner.Dockerfile", "clw-runner-base:latest"),
        ("docker/task.Dockerfile", "clw-task-base:latest"),
        ("docker/e2e/broker.e2e.Dockerfile", "clw-broker:e2e"),
        ("docker/e2e/runner.e2e.Dockerfile", "clw-runner:e2e"),
        ("docker/e2e/task.e2e.Dockerfile", "clw-task:e2e"),
        ("docker/analyser.Dockerfile", "clw-analyser:e2e"),
        ("docker/facade-proxy.Dockerfile", "clw-facade-proxy:e2e"),
        ("docker/mcp-gateway.Dockerfile", "clw-mcp-gateway:e2e"),
    ]
    for dockerfile, tag in builds:
        _run(["docker", "build", "-f", dockerfile, "-t", tag, "."], timeout=900.0)


def _build_script_image(facade_public: Path) -> None:
    """The PowerShell task image, trusting this run's facade CA (its public directory only)."""
    _run(["docker", "build", "--build-context", f"facade_ca={_posix(facade_public)}",
          "-f", "docker/task-pwsh.Dockerfile", "-t", "clw-task-pwsh:e2e", "."], timeout=1200.0)


def _certifi_path(image: str) -> str:
    out = _run(["docker", "run", "--rm", image, "/srv/.venv/bin/python", "-c",
                "import certifi; print(certifi.where())"])
    return out.stdout.strip()


def _profile_key(into: Path) -> tuple[Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path = into / "profile_key.pem"
    path.write_bytes(pem)
    thumbprint = hashlib.sha1(pem).hexdigest()  # 40 hex, the shape the provider requires (not verified by FakeMsal)
    return path, thumbprint


def _sqlalchemy_url(host_port: int) -> str:
    return f"postgresql+asyncpg://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{host_port}/{PG_DB}"


def _asyncpg_dsn(host_port: int) -> str:
    return f"postgresql://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{host_port}/{PG_DB}"


def _wait(label: str, check, *, timeout: float = READY_TIMEOUT, interval: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(interval)
    raise RuntimeError(f"timed out waiting for {label}: {last}")


@dataclass
class Stack:
    api_base: str
    graph: httpx.Client          # control-plane client to the fake Graph (TLS verification off)
    tenant: tuple[str, uuid.UUID, str]
    session_secret: str
    lead: tuple[uuid.UUID, str] | None = None   # a security lead of the tenant (user id, oid)
    compose: tuple[str, ...] = ()                # `docker compose -f ...`, with the profiles enabled
    env: dict | None = None                      # the compose environment
    prod_api_base: str = ""                      # the production-mode api (profile prod), when started
    mcp_url: str = ""                            # the MCP gateway's endpoint (SD-052)
    pg_port: int = 0                             # the stack's Postgres, on the host

    def compose_run(self, *args: str, timeout: float = 180.0) -> subprocess.CompletedProcess:
        return subprocess.run([*self.compose, *args], cwd=str(REPO), capture_output=True, text=True,
                              env={**os.environ, **self.env}, timeout=timeout)

    def session_cookie(self, role: str = "analyst") -> dict[str, str]:
        os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/none"
        os.environ["SESSION_JWT_SECRET"] = self.session_secret
        os.environ["ENVIRONMENT"] = "test"
        from types import SimpleNamespace
        from unittest import mock

        from clw.auth import session_jwt
        from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
        from clw.common import config
        config.get_settings.cache_clear()
        tid, user_id, oid = self.tenant
        if role == "security_lead":
            user_id, oid = self.lead
        # Minted here on the host, verified in the api container: Docker Desktop's
        # VM clock ran 0.3-0.4 s behind the Windows host (2026-10-26), so a token
        # minted early in a second had an iat in the api's future and was refused
        # (not_yet_valid; the intermittent e2e 401). Backdate it by 2 s instead of
        # giving the verifier any leeway.
        real_time = session_jwt.time.time
        with mock.patch.object(session_jwt, "time", SimpleNamespace(time=lambda: real_time() - 2)):
            token = issue_session(user_id=user_id, oid=oid, tid=tid, role=role)
        config.get_settings.cache_clear()
        return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}

    def graph_requests(self) -> list[dict]:
        return self.graph.get("/_control/requests").json()["requests"]

    def graph_reset(self) -> None:
        self.graph.post("/_control/reset")

    def graph_set_mode(self, mode: str) -> None:
        self.graph.post(f"/_control/mode/{mode}")


async def _seed(dsn: str, tenant: tuple[str, uuid.UUID, str], lead: tuple[uuid.UUID, str]) -> None:
    tid, user_id, oid = tenant
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("INSERT INTO tenants (id, display_name, status) VALUES ($1, 'E2E tenant', 'active')", tid)
        await conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'analyst')",
                           user_id, tid, oid)
        await conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) "
                           "VALUES ($1, $2, $3, 'security_lead')", lead[0], tid, lead[1])
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def stack():
    import asyncio

    if not _docker_ok():
        pytest.skip("Docker daemon not reachable")

    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS, ignore_errors=True)
    ARTIFACTS.mkdir(parents=True)

    _build_images()
    certifi_path = _certifi_path("clw-broker:e2e")
    certs = e2e_certs.generate(ARTIFACTS)
    key_path, thumbprint = _profile_key(ARTIFACTS)
    from clw.broker.facade.ca import create as create_facade_ca
    facade = create_facade_ca(ARTIFACTS / "facade")
    _build_script_image(facade.ca_cert.parent)

    pg_port, api_port, broker_port, graph_port, prod_api_port, mcp_port = (_free_port() for _ in range(6))
    tenant = (str(uuid.uuid4()), uuid.uuid4(), str(uuid.uuid4()))
    lead = (uuid.uuid4(), str(uuid.uuid4()))
    session_secret = uuid.uuid4().hex + uuid.uuid4().hex  # >= 32 bytes

    env = {
        "E2E_PG_USER": PG_USER, "E2E_PG_PASSWORD": PG_PASSWORD, "E2E_PG_DB": PG_DB, "E2E_PG_PORT": str(pg_port),
        "E2E_DATABASE_URL": f"postgresql+asyncpg://{PG_USER}:{PG_PASSWORD}@postgres:5432/{PG_DB}",
        "E2E_DIR": _posix(E2E_DIR), "E2E_CERTS_DIR": _posix(ARTIFACTS),
        "E2E_API_PORT": str(api_port), "E2E_BROKER_PORT": str(broker_port), "E2E_GRAPH_PORT": str(graph_port),
        "E2E_PROFILE_CLIENT_ID": FAKE_CLIENT_ID, "E2E_PROFILE_THUMBPRINT": thumbprint,
        "E2E_PROFILE_KEY": _posix(key_path), "E2E_CA_PEM": _posix(certs.ca_pem), "E2E_CERTIFI_PATH": certifi_path,
        "E2E_SESSION_SECRET": session_secret,
        "E2E_FACADE_DIR": _posix(facade.leaf_cert.parent),
        "E2E_API_PROD_PORT": str(prod_api_port), "E2E_REDIS_PASSWORD": uuid.uuid4().hex,
        "E2E_MCP_PORT": str(mcp_port), "E2E_AGENT_PROFILE_CLIENT_ID": FAKE_AGENT_CLIENT_ID,
    }
    compose = ["docker", "compose", "-f", str(COMPOSE), "--profile", "prod"]

    try:
        # The fixed sandbox network (internal) is external to compose; create it
        # if it is not already there (it may linger from the sandbox tests).
        subprocess.run(["docker", "network", "create", "--internal", "clw_tasknet"],
                       capture_output=True, text=True, timeout=30)
        subprocess.run(["docker", "network", "create", "--internal", "clw_scriptnet"],
                       capture_output=True, text=True, timeout=30)
        _run([*compose, "up", "-d", "postgres"], env=env)
        _wait("postgres", lambda: asyncio.run(_pg_ready(_asyncpg_dsn(pg_port))))
        cfg = Config(str(REPO / "alembic.ini"))
        cfg.attributes["database_url"] = _sqlalchemy_url(pg_port)
        command.upgrade(cfg, "head")
        asyncio.run(_seed(_asyncpg_dsn(pg_port), tenant, lead))

        _run([*compose, "up", "-d", "fake-graph", "broker", "facade-proxy", "runner", "api", "mcp-gateway"], env=env)

        graph = httpx.Client(base_url=f"https://127.0.0.1:{graph_port}", verify=False, timeout=10.0)
        api_base = f"http://127.0.0.1:{api_port}"
        _wait("fake-graph", lambda: graph.get("/_control/health").status_code == 200)
        _wait("broker", lambda: _tcp_ok("127.0.0.1", broker_port))
        with httpx.Client(timeout=10.0) as probe:
            _wait("api", lambda: probe.get(f"{api_base}/tasks").status_code == 401)
            _wait("mcp-gateway", lambda: probe.post(f"http://127.0.0.1:{mcp_port}/mcp").status_code == 401)

        yield Stack(api_base=api_base, graph=graph, tenant=tenant, session_secret=session_secret, lead=lead,
                    compose=tuple(compose), env=env, prod_api_base=f"http://127.0.0.1:{prod_api_port}",
                    mcp_url=f"http://127.0.0.1:{mcp_port}/mcp", pg_port=pg_port)
        graph.close()
    finally:
        subprocess.run([*compose, "logs", "--no-color", "--tail", "40"], cwd=str(REPO),
                       capture_output=True, text=True, env={**os.environ, **env})
        subprocess.run([*compose, "down", "-v", "--remove-orphans"], cwd=str(REPO),
                       capture_output=True, text=True, env={**os.environ, **env}, timeout=120)
        _remove_stray_task_containers()
        shutil.rmtree(ARTIFACTS, ignore_errors=True)


async def _pg_ready(dsn: str) -> bool:
    conn = await asyncpg.connect(dsn)
    await conn.close()
    return True


def _tcp_ok(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(2)
        s.connect((host, port))
    return True


def _remove_stray_task_containers() -> None:
    try:
        out = subprocess.run(["docker", "ps", "-aq", "--filter", "name=clw-task-"],
                             capture_output=True, text=True, timeout=30).stdout.split()
        if out:
            subprocess.run(["docker", "rm", "-f", *out], capture_output=True, timeout=60)
    except Exception:
        pass
