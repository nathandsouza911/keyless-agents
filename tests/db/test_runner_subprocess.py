"""The launcher running the real Dormant Account task as a local process (Task 14).

A test-only backend runs the container's command as a subprocess with the
container's environment, against a stub broker on 127.0.0.1 that answers
users.list_with_sign_in_activity. This shows the run's inactive_days
reaching the task through its command line and the task's own result line
being validated, stored and hashed. It is not the sandbox: no network
isolation, no limits (Task 15 tests the container). On Windows, SYSTEMROOT
is added to the process environment because Python cannot start its
networking without it, and "\\r\\n" in stdout is read as "\\n" (Windows
text-mode stdout translates line ends; the Linux container does not, and
the runner itself rejects "\\r"). The container's environment is checked
separately to be exactly the two keys.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from clw.audit.chain import verify_run_result
from clw.audit.writer import AuditWriter
from clw.audit.verifier import load_chain
from clw.runner.launcher import Launcher
from clw.runner.sandbox_spec import SandboxConfig
from tests.db.broker_fixtures import CATALOG, REPO, add_tenant, run_row
from tests.db.runner_fixtures import end_stray_queued_runs, queue_run

pytestmark = pytest.mark.pg

NOW = datetime.now(timezone.utc)


def stamp(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


USERS = [
    {"id": "u-45", "userPrincipalName": "u45@contoso.test", "displayName": "45 days", "accountEnabled": True,
     "createdDateTime": stamp(400), "signInActivity": {"lastSuccessfulSignInDateTime": stamp(45)}},
    {"id": "u-10", "userPrincipalName": "u10@contoso.test", "displayName": "10 days", "accountEnabled": True,
     "createdDateTime": stamp(400), "signInActivity": {"lastSuccessfulSignInDateTime": stamp(10)}},
]


class StubBroker:
    def __init__(self, status: int = 200, reply: dict | None = None) -> None:
        self.requests: list[tuple[str, str | None, dict]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                outer.requests.append((self.path, self.headers.get("authorization"), body))
                payload = json.dumps(reply or {"status": "ok", "data": USERS}).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Process:
    def __init__(self, popen: subprocess.Popen) -> None:
        self._popen = popen

    def stdout(self):
        data = b""
        while chunk := self._popen.stdout.read1(65536):
            data += chunk
        # Windows text-mode stdout writes "\r\n" for "\n" (the Linux container does not).
        yield data.replace(b"\r\n", b"\n") if os.name == "nt" else data

    def wait(self) -> int:
        return self._popen.wait(timeout=120)

    def kill(self) -> None:
        self._popen.kill()

    def remove(self) -> None:
        self._popen.stdout.close()


class SubprocessBackend:
    def __init__(self) -> None:
        self.started: list[dict] = []

    def start(self, kwargs: dict):
        self.started.append(kwargs)
        command = [sys.executable if kwargs["command"][0] == "python" else kwargs["command"][0], *kwargs["command"][1:]]
        env = dict(kwargs["environment"])
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        return _Process(subprocess.Popen(command, cwd=REPO, env=env, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL))

    def kill_run(self, run_id: str) -> None:
        pass

    def peer_address(self, network: str, name: str) -> str | None:
        return "127.0.0.1"  # a local process: the hosts entry is not used


@pytest.fixture(autouse=True)
async def _no_stray_queued_runs(admin_conn):
    await end_stray_queued_runs(admin_conn)


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


@pytest.fixture
def stub():
    broker = StubBroker()
    yield broker
    broker.close()


def launcher(runner_sessionmaker, writer, backend, url) -> Launcher:
    return Launcher(sessionmaker=runner_sessionmaker, writer=writer, backend=backend, catalog=CATALOG,
                    config=SandboxConfig(image="clw-task:phase1", broker_url=url))


async def test_real_task_receives_inactive_days_and_its_result_is_stored(runner_sessionmaker, admin_conn, tenant,
                                                                         stub):
    writer = AuditWriter(runner_sessionmaker)
    run_id = await queue_run(admin_conn, writer, tenant, params={"inactive_days": 30})
    backend = SubprocessBackend()

    outcome = await launcher(runner_sessionmaker, writer, backend, stub.url).run_once()

    assert (outcome.status, outcome.reason) == ("completed", "succeeded")
    assert set(backend.started[0]["environment"]) == {"CLW_RUN_TOKEN", "CLW_BROKER_URL"}
    row = await run_row(admin_conn, run_id)
    result = json.loads(row["result"])
    assert result["inactive_days"] == 30
    assert [u["id"] for u in result["dormant"]] == ["u-45"] and result["counts"]["active"] == 1
    # The task sent only {op, params}, with the token the launcher minted.
    ((path, authorization, sent),) = stub.requests
    token = backend.started[0]["environment"]["CLW_RUN_TOKEN"]
    assert path == "/v1/ops" and authorization == f"RunToken {token}"
    assert set(sent) == {"op", "params"} and sent["op"] == "users.list_with_sign_in_activity"
    assert row["run_token_sha256"] is None
    async with runner_sessionmaker() as session:
        completed = [r for r in await load_chain(session, chain_id=tenant[0]) if r.run_id == run_id][-1]
    assert verify_run_result(completed, result) == "ok"


async def test_real_task_refused_by_the_broker_leaves_no_result(runner_sessionmaker, admin_conn, tenant):
    writer = AuditWriter(runner_sessionmaker)
    run_id = await queue_run(admin_conn, writer, tenant)
    broker = StubBroker(status=403, reply={"status": "denied", "reason": "not_in_manifest"})
    try:
        outcome = await launcher(runner_sessionmaker, writer, SubprocessBackend(), broker.url).run_once()
    finally:
        broker.close()
    assert (outcome.status, outcome.reason) == ("failed", "task_error")
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"]) == ("failed", "task_error", None)
