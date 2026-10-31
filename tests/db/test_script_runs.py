"""Launching script runs against Postgres (SD-044): the runner configured for
the PowerShell sandbox starts an approved script run with the script on
stdin, records its bootstrap, and stores the script's output; a run whose
approval no longer binds it starts nothing. The container is a fake; the
real image is tests/sandbox/test_task_pwsh.py."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta

import pytest

from clw.audit.events import EventType
from clw.audit.writer import AuditWriter
from clw.runner.catalog import load_task_catalog
from clw.runner.launcher import Launcher
from clw.runner.sandbox_spec import (MAX_SCRIPT_OUTPUT_BYTES, SCRIPT_NETWORK, SCRIPT_TIMEOUT_SECONDS,
                                     SandboxConfig, ScriptSandboxConfig)
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.runner_fixtures import FakeBackend, FakeProcess
from tests.db.test_scripts import SCRIPT, _analysed, approve, chain, client, org  # noqa: F401 (fixture)

pytestmark = pytest.mark.pg

BOOTSTRAP = "b" * 64


def launcher(org, backend, *, scripts=True):
    maker = org["runner_maker"]
    return Launcher(sessionmaker=maker, writer=AuditWriter(maker), backend=backend, catalog=load_task_catalog(),
                    config=SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080"),
                    script_config=ScriptSandboxConfig(image="clw-task-pwsh:test", broker_url="https://graph.microsoft.com") if scripts else None,
                    bootstrap_sha256=BOOTSTRAP if scripts else None)


@pytest.fixture
async def queued(org, admin_conn):
    """An approved script and its queued run, alone in the queue."""
    sha, proposed = await _analysed(org)
    await approve(org, sha, proposed)
    async with client(org["app"]) as c:
        run_id = (await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])).json()["id"]
    # The launcher claims the oldest queued run of any tenant: close earlier tests' leftovers first.
    await admin_conn.execute("UPDATE runs SET status = 'failed', outcome = 'test_cleanup', run_token_sha256 = NULL, ended_at = now() "
                             "WHERE status = 'queued' AND id <> $1", uuid.UUID(run_id))
    return {"run_id": run_id, "sha": sha}


async def run_row(admin_conn, run_id):
    return await admin_conn.fetchrow("SELECT status, outcome, result, started_at, deadline_at FROM runs WHERE id = $1",
                                     uuid.UUID(run_id))


async def test_an_approved_script_run_starts_in_the_script_sandbox_with_the_script_on_stdin(
        org, queued, admin_conn, sessionmaker):
    backend = FakeBackend(FakeProcess([b"two users\n", b"CLW_SCRIPT_EXIT 0\n"]))
    outcome = await launcher(org, backend).run_once()
    assert (outcome.status, outcome.reason) == ("completed", "succeeded")

    (kwargs,), (stdin,) = backend.started, backend.stdin
    assert stdin == SCRIPT.encode("utf-8") and hashlib.sha256(stdin).hexdigest() == queued["sha"]
    assert kwargs["command"] == [queued["sha"], BOOTSTRAP] and kwargs["stdin_open"] is True
    assert kwargs["network"] == SCRIPT_NETWORK and kwargs["image"] == "clw-task-pwsh:test"
    # The facade proxy by its looked-up address, not through Docker's DNS (gVisor; SD-044).
    assert backend.peer_lookups == [(SCRIPT_NETWORK, "graph.microsoft.com")]
    assert kwargs["extra_hosts"] == {"graph.microsoft.com": "172.30.0.2"}
    assert set(kwargs["environment"]) == {"CLW_RUN_TOKEN", "CLW_BROKER_URL"}
    assert kwargs["environment"]["CLW_BROKER_URL"] == "https://graph.microsoft.com"
    assert kwargs["read_only"] and kwargs["cap_drop"] == ["ALL"] and kwargs["user"] == "10006:10006"
    assert not {"volumes", "mounts", "devices", "ports", "privileged"} & {k for k, v in kwargs.items() if v}

    row = await run_row(admin_conn, queued["run_id"])
    assert row["status"] == "completed"
    assert row["deadline_at"] - row["started_at"] == pytest.approx(timedelta(seconds=SCRIPT_TIMEOUT_SECONDS),
                                                                   abs=timedelta(seconds=5))
    assert json.loads(row["result"]) == {"kind": "script_output", "script_exit_code": 0, "output": "two users\n"}

    records, report = await chain(sessionmaker, org["tid"])
    started = next(r for r in records if r.event_type == EventType.RUN_STARTED and r.run_id == queued["run_id"])
    approval_id = next(r for r in records if r.event_type == EventType.MANIFEST_APPROVED).details["approval_id"]
    assert started.details == {"script_sha256": queued["sha"], "approval_id": approval_id, "bootstrap_sha256": BOOTSTRAP}
    assert records[-1].event_type == EventType.RUN_COMPLETED and report.valid, report


async def test_the_script_exit_code_is_the_scripts_outcome_not_the_runs(org, queued, admin_conn):
    backend = FakeBackend(FakeProcess([b"ERROR: Cloud Locksmith: denied\n", b"CLW_SCRIPT_EXIT 1\n"]))
    assert (await launcher(org, backend).run_once()).status == "completed"
    result = json.loads((await run_row(admin_conn, queued["run_id"]))["result"])
    assert result["script_exit_code"] == 1 and "denied" in result["output"]


@pytest.mark.parametrize("process, reason", [
    (FakeProcess([b"CLW_BOOTSTRAP_FAILED script_digest_mismatch\n"], exit_code=70), "script_digest_mismatch"),
    (FakeProcess([b"CLW_BOOTSTRAP_FAILED bootstrap_mismatch\n"], exit_code=70), "bootstrap_mismatch"),
    (FakeProcess([b"half a report\n"]), "result_missing"),            # the bootstrap never finished
    (FakeProcess([b"CLW_SCRIPT_EXIT 0\n"], exit_code=137), "task_error"),
    (FakeProcess([b"CLW_BOOTSTRAP_FAILED made_up_reason\n"], exit_code=70), "task_error"),
    (FakeProcess([b"x" * (MAX_SCRIPT_OUTPUT_BYTES + 1)], hang=True), "result_too_large"),
], ids=["digest", "bootstrap", "unfinished", "killed", "unknown-refusal", "too-much-output"])
async def test_a_script_run_that_does_not_finish_cleanly_fails_with_its_reason(org, queued, admin_conn, process, reason):
    outcome = await launcher(org, FakeBackend(process)).run_once()
    row = await run_row(admin_conn, queued["run_id"])
    assert (outcome.status, outcome.reason) == ("failed", reason) == (row["status"], row["outcome"])
    assert row["result"] is None
    if process.hang:  # too much output: killed as soon as it passed the limit, not left to run
        assert process.kill_calls == 1


async def test_a_run_whose_script_no_longer_matches_its_approval_starts_nothing(org, queued, admin_conn):
    # A database writer that bypasses the immutability trigger edits the approved script.
    await admin_conn.execute("ALTER TABLE scripts DISABLE TRIGGER scripts_guard_update")
    try:
        await admin_conn.execute("UPDATE scripts SET text = text || '# edited' WHERE sha256 = $1", queued["sha"])
    finally:
        await admin_conn.execute("ALTER TABLE scripts ENABLE TRIGGER scripts_guard_update")
    backend = FakeBackend()
    outcome = await launcher(org, backend).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "approval_invalid")
    assert backend.started == [] and (await run_row(admin_conn, queued["run_id"]))["started_at"] is None


async def test_a_run_whose_approval_was_tampered_with_starts_nothing(org, queued, admin_conn):
    await admin_conn.execute("ALTER TABLE script_approvals DISABLE TRIGGER script_approvals_guard_update")
    try:
        await admin_conn.execute("UPDATE script_approvals SET manifest = jsonb_set(manifest, '{entries,0,top}', '999') "
                                 "WHERE script_sha256 = $1", queued["sha"])
    finally:
        await admin_conn.execute("ALTER TABLE script_approvals ENABLE TRIGGER script_approvals_guard_update")
    backend = FakeBackend()
    assert (await launcher(org, backend).run_once()).reason == "approval_invalid"
    assert backend.started == []


async def test_without_exactly_one_facade_proxy_nothing_starts(org, queued, admin_conn):
    backend = FakeBackend(peer=None)
    outcome = await launcher(org, backend).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "peer_unavailable") and backend.started == []
    assert (await run_row(admin_conn, queued["run_id"]))["outcome"] == "peer_unavailable"


async def test_without_the_script_sandbox_the_run_stays_queued(org, queued, admin_conn):
    assert await launcher(org, FakeBackend(), scripts=False).run_once() is None
    assert (await run_row(admin_conn, queued["run_id"]))["status"] == "queued"


def test_script_runs_need_both_the_sandbox_and_the_bootstrap_digest():
    with pytest.raises(ValueError):
        Launcher(sessionmaker=None, writer=None, backend=None, catalog={},
                 config=SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080"),
                 script_config=ScriptSandboxConfig(image="clw-task-pwsh:test", broker_url="https://graph.microsoft.com"))
