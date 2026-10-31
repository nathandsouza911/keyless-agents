"""The runner kills a real over-running container and the token dies (Task 15).

Needs Docker AND Postgres. This is the one sandbox test that drives the real
DockerBackend through the real launcher against the real audit chain: the
probe image sleeps past its 10 s deadline, and the test proves the container
is killed near the deadline (not after the sleep), RUN_TIMED_OUT is audited,
the container is removed, and the run token no longer resolves at the broker
(the two enforcement points of threat-model §7.1). Skips, never passes, if
Docker is unavailable.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from clw.audit.events import EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.broker.capability import RunRefused, resolve_run
from clw.runner.launcher import Launcher
from clw.runner.sandbox_spec import SandboxConfig
from tests.db.broker_fixtures import add_tenant, run_row
from tests.db.runner_fixtures import end_stray_queued_runs, queue_run
from tests.sandbox_support import (
    BROKER_URL, PROBE_IMAGE, PROBE_MANIFEST, RUNTIME, DockerUnavailable, docker_client, ensure_network,
    ensure_probe_image, remove_named, start_broker_stub,
)

# sandbox only (not pg): it needs Docker AND Postgres, but marking it pg would
# pull Docker into the Docker-free pg job. The sandbox CI job has Postgres.
pytestmark = pytest.mark.sandbox

CATALOG = {PROBE_MANIFEST.id: PROBE_MANIFEST}


@pytest.fixture(scope="session")
def docker_env():
    try:
        client = docker_client()
    except DockerUnavailable as exc:
        pytest.skip(f"Docker daemon not reachable: {exc}")
    ensure_probe_image(client)
    ensure_network(client)
    # The launcher starts a task only if exactly one broker is on tasknet (SD-044).
    start_broker_stub(client)
    try:
        yield client
    finally:
        # By name: the sandbox tests' fixture starts the same stub.
        remove_named(client, "clw-probe-brokerstub")


@pytest.fixture(autouse=True)
async def _no_stray_queued_runs(admin_conn):
    await end_stray_queued_runs(admin_conn)


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


async def test_over_running_container_is_killed_timed_out_and_the_token_dies(
        runner_sessionmaker, admin_conn, tenant, docker_env, monkeypatch):
    from clw.runner import launcher as launcher_module

    client = docker_env
    tid = tenant[0]
    writer = AuditWriter(runner_sessionmaker)
    run_id = await queue_run(admin_conn, writer, tenant, manifest=PROBE_MANIFEST, params={})

    # Capture the token the launcher mints (it only stores the hash).
    minted = {}
    real_issue = launcher_module.issue_run_token

    def capture():
        issued = real_issue()
        minted["token"] = issued.token
        return issued

    monkeypatch.setattr(launcher_module, "issue_run_token", capture)

    from clw.runner.backend import DockerBackend

    launcher = Launcher(sessionmaker=runner_sessionmaker, writer=writer, backend=DockerBackend(client),
                        catalog=CATALOG, config=SandboxConfig(image=PROBE_IMAGE, broker_url=BROKER_URL, runtime=RUNTIME))

    started = time.monotonic()
    outcome = await launcher.run_once()
    elapsed = time.monotonic() - started

    assert (outcome.status, outcome.reason) == ("timed_out", "timeout")
    # Killed near the 10 s deadline, well before the probe's 60 s sleep.
    assert 8 <= elapsed < 45, elapsed

    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"], row["run_token_sha256"]) == (
        "timed_out", "timeout", None, None)

    records = [r for r in await load_records(runner_sessionmaker, tid) if r.run_id == run_id]
    assert [r.event_type for r in records][-1] == EventType.RUN_TIMED_OUT
    async with runner_sessionmaker() as session:
        assert (await verify_chain(session, chain_id=tid)).valid

    # The container is gone (cleanup fails safe).
    assert client.containers.list(all=True, filters={"label": f"clw.run_id={run_id}"}) == []

    # Second enforcement point: the broker refuses the (now revoked) token.
    async with runner_sessionmaker() as session:
        with pytest.raises(RunRefused) as refused:
            await resolve_run(session, minted["token"], catalog=CATALOG, now=datetime.now(timezone.utc))
    assert refused.value.reason in ("run_token_invalid", "run_not_running")


async def load_records(sessionmaker, tid):
    async with sessionmaker() as session:
        return await load_chain(session, chain_id=tid)
