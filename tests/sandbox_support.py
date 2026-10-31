"""Shared helpers for the Docker sandbox tests (Task 15).

Plain functions (not fixtures) so both tests/sandbox/ and the DB-backed
timeout test in tests/db/ can use them. They need a real Docker daemon; the
callers are marked `sandbox`. Containers run with the SAME kwargs the runner
builds (`clw.runner.sandbox_spec.sandbox_container_kwargs`), so the tests
exercise the real enforcement path, only overriding the command to drive the
probe.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from clw.broker.manifest import TaskManifest, load_manifest
from clw.runner.sandbox_spec import SandboxConfig, sandbox_container_kwargs

REPO = Path(__file__).resolve().parents[1]
PROBE_IMAGE = "clw-task-probe:test"
PROBE_DOCKERFILE = "docker/task-probe.Dockerfile"
TASK_NETWORK = "clw_tasknet"
BROKER_ALIAS = "broker"
BROKER_URL = f"http://{BROKER_ALIAS}:8080"
PROBE_MANIFEST = load_manifest(REPO / "tests" / "fixtures" / "tasks" / "escape_probe" / "manifest.yaml")
# The container runtime under test (SD-044): CLW_TASK_RUNTIME=runsc runs every
# sandbox suite under gVisor; unset, Docker's default runtime.
RUNTIME = os.environ.get("CLW_TASK_RUNTIME") or None
# A token of the issued shape (43 url-safe chars); never a real token.
FAKE_TOKEN = "A" * 20 + "_-" + "b" * 21


class DockerUnavailable(Exception):
    """A real Docker daemon is not reachable."""


def docker_client():
    try:
        import docker
    except ImportError as exc:  # pragma: no cover
        raise DockerUnavailable("docker SDK not installed") from exc
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        raise DockerUnavailable(str(exc)) from exc
    return client


def ensure_probe_image(client) -> None:
    import docker

    try:
        client.images.get(PROBE_IMAGE)
        return
    except docker.errors.ImageNotFound:
        pass
    client.images.build(path=str(REPO), dockerfile=PROBE_DOCKERFILE, tag=PROBE_IMAGE, rm=True)


def ensure_network(client):
    import docker

    try:
        return client.networks.get(TASK_NETWORK)
    except docker.errors.NotFound:
        return client.networks.create(TASK_NETWORK, driver="bridge", internal=True)


def start_broker_stub(client):
    """A container on tasknet, resolvable as `broker`, that accepts TCP on 8080.
    It is the positive control: the task CAN reach the broker endpoint."""
    remove_named(client, "clw-probe-brokerstub")
    stub = client.containers.create(
        PROBE_IMAGE, command=["python", "-m", "http.server", "8080"],
        name="clw-probe-brokerstub", detach=True, user="10001:10001")
    ensure_network(client).connect(stub, aliases=[BROKER_ALIAS])
    stub.start()
    return stub


def remove_named(client, name: str) -> None:
    for container in client.containers.list(all=True, filters={"name": name}):
        container.remove(force=True)


def probe_kwargs(command: list[str], *, peer: str, image: str = PROBE_IMAGE, broker_url: str = BROKER_URL,
                 manifest: TaskManifest = PROBE_MANIFEST) -> dict:
    run = SimpleNamespace(id=uuid.uuid4(), task_id=manifest.id, params={})
    kwargs = sandbox_container_kwargs(run, FAKE_TOKEN, manifest=manifest,
                                      config=SandboxConfig(image=image, broker_url=broker_url, runtime=RUNTIME),
                                      peer=peer)
    kwargs["command"] = command
    kwargs["name"] = f"clw-probe-{run.id}"
    return kwargs


@dataclass
class ProbeOutcome:
    exit_code: int
    report: dict
    host_config: dict
    config: dict
    networks: list[str]


def run_probe(client, *, command=("python", "-m", "tasks.escape_probe.task", "--attempts"),
              broker_url: str = BROKER_URL, timeout: int = 120) -> ProbeOutcome:
    from clw.runner.backend import DockerBackend

    # The runner's own lookup of the broker stub (SD-044): its name reaches the
    # probe through the hosts file, as in a real run.
    peer = DockerBackend(client).peer_address(TASK_NETWORK, BROKER_ALIAS)
    assert peer is not None, "the broker stub is not on tasknet"
    kwargs = probe_kwargs(list(command), peer=peer, broker_url=broker_url)
    remove_named(client, kwargs["name"])
    container = client.containers.run(**kwargs)
    try:
        status = container.wait(timeout=timeout)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        container.reload()
        report: dict = {}
        for line in stdout.splitlines():
            if line.startswith("CLW_PROBE "):
                report = json.loads(line[len("CLW_PROBE "):])
        return ProbeOutcome(
            exit_code=int(status["StatusCode"]),
            report=report,
            host_config=container.attrs["HostConfig"],
            config=container.attrs["Config"],
            networks=list(container.attrs["NetworkSettings"]["Networks"]),
        )
    finally:
        container.remove(force=True)
