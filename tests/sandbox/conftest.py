"""Fixtures for the Docker sandbox tests (Task 15).

If a real Docker daemon is not reachable the tests SKIP with the reason, so a
missing daemon is never reported as a pass (the plan's source of truth for
these properties is CI on Linux). The probe image is built once, the internal
network and the broker stub come up once, and the escape probe runs once; the
tests assert on that one structured report plus the container's inspected
host config.
"""

from __future__ import annotations

import pytest

from tests.sandbox_support import (
    DockerUnavailable, docker_client, ensure_network, ensure_probe_image, remove_named, run_probe, start_broker_stub,
)

pytestmark = pytest.mark.sandbox


@pytest.fixture(scope="session")
def client():
    try:
        return docker_client()
    except DockerUnavailable as exc:
        pytest.skip(f"Docker daemon not reachable: {exc}")


@pytest.fixture(scope="session")
def sandbox_ready(client):
    ensure_probe_image(client)
    ensure_network(client)
    start_broker_stub(client)
    try:
        yield client
    finally:
        # By name: the sandbox timeout test (tests/db) starts the same stub.
        remove_named(client, "clw-probe-brokerstub")


@pytest.fixture(scope="session")
def probe(sandbox_ready):
    """The escape probe, run once under the real sandbox kwargs."""
    outcome = run_probe(sandbox_ready)
    assert outcome.report, "the probe produced no CLW_PROBE report line"
    return outcome
