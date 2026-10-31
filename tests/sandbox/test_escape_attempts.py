"""Prove the task sandbox blocks escapes (Task 15; SD-008; threat-model §7).

These run the escape probe inside a container built with the runner's real
sandbox kwargs, against an `internal` Docker network, and assert every
attempt the probe made failed. They test the enforcement (the probe actually
tries each thing and reports the OS-level failure), not configuration
strings; the inspected host config is checked only for the two limits that
cannot be driven to a deterministic failure here (memory, CPU), which are
stated as such.
"""

from __future__ import annotations

import pytest

from tests.sandbox_support import probe_kwargs, remove_named

pytestmark = pytest.mark.sandbox


# ---------------------------------------------------------------- network egress


def test_task_cannot_reach_graph_directly(probe):
    graph_dns = probe.report["connect"]["graph_dns"]
    graph_tcp = probe.report["connect"]["graph_tcp"]
    assert "resolved" not in graph_dns, graph_dns  # name resolution failed
    assert "connected" not in graph_tcp, graph_tcp


def test_task_cannot_reach_raw_ip(probe):
    raw = probe.report["connect"]["raw_ip"]
    assert "connected" not in raw, raw  # no route off the internal network


def test_task_can_reach_the_broker_endpoint(probe):
    # Positive control: the one permitted peer on tasknet is reachable.
    broker = probe.report["connect"]["broker"]
    assert broker.get("connected") is True, broker


def test_subprocess_cannot_call_graph(probe):
    # curl is in the probe image on purpose; a subprocess has no route either.
    graph = probe.report["subprocess_curl"]["graph"]
    raw = probe.report["subprocess_curl"]["raw_ip"]
    assert graph["available"] is True  # curl really is present
    assert graph["exit_code"] != 0, graph
    assert raw["exit_code"] != 0, raw


# ---------------------------------------------------------------- credentials and secrets


def test_task_env_has_no_secrets(probe):
    env = probe.report["env"]
    assert env["secrets_present"] == [], env["secrets_present"]
    keys = set(env["keys"])
    assert {"CLW_RUN_TOKEN", "CLW_BROKER_URL"} <= keys
    # Beyond the two the runner injects, only Docker/base infra vars may appear;
    # none carries a secret (asserted above). The runner injecting exactly the
    # two keys is covered deterministically in tests/unit/runner/test_sandbox_spec.py.
    assert keys <= {"CLW_RUN_TOKEN", "CLW_BROKER_URL", "PATH", "HOME", "HOSTNAME", "LC_CTYPE", "LANG", "TERM"}


def test_task_cannot_read_profile_keys(probe):
    secrets = probe.report["secrets"]
    assert secrets["paths_found"] == [], secrets["paths_found"]
    assert secrets["run_secrets"] in ({}, {"entries": []}), secrets["run_secrets"]


def test_task_cannot_see_broker_processes(probe):
    proc = probe.report["proc"]
    assert proc["broker_seen"] is False, proc["cmdlines"]
    # Its own PID namespace: only the probe's own process tree is visible.
    assert proc["pid_count"] <= 5, proc


# ---------------------------------------------------------------- filesystem, user, capabilities


def test_rootfs_read_only(probe):
    rootfs = probe.report["rootfs"]
    assert rootfs.get("is_erofs") is True, rootfs  # errno 30, EROFS


def test_tmp_is_writable(probe):
    assert probe.report["tmp"].get("writable") is True


def test_tmp_is_noexec(probe):
    # Writable, but a script there cannot be executed (noexec tmpfs).
    noexec = probe.report["tmp_noexec"]
    assert "executed" not in noexec, noexec


def test_task_runs_as_non_root(probe):
    assert probe.report["uid"] == 10001, probe.report["uid"]
    assert probe.config["User"] == "10001:10001"


def test_capabilities_are_dropped(probe):
    # A raw socket needs CAP_NET_RAW, which cap_drop=[ALL] removes.
    raw = probe.report["cap_net_raw"]
    assert "created" not in raw and raw.get("error") == "PermissionError", raw
    assert probe.host_config["CapDrop"] == ["ALL"]


def test_privilege_escalation_is_blocked(probe):
    setuid = probe.report["setuid_root"]
    assert "became_root" not in setuid and setuid.get("error") == "PermissionError", setuid
    assert any("no-new-privileges" in opt for opt in probe.host_config["SecurityOpt"])


# ---------------------------------------------------------------- resource limits


def test_pid_limit_is_enforced(probe):
    pids = probe.report["pids"]
    assert pids["hit_limit"] is True, pids  # could not start the full target
    assert pids["threads_started"] < 64, pids  # capped at pids_limit
    assert probe.host_config["PidsLimit"] == 64
    # Under gVisor the PID limit does not bound the sandbox's threads; RLIMIT_NPROC does (SD-044).
    assert {"Name": "nproc", "Soft": 64, "Hard": 64} in probe.host_config["Ulimits"]


def test_memory_and_cpu_limits_are_set(probe):
    # These two are verified by the container's enforced config. Driving them to
    # a deterministic failure (OOM kill / CPU starvation) is not reliable in
    # this environment, so enforcement of mem/cpu is not asserted by attempt.
    assert probe.host_config["Memory"] == 256 * 1024 * 1024
    assert probe.host_config["NanoCpus"] == 500_000_000


def test_root_filesystem_is_read_only_in_config(probe):
    assert probe.host_config["ReadonlyRootfs"] is True


def test_container_is_only_on_the_internal_network(probe):
    assert probe.networks == ["clw_tasknet"], probe.networks


# ---------------------------------------------------------------- startup fails safe


def test_startup_with_an_unknown_image_fails_and_leaks_nothing(sandbox_ready):
    import docker

    client = sandbox_ready
    kwargs = probe_kwargs(["python", "-m", "tasks.escape_probe.task", "--attempts"],
                          peer="127.0.0.1", image="clw-task-probe:does-not-exist")
    kwargs["name"] = "clw-probe-badimage"
    remove_named(client, kwargs["name"])
    with pytest.raises(docker.errors.ImageNotFound):
        client.containers.run(**kwargs)
    # No container was left behind.
    assert client.containers.list(all=True, filters={"name": kwargs["name"]}) == []


def test_the_task_ran_under_the_configured_runtime(probe):
    from tests.sandbox_support import RUNTIME

    # Docker reports the default runtime as runc; with CLW_TASK_RUNTIME=runsc this is gVisor.
    assert probe.host_config["Runtime"] == (RUNTIME or "runc")
