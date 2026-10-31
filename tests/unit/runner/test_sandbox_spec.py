"""Task container configuration (Task 14; SD-008; threat-model §7.1). Pure; no Docker."""

from __future__ import annotations

import dataclasses
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from clw.broker.manifest import ParamSpec, load_manifest
from clw.runner.catalog import load_task_catalog
from clw.runner.sandbox_spec import (
    MAX_RESULT_BYTES, TASK_ENV_KEYS, InvalidRunParams, SandboxConfig, sandbox_container_kwargs, task_arguments,
    task_module,
)

REPO = Path(__file__).resolve().parents[3]
MANIFEST = load_manifest(REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml")
CONFIG = SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080")
TOKEN = "A" * 20 + "_-" + "b" * 21
PEER = "172.30.0.2"
RUN_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def run(params=None, task_id=MANIFEST.id):
    return SimpleNamespace(id=RUN_ID, task_id=task_id, params={"inactive_days": 90} if params is None else params)


def spec(**kwargs):
    return sandbox_container_kwargs(run(**kwargs), TOKEN, manifest=MANIFEST, config=CONFIG, peer=PEER)


def test_sandbox_limits_and_isolation():
    k = spec()
    assert k["network"] == "clw_tasknet"
    assert k["read_only"] is True and k["privileged"] is False
    assert k["cap_drop"] == ["ALL"] and "no-new-privileges:true" in k["security_opt"]
    assert (k["pids_limit"], k["mem_limit"], k["memswap_limit"], k["nano_cpus"]) == (64, "256m", "256m", 500_000_000)
    assert k["user"] not in ("root", "0", "0:0") and not k["user"].startswith("0:")
    assert k["tmpfs"] == {"/tmp": "rw,noexec,nosuid,nodev,size=16m"}
    for absent in ("volumes", "mounts", "devices", "device_requests", "ports", "network_mode", "pid_mode",
                   "ipc_mode", "userns_mode", "cap_add", "dns", "volumes_from", "links",
                   "auto_remove", "entrypoint", "working_dir", "sysctls"):
        assert absent not in k, absent
    assert "docker.sock" not in repr(k)


def test_the_only_host_entry_is_the_broker_at_its_looked_up_address():
    # The runner's lookup, not the run, supplies the address (SD-044); nothing else is added.
    assert spec()["extra_hosts"] == {"broker": PEER}


@pytest.mark.parametrize("peer", ["broker", "", "172.30.0.2 evil", "172.30.0.256", None, "::1/128"])
def test_the_peer_must_be_an_ip_address(peer):
    with pytest.raises(ValueError):
        sandbox_container_kwargs(run(), TOKEN, manifest=MANIFEST, config=CONFIG, peer=peer)


def test_environment_is_exactly_the_two_keys():
    k = spec()
    assert set(k["environment"]) == TASK_ENV_KEYS == {"CLW_RUN_TOKEN", "CLW_BROKER_URL"}
    assert k["environment"] == {"CLW_RUN_TOKEN": TOKEN, "CLW_BROKER_URL": "http://broker:8080"}


def test_token_appears_only_in_the_environment():
    k = spec()
    rest = {key: value for key, value in k.items() if key != "environment"}
    assert TOKEN not in repr(rest)


def test_command_runs_the_task_module_with_its_params():
    assert spec()["command"] == ["python", "-m", "tasks.dormant_account_investigation.task", "--inactive-days", "90"]
    assert spec(params={"inactive_days": 45})["command"][-2:] == ["--inactive-days", "45"]
    assert spec(params={})["command"][-2:] == ["--inactive-days", "90"]  # the manifest default


def test_labels_and_name_identify_the_run():
    k = spec()
    assert k["labels"] == {"clw.run_id": str(RUN_ID), "clw.task_id": MANIFEST.id}
    assert k["name"] == f"clw-task-{RUN_ID}" and k["detach"] is True


@pytest.mark.parametrize("params", [
    {"inactive_days": 29}, {"inactive_days": 366}, {"inactive_days": True}, {"inactive_days": "90"},
    {"inactive_days": 90.0}, {"inactive_days": None}, {"inactive_days": [90]},
    {"inactive_days": 90, "broker_url": "http://evil"}, {"CLW_RUN_TOKEN": "x"}, {"image": "evil"},
    {"inactive_days": 90, "--broker": 1}, {"tenant_id": "t"}, [], "inactive_days=90", None,
])
def test_params_cannot_shape_the_container(params):
    with pytest.raises((InvalidRunParams, ValueError)):
        sandbox_container_kwargs(SimpleNamespace(id=RUN_ID, task_id=MANIFEST.id, params=params), TOKEN,
                                 manifest=MANIFEST, config=CONFIG, peer=PEER)


def test_required_param_without_default_is_refused():
    manifest = dataclasses.replace(MANIFEST, params={"inactive_days": ParamSpec("integer", 30, 365, None)})
    with pytest.raises(InvalidRunParams):
        task_arguments(manifest, {})
    assert task_arguments(manifest, {"inactive_days": 30}) == ["--inactive-days", "30"]


def test_bool_is_not_an_integer_even_within_bounds():
    manifest = dataclasses.replace(MANIFEST, params={"inactive_days": ParamSpec("integer", 0, 5, None)})
    for value in (True, False):
        with pytest.raises(InvalidRunParams):
            task_arguments(manifest, {"inactive_days": value})
    assert task_arguments(manifest, {"inactive_days": 1}) == ["--inactive-days", "1"]


def test_invalid_param_messages_carry_no_values():
    with pytest.raises(InvalidRunParams) as caught:
        task_arguments(MANIFEST, {"inactive_days": 90, "secret-looking-value": "zzz-sentinel"})
    assert "zzz-sentinel" not in str(caught.value) and "secret-looking-value" not in str(caught.value)


def test_manifest_must_be_the_runs():
    with pytest.raises(ValueError):
        sandbox_container_kwargs(run(task_id="other-task"), TOKEN, manifest=MANIFEST, config=CONFIG, peer=PEER)


@pytest.mark.parametrize("token", ["", "short", TOKEN + "x", TOKEN[:-1] + "\n", TOKEN[:-1] + " ", None])
def test_token_shape_is_checked(token):
    with pytest.raises(ValueError):
        sandbox_container_kwargs(run(), token, manifest=MANIFEST, config=CONFIG, peer=PEER)


@pytest.mark.parametrize("task_id", ["../etc", "tasks.x", "a/b", "A-B", "-x", "x y", "", "x" * 65, None])
def test_task_id_must_be_a_plain_name(task_id):
    with pytest.raises(ValueError):
        task_module(task_id)


@pytest.mark.parametrize("url", ["http://broker:8080/v1", "http://u:p@broker", "ftp://broker", "broker:8080",
                                 "http://broker?x=1", "http://broker\n", ""])
def test_broker_url_config_is_a_bare_origin(url):
    with pytest.raises(ValueError):
        SandboxConfig(image="clw-task:phase1", broker_url=url)


@pytest.mark.parametrize("image", ["", "--privileged", "clw task", "Clw-Task", "clw-task:x;rm", "../img"])
def test_image_config_is_a_plain_reference(image):
    with pytest.raises(ValueError):
        SandboxConfig(image=image, broker_url="http://broker:8080")


def test_result_limit_is_five_mebibytes():
    assert MAX_RESULT_BYTES == 5 * 1024 * 1024


# ------------------------------------------------------------ catalog


def test_catalog_has_the_dormant_task():
    catalog = load_task_catalog()
    assert set(catalog) == {MANIFEST.id} and catalog[MANIFEST.id].sha256 == MANIFEST.sha256


def _task_dir(root: Path, name: str, manifest_text: str, *, task_py: bool = True) -> None:
    directory = root / name
    directory.mkdir()
    (directory / "manifest.yaml").write_text(manifest_text, encoding="utf-8")
    if task_py:
        (directory / "task.py").write_text("", encoding="utf-8")


def test_catalog_refuses_a_directory_that_is_not_the_tasks_module(tmp_path):
    text = (REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml").read_text(encoding="utf-8")
    _task_dir(tmp_path, "somewhere_else", text)
    with pytest.raises(RuntimeError):
        load_task_catalog(tmp_path)


def test_catalog_refuses_a_task_without_task_py(tmp_path):
    text = (REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml").read_text(encoding="utf-8")
    _task_dir(tmp_path, "dormant_account_investigation", text, task_py=False)
    with pytest.raises(RuntimeError):
        load_task_catalog(tmp_path)
