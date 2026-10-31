"""The script-run sandbox's configuration and output parsing (SD-044), without Docker."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from clw.runner.analyser import analyser_container_kwargs
from clw.runner.result import BOOTSTRAP_EXIT_CODE, ResultRejected, bootstrap_refusal, parse_script_output
from clw.runner.sandbox_spec import (BOOTSTRAP, MAX_SCRIPT_OUTPUT_BYTES, SandboxConfig, ScriptSandboxConfig,
                                     bootstrap_sha256, sandbox_container_kwargs, script_container_kwargs)
from tests.db.broker_fixtures import MANIFEST

TOKEN = "A" * 20 + "_-" + "b" * 21
SHA = "a" * 64


def script_run():
    return SimpleNamespace(kind="script", id=uuid.uuid4())


def kwargs(**overrides):
    args = {"script_sha256": SHA, "bootstrap": "b" * 64, "peer": "172.31.0.2", "config": ScriptSandboxConfig(image="clw-task-pwsh:m5", broker_url="https://graph.microsoft.com")}
    return script_container_kwargs(script_run(), TOKEN, **{**args, **overrides})


def test_the_script_container_gets_only_the_two_variables_and_no_mounts():
    k = kwargs()
    assert k["environment"] == {"CLW_RUN_TOKEN": TOKEN, "CLW_BROKER_URL": "https://graph.microsoft.com"}
    assert k["network"] == "clw_scriptnet" and k["command"] == [SHA, "b" * 64]
    assert not {"volumes", "mounts", "devices", "ports", "runtime", "dns"} & set(k)
    assert k["extra_hosts"] == {"graph.microsoft.com": "172.31.0.2"}  # the facade proxy, looked up at launch
    assert k["read_only"] and k["privileged"] is False and k["cap_drop"] == ["ALL"]
    assert k["mem_limit"] == k["memswap_limit"] == "512m" and k["pids_limit"] == 64


@pytest.mark.parametrize("overrides", [{"script_sha256": "A" * 64}, {"bootstrap": "b" * 63},
                                       {"script_sha256": SHA + "\n"}])
def test_digests_must_be_lowercase_hex(overrides):
    with pytest.raises(ValueError):
        kwargs(**overrides)


def test_only_a_script_run_gets_the_script_sandbox():
    with pytest.raises(ValueError):
        script_container_kwargs(SimpleNamespace(kind="task", id=uuid.uuid4()), TOKEN, script_sha256=SHA,
                                bootstrap=SHA, config=ScriptSandboxConfig(image="clw-task-pwsh:m5", broker_url="https://graph.microsoft.com"),
                                peer="172.31.0.2")


def test_the_runtime_applies_to_every_container_kind():
    task = sandbox_container_kwargs(SimpleNamespace(id=uuid.uuid4(), task_id=MANIFEST.id, params={}), TOKEN,
                                    manifest=MANIFEST, config=SandboxConfig(image="clw-task:phase1",
                                                                            broker_url="http://broker:8080",
                                                                            runtime="runsc"), peer="172.30.0.2")
    script = kwargs(config=ScriptSandboxConfig(image="clw-task-pwsh:m5", broker_url="https://graph.microsoft.com", runtime="runsc"))
    analysis = analyser_container_kwargs("x", image="clw-analyser:m4", runtime="runsc")
    assert task["runtime"] == script["runtime"] == analysis["runtime"] == "runsc"
    # gVisor does not apply the PID limit inside the sandbox; RLIMIT_NPROC holds under both runtimes.
    assert task["ulimits"] == script["ulimits"] == analysis["ulimits"] == [{"Name": "nproc", "Soft": 64, "Hard": 64}]


@pytest.mark.parametrize("runtime", ["", "runsc --debug", "../runsc", "RUNSC", "a" * 40])
def test_a_runtime_is_a_plain_name(runtime):
    with pytest.raises(ValueError):
        ScriptSandboxConfig(image="clw-task-pwsh:m5", broker_url="https://graph.microsoft.com", runtime=runtime)


def test_the_bootstrap_digest_is_of_the_file_the_image_is_built_from():
    import hashlib
    assert bootstrap_sha256() == hashlib.sha256(BOOTSTRAP.read_bytes()).hexdigest()
    assert b"\r\n" not in BOOTSTRAP.read_bytes()  # LF only, so every checkout hashes the same (.gitattributes)


# ------------------------------------------------------------------ output


def test_the_output_is_everything_before_the_bootstraps_last_line():
    value = parse_script_output(b"line 1\nCLW_SCRIPT_EXIT 0 (looks like one)\nline 3\nCLW_SCRIPT_EXIT 2\n").value
    assert value == {"kind": "script_output", "script_exit_code": 2,
                     "output": "line 1\nCLW_SCRIPT_EXIT 0 (looks like one)\nline 3\n"}


@pytest.mark.parametrize("stdout", [b"", b"report\n", b"CLW_SCRIPT_EXIT 0", b"CLW_SCRIPT_EXIT 0\nmore\n",
                                    b"CLW_SCRIPT_EXIT 01\n", b"CLW_SCRIPT_EXIT x\n", b"CLW_SCRIPT_EXIT 0\r\n"])
def test_without_the_closing_line_there_is_no_result(stdout):
    with pytest.raises(ResultRejected) as exc:
        parse_script_output(stdout)
    assert exc.value.reason == "result_missing"


def test_undecodable_bytes_and_nul_survive_as_replacement_characters():
    value = parse_script_output(b"a" + bytes([0]) + b"b\xff\nCLW_SCRIPT_EXIT 0\n").value
    assert value["output"] == "a�b�\n"


def test_output_over_the_limit_is_refused():
    with pytest.raises(ResultRejected) as exc:
        parse_script_output(b"x" * MAX_SCRIPT_OUTPUT_BYTES + b"\nCLW_SCRIPT_EXIT 0\n")
    assert exc.value.reason == "result_too_large"


@pytest.mark.parametrize("exit_code, stdout, reason", [
    (BOOTSTRAP_EXIT_CODE, b"CLW_BOOTSTRAP_FAILED script_digest_mismatch\n", "script_digest_mismatch"),
    (BOOTSTRAP_EXIT_CODE, b"CLW_BOOTSTRAP_FAILED not_a_reason\n", None),
    (BOOTSTRAP_EXIT_CODE, b"output\nCLW_BOOTSTRAP_FAILED script_digest_mismatch\n", None),  # a script printed it
    (1, b"CLW_BOOTSTRAP_FAILED script_digest_mismatch\n", None),
])
def test_only_the_bootstraps_own_refusal_is_one(exit_code, stdout, reason):
    assert bootstrap_refusal(exit_code, stdout) == reason


@pytest.mark.parametrize("url", ["http://graph.microsoft.com", "https://graph.microsoft.com/v1.0", "https://", ""])
def test_the_script_broker_url_is_an_https_origin(url):
    with pytest.raises(ValueError):
        ScriptSandboxConfig(image="clw-task-pwsh:m5", broker_url=url)
