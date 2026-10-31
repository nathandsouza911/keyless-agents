"""The PowerShell task image and its bootstrap, by attempt (SD-044).

Builds docker/task-pwsh.Dockerfile with a throwaway facade CA (the image
trusts it; nothing else does), then runs scripts exactly as the runner
starts them (script_container_kwargs, the script on stdin) on an internal
network where graph.microsoft.com is a small TLS stub serving that CA's
certificate. The stub stands in for the facade proxy: it answers one read
and refuses everything else with a Graph-shaped 403, and logs what reached
it. The real facade's policy is tested in tests/security and tests/db."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

from clw.broker.capability import issue_run_token
from clw.broker.facade.ca import create as create_ca
from clw.runner.backend import DockerBackend
from clw.runner.result import bootstrap_refusal, parse_script_output
from clw.runner.sandbox_spec import ScriptSandboxConfig, bootstrap_sha256, script_container_kwargs
from tests.sandbox_support import RUNTIME

pytestmark = pytest.mark.sandbox

REPO = Path(__file__).resolve().parents[2]
IMAGE = "clw-task-pwsh:sandboxtest"
STUB_IMAGE = "python:3.11-slim"

STUB = r'''
import json, ssl, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def _answer(self):
        print(json.dumps({"method": self.command, "path": self.path,
                          "authorization": self.headers.get("Authorization", "")}), flush=True)
        if self.command == "GET" and self.path.startswith("/v1.0/users"):
            status, body = 200, {"value": [{"id": "1", "displayName": "Ada Test"},
                                           {"id": "2", "displayName": "Grace Test"}]}
        else:
            status, body = 403, {"error": {"code": "Authorization_RequestDenied",
                                           "message": "Cloud Locksmith: not in the approved manifest"}}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    do_GET = do_POST = do_PATCH = do_DELETE = _answer
    def log_message(self, *args):
        pass

server = HTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/stub/leaf.crt", "/stub/leaf.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''


def _tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture(scope="module")
def facade(client, tmp_path_factory):
    ca_dir = tmp_path_factory.mktemp("facade-ca")
    made = create_ca(ca_dir)
    build = subprocess.run(
        ["docker", "build", "-q", "--build-context", f"facade_ca={made.ca_cert.parent}",
         "-f", str(REPO / "docker" / "task-pwsh.Dockerfile"), "-t", IMAGE, str(REPO)],
        capture_output=True, text=True, timeout=900)
    assert build.returncode == 0, build.stderr[-2000:]
    try:
        client.images.get(STUB_IMAGE)
    except Exception:  # noqa: BLE001 - absent on a fresh CI runner
        client.images.pull(STUB_IMAGE)
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"clw_sbx_scriptnet_{suffix}", internal=True)
    stub = client.containers.create(STUB_IMAGE, ["python", "/stub/stub.py"], name=f"clw-sbx-facade-{suffix}",
                                    network=network.name)
    try:
        stub.put_archive("/", _tar({"stub/stub.py": STUB.encode(), "stub/leaf.crt": made.leaf_cert.read_bytes(),
                                    "stub/leaf.key": made.leaf_key.read_bytes()}))
        network.disconnect(stub)
        network.connect(stub, aliases=["graph.microsoft.com"])
        stub.start()
        yield {"client": client, "network": network.name, "stub": stub}
    finally:
        stub.remove(force=True)
        network.remove()


def run_script(facade, text: str, *, script_sha256: str | None = None, bootstrap: str | None = None):
    """Run `text` as a script run: (exit code, stdout, the run token, what reached the stub)."""
    script = text.encode("utf-8")
    token = issue_run_token().token
    run = type("Run", (), {"kind": "script", "id": uuid.uuid4()})()
    backend = DockerBackend(facade["client"])
    # The runner's own lookup (SD-044): the script reaches the stub through its
    # hosts file, never Docker's DNS, so this holds under gVisor too.
    peer = backend.peer_address(facade["network"], "graph.microsoft.com")
    assert peer is not None
    config = ScriptSandboxConfig(image=IMAGE, broker_url="https://graph.microsoft.com", runtime=RUNTIME)
    kwargs = script_container_kwargs(run, token, script_sha256=script_sha256 or hashlib.sha256(script).hexdigest(),
                                     bootstrap=bootstrap or bootstrap_sha256(), config=config, peer=peer)
    kwargs["network"] = facade["network"]  # the test's own internal network, not the deployment's
    before = len(facade["stub"].logs(stdout=True, stderr=False).splitlines())
    process = backend.start(kwargs, script)
    try:
        stdout = b"".join(process.stdout())
        code = process.wait()
    finally:
        process.remove()
    seen = [json.loads(line) for line in facade["stub"].logs(stdout=True, stderr=False).splitlines()[before:]]
    return code, stdout, token, seen


def test_an_unmodified_sdk_script_reads_through_the_facade_with_the_run_capability(facade):
    code, stdout, token, seen = run_script(facade, (
        "Connect-MgGraph -Scopes 'User.Read.All' -NoWelcome\n"
        "Get-MgUser -Top 2 -Property Id,DisplayName | ForEach-Object DisplayName\n"))
    result = parse_script_output(stdout).value
    assert code == 0 and result["script_exit_code"] == 0, stdout[-1500:]
    assert result["output"].splitlines() == ["Ada Test", "Grace Test"]
    assert [(r["method"], r["path"].split("?")[0]) for r in seen] == [("GET", "/v1.0/users")]
    assert seen[0]["authorization"] == f"Bearer {token}"  # the capability, through the shimmed Connect-MgGraph


def test_a_denied_write_reaches_the_script_as_a_graph_error_and_the_script_carries_on(facade):
    code, stdout, _, seen = run_script(facade, (
        "Update-MgUser -UserId 1 -AccountEnabled:$false\n"
        "'after the write'\n"))
    output = parse_script_output(stdout).value["output"]
    assert "not in the approved manifest" in output and output.rstrip().endswith("after the write")
    assert [r["method"] for r in seen] == ["PATCH"]  # the facade decides; here the stub refuses it


def test_the_script_cannot_read_the_capability_from_its_environment(facade):
    _, stdout, _, _ = run_script(facade, "\"[$env:CLW_RUN_TOKEN]\"\n(Get-MgContext).AuthType\n")
    assert parse_script_output(stdout).value["output"].splitlines() == ["[]", "UserProvidedAccessToken"]


def test_the_shims_are_non_interactive_and_capture_grid_output(facade):
    _, stdout, _, _ = run_script(facade, (
        "@([pscustomobject]@{Name='a'}, [pscustomobject]@{Name='b'}) | Out-GridView -Title report\n"
        "Disconnect-MgGraph\n"
        "(Get-MgContext).AuthType\n"
        "$name = Read-Host 'Who?'\n"
        "'never printed'\n"))
    result = parse_script_output(stdout).value
    lines = result["output"].splitlines()
    assert lines[0] == 'CLW_OUTPUT [{"Name":"a"},{"Name":"b"}]'
    assert lines[1] == "UserProvidedAccessToken"  # Disconnect-MgGraph did not drop the run's connection
    assert "non-interactive" in result["output"] and "never printed" not in result["output"]
    assert result["script_exit_code"] == 1  # Read-Host's error ended the script


def test_the_scripts_own_exit_ends_the_script_not_the_bootstrap(facade):
    _, stdout, _, _ = run_script(facade, "'partial'\nexit 4\n'not reached'\n")
    assert parse_script_output(stdout).value == {"kind": "script_output", "script_exit_code": 4, "output": "partial\n"}


def test_a_script_that_is_not_the_approved_digest_never_runs(facade):
    code, stdout, _, seen = run_script(facade, "Get-MgUser -Top 1\n", script_sha256="0" * 64)
    assert bootstrap_refusal(code, stdout) == "script_digest_mismatch" and seen == []


def test_a_bootstrap_that_is_not_the_recorded_digest_runs_nothing(facade):
    code, stdout, _, seen = run_script(facade, "Get-MgUser -Top 1\n", bootstrap="0" * 64)
    assert bootstrap_refusal(code, stdout) == "bootstrap_mismatch" and seen == []


def test_the_internet_is_unreachable_from_a_script(facade):
    _, stdout, _, _ = run_script(facade, (
        "try { Invoke-RestMethod -Uri https://example.com -TimeoutSec 5 | Out-Null; 'reached' } "
        "catch { 'blocked' }\n"))
    assert parse_script_output(stdout).value["output"].strip() == "blocked"
