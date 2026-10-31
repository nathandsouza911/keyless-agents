"""The real offline analyser in its container (SD-043), by attempt.

Builds on the image docker/analyser.Dockerfile (tag clw-analyser:test; built
by CI's sandbox job, or locally with `docker build -f docker/analyser.Dockerfile
-t clw-analyser:test .`). Runs it exactly as the runner does: no network, a
read-only root, no capabilities, the script on stdin, never executed."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from clw.broker.facade.rules import load_script_manifest
from clw.runner.analyser import analyser_container_kwargs
from clw.runner.backend import DockerBackend
from clw.scripts.analysis import MAX_OUTPUT_BYTES, parse_analysis, propose, summarize
from tests.sandbox_support import RUNTIME

pytestmark = pytest.mark.sandbox

IMAGE = "clw-analyser:test"
SCRIPT = (Path(__file__).resolve().parents[1] / "fixtures" / "scripts" / "inactive_users_demo.ps1").read_bytes()


@pytest.fixture(scope="module")
def analysed(client):
    try:
        client.images.get(IMAGE)
    except Exception:  # noqa: BLE001
        pytest.skip(f"{IMAGE} not built")
    exit_code, stdout = DockerBackend(client).analyse(
        analyser_container_kwargs(uuid.uuid4().hex, image=IMAGE, runtime=RUNTIME), SCRIPT, 120.0, MAX_OUTPUT_BYTES)
    assert exit_code == 0, stdout[-500:]
    analysis = parse_analysis(stdout)
    proposed = propose(analysis)
    return analysis, proposed, summarize(analysis, proposed)


def test_the_proposal_is_read_only_and_approvable(analysed):
    _, proposed, _ = analysed
    manifest = load_script_manifest(proposed)
    entry = next(e for e in proposed["entries"] if e["path"] == "/users")
    assert {"Id", "DisplayName", "UserPrincipalName", "AccountEnabled", "SignInActivity"} <= set(entry["select"])
    assert entry["filter"] == {"allowed": True, "properties": ["accountenabled"]}
    assert all(e["method"] == "GET" for e in proposed["entries"]) and manifest.sha256


def test_the_write_is_named_as_blocked(analysed):
    _, _, summary = analysed
    assert any(line.startswith("Tries to change data: PATCH /users/{user-id} (Update-MgUser") for line in summary["blocked"])


def test_the_risks_are_flagged(analysed):
    analysis, _, _ = analysed
    kinds = {r["kind"] for r in analysis["risks"]}
    assert {"interactive_prompt", "module_install", "file_write"} <= kinds


def test_the_literal_graph_request_is_resolved(analysed):
    analysis, _, _ = analysed
    uris = {c["uri"] for c in analysis["graph_calls"] if c["source"] == "Invoke-MgGraphRequest"}
    assert uris == {"https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses&$top=999"}


def test_the_script_was_never_executed(analysed, client):
    # Executing it would have reached Read-Host or Connect-MgGraph; the analysis has no trace of either running,
    # and nothing ran with a network: the container had none (network_mode none, checked in the kwargs).
    kwargs = analyser_container_kwargs("x", image=IMAGE)
    assert kwargs["network_mode"] == "none" and kwargs["read_only"] and kwargs["cap_drop"] == ["ALL"]
    assert kwargs["environment"] == {}


def test_every_analysis_resolves_the_cmdlets(client):
    # Loading the SDK's metadata per analysis once ran out of memory about half
    # the time, and the cmdlets came out as unknown; the limit must hold every time.
    for _ in range(4):
        exit_code, stdout = DockerBackend(client).analyse(
            analyser_container_kwargs(uuid.uuid4().hex, image=IMAGE, runtime=RUNTIME), SCRIPT, 120.0, MAX_OUTPUT_BYTES)
        assert exit_code == 0
        assert {c["source"] for c in parse_analysis(stdout)["graph_calls"]} >= {"Get-MgUser", "Update-MgUser"}


def test_an_analysis_that_runs_out_of_memory_fails_rather_than_calling_cmdlets_unknown(client):
    kwargs = {**analyser_container_kwargs(uuid.uuid4().hex, image=IMAGE, runtime=RUNTIME),
              "mem_limit": "128m", "memswap_limit": "128m"}
    exit_code, stdout = DockerBackend(client).analyse(kwargs, SCRIPT, 120.0, MAX_OUTPUT_BYTES)
    assert exit_code != 0 and b"not a known Graph SDK cmdlet" not in stdout


# The built-in index must say what Find-MgGraphCommand says, for commands and
# aliases alike (every 97th of each, so the sample spans every module).
# The parsed metadata is dropped before Find-MgGraphCommand loads its own copy:
# both at once ran a 2 GiB container out of memory on a 4-core Linux host.
INDEX_AGREES = r'''
$module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Select-Object -First 1
$metadata = Get-Content -Raw (Join-Path $module.ModuleBase 'custom/common/MgCommandMetadata.json') | ConvertFrom-Json
$names = @($metadata.Command | Sort-Object -Unique)
$aliases = @($metadata.CommandAlias | Where-Object { $_ } | Sort-Object -Unique)
$sample = @(for ($i = 0; $i -lt $names.Count; $i += 97) { $names[$i] }) + @(for ($i = 0; $i -lt $aliases.Count; $i += 97) { $aliases[$i] })
Remove-Variable metadata, names, aliases
[GC]::Collect()
$index = Get-Content -Raw /clw/graph-commands.json | ConvertFrom-Json -AsHashtable
$bad = 0
foreach ($name in $sample) {
    $expected = @(Find-MgGraphCommand -Command $name | ForEach-Object { "$($_.Method) $($_.APIVersion) $($_.URI)" } | Sort-Object)
    $actual = @($index[$name.ToLowerInvariant()] | ForEach-Object { "$($_.Method) $($_.APIVersion) $($_.URI)" } | Sort-Object)
    if (($expected -join '|') -ne ($actual -join '|')) { $bad++; "MISMATCH $name" }
}
"checked $($sample.Count) mismatched $bad"
'''


def test_the_built_in_index_agrees_with_find_mggraphcommand(client):
    output = client.containers.run(IMAGE, ["-NoProfile", "-NonInteractive", "-Command", INDEX_AGREES],
                                   entrypoint="pwsh", network_mode="none", mem_limit="2g", remove=True).decode()
    summary = output.strip().splitlines()[-1]
    checked, mismatched = int(summary.split()[1]), int(summary.split()[3])
    assert checked > 250 and mismatched == 0, output[-2000:]


def test_a_uri_in_a_variable_resolves_from_its_nearest_assignment(client):
    # The first request uses the literal assigned just before it; the paging
    # request uses a next link, so it stays unresolved (the facade pages).
    script = (Path(__file__).resolve().parents[1] / "fixtures" / "scripts" / "paged_variable_uri.ps1").read_bytes()
    exit_code, stdout = DockerBackend(client).analyse(
        analyser_container_kwargs(uuid.uuid4().hex, image=IMAGE, runtime=RUNTIME), script, 120.0, MAX_OUTPUT_BYTES)
    assert exit_code == 0
    analysis = parse_analysis(stdout)
    calls = [(c["line"], c["uri"]) for c in analysis["graph_calls"] if c["source"] == "Invoke-MgGraphRequest"]
    assert calls == [(5, "https://graph.microsoft.com/beta/users?$count=true&$filter=userType eq 'Member'"
                         "&$top=500&$select=id,displayName")]
    assert [(u["line"], u["reason"]) for u in analysis["unresolved"]] == [
        (8, "URI not a constant (for example a nextLink)")]
    (entry,) = propose(analysis)["entries"]
    assert entry["versions"] == ["beta"] and entry["select"] == ["id", "displayName"] and entry["top"] == 500
