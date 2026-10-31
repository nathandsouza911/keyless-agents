"""From analyser output to a proposed manifest and a plain-English summary (SD-043)."""

from __future__ import annotations

import json

import pytest

from clw.broker.facade.rules import load_script_manifest
from clw.scripts.analysis import AnalysisRefused, parse_analysis, propose, summarize

# What analyse.ps1 reports for the demo script plus one added Update-MgUser line.
DEMO = {
    "version": "1",
    "parse_errors": [],
    "commands": [{"name": "Connect-MgGraph", "line": 7}, {"name": "Invoke-MgGraphRequest", "line": 12},
                 {"name": "Update-MgUser", "line": 13}, {"name": "Out-GridView", "line": 52}],
    "graph_calls": [
        {"source": "Invoke-MgGraphRequest", "method": "GET", "line": 12,
         "uri": "https://graph.microsoft.com/beta/users?$count=true&$filter=(assignedLicenses/$count ne 0 and "
                "userType eq 'Member')&$\top=999&$select=id, displayName, usertype, signInActivity"},
        {"source": "Update-MgUser", "method": "PATCH", "uri": "/users/{user-id}", "api_version": "v1.0", "line": 13,
         "parameters": {"UserId": None, "AccountEnabled": "False"}},
    ],
    "unresolved": [{"line": 23, "command": "Invoke-MgGraphRequest", "reason": "URI not a constant (for example a nextLink)"}],
    "risks": [],
}


def line(document: dict) -> bytes:
    return b"CLW_ANALYSIS " + json.dumps(document).encode() + b"\n"


def test_the_demo_proposal_is_one_valid_read_only_entry():
    proposed = propose(parse_analysis(line(DEMO)))
    manifest = load_script_manifest(proposed)  # approvable as proposed
    (entry,) = proposed["entries"]
    assert entry["method"] == "GET" and entry["path"] == "/users" and entry["versions"] == ["beta"]
    assert entry["select"] == ["id", "displayName", "usertype", "signInActivity"]
    assert entry["filter"] == {"allowed": True, "properties": ["assignedlicenses", "usertype"]}
    assert entry["count"] is True and entry["consistency_level"] is True
    assert manifest.sha256 and len(manifest.entries) == 1


def test_writes_are_never_proposed_and_are_named_as_blocked():
    analysis = parse_analysis(line(DEMO))
    summary = summarize(analysis, propose(analysis))
    assert summary["blocked"] == ["Tries to change data: PATCH /users/{user-id} (Update-MgUser, line 13). "
                                  "This will be blocked."]
    assert summary["reads"] == ["Reads /users (beta): id, displayName, usertype, signInActivity; filters on "
                                "assignedlicenses, usertype; counts results."]
    assert summary["unknown"] == ["Line 23: URI not a constant (for example a nextLink) (Invoke-MgGraphRequest). "
                                  "Denied unless the manifest allows it."]


def test_a_cmdlet_with_properties_becomes_an_entry():
    analysis = {**DEMO, "graph_calls": [{
        "source": "Get-MgUser", "method": "GET", "uri": "/users", "api_version": "v1.0", "line": 3,
        "parameters": {"All": True, "Property": ["Id", "DisplayName", "SignInActivity"], "Filter": "accountEnabled eq true"}}]}
    (entry,) = propose(analysis)["entries"]
    assert entry["versions"] == ["v1.0"] and entry["select"] == ["Id", "DisplayName", "SignInActivity"]
    assert entry["filter"] == {"allowed": True, "properties": ["accountenabled"]}


def test_calls_to_one_path_merge_and_properties_differing_in_case_are_one():
    get = {"source": "Get-MgUser", "method": "GET", "uri": "/users", "api_version": "v1.0", "line": 3,
           "parameters": {"Property": ["Id", "DisplayName"]}}
    raw = {"source": "Invoke-MgGraphRequest", "method": "GET", "line": 9,
           "uri": "https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses&$top=999"}
    (entry,) = propose({**DEMO, "graph_calls": [get, raw]})["entries"]
    assert entry["select"] == ["Id", "DisplayName", "assignedLicenses"] and entry["top"] == 999


def test_a_script_that_selects_nothing_leaves_the_choice_to_the_approver():
    analysis = {**DEMO, "graph_calls": [{"source": "Get-MgUser", "method": "GET", "uri": "/users",
                                         "api_version": "v1.0", "line": 3, "parameters": {"All": True}}]}
    proposed = propose(analysis)
    assert proposed["entries"][0]["select_required"] is False
    assert "choose the properties before approving" in summarize(analysis, proposed)["reads"][0]


def test_a_filter_from_a_variable_is_allowed_but_with_no_properties():
    analysis = {**DEMO, "graph_calls": [{"source": "Get-MgUser", "method": "GET", "uri": "/users",
                                         "api_version": "v1.0", "line": 3,
                                         "parameters": {"Property": ["Id"], "Filter": None}}]}
    assert propose(analysis)["entries"][0]["filter"] == {"allowed": True, "properties": []}


def test_risk_flags_and_parse_errors_are_explained():
    analysis = {**DEMO, "parse_errors": [{"line": 1, "message": "x"}],
                "risks": [{"kind": "interactive_prompt", "line": 49, "detail": "Read-Host"},
                          {"kind": "removed_in_sdk_v2", "line": 68, "detail": "Select-MgProfile"}]}
    risks = summarize(analysis, propose(analysis))["risks"]
    assert risks[0].startswith("The script does not parse")
    assert any("Read-Host" in r for r in risks) and any("Select-MgProfile" in r for r in risks)


@pytest.mark.parametrize("stdout", [
    b"", b"CLW_ANALYSIS {}\n", b"noise\n" + line(DEMO), line(DEMO) + b"extra\n", b"CLW_ANALYSIS not json\n",
    b"CLW_ANALYSIS " + json.dumps({**DEMO, "extra": 1}).encode() + b"\n",
    b"CLW_ANALYSIS " + json.dumps({**DEMO, "risks": "x"}).encode() + b"\n",
    b"CLW_ANALYSIS " + b"x" * (1024 * 1024),
], ids=["empty", "no-keys", "noise-before", "noise-after", "not-json", "extra-key", "wrong-type", "too-large"])
def test_only_the_analysers_exact_output_is_accepted(stdout):
    with pytest.raises(AnalysisRefused):
        parse_analysis(stdout)
