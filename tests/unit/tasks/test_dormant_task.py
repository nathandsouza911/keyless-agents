"""The Dormant Account Investigation task (Task 13): result, entry point, imports.

The broker is replaced by a fake client here; tests/db/test_task_sdk_broker.py
runs the same task through the real broker (Graph mocked).
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from clw_task_sdk.client import BrokerError, OperationDenied
from clw_task_sdk.result import RESULT_PREFIX
from tasks.dormant_account_investigation import task
from tasks.dormant_account_investigation.task import investigate, main

REPO = Path(__file__).resolve().parents[3]
TASKS = REPO / "tasks"
MANIFEST = yaml.safe_load((TASKS / "dormant_account_investigation" / "manifest.yaml").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def stamp(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def graph_user(uid, *, enabled=True, created=400, success=None, **extra):
    return {"id": uid, "userPrincipalName": f"{uid}@contoso.test", "displayName": f"User {uid}",
            "accountEnabled": enabled, "createdDateTime": stamp(created) if created is not None else None,
            "signInActivity": None if success is None else {"lastSuccessfulSignInDateTime": stamp(success)},
            **extra}


USERS = [
    graph_user("b-active", success=1),
    graph_user("d-dormant", success=200, userType="Member"),
    graph_user("a-dormant", success=90),
    graph_user("c-never"),
    graph_user("e-new", created=3),
    graph_user("f-disabled", enabled=False, success=500),
    graph_user("g-disabled", enabled=False),
]


class FakeClient:
    def __init__(self, users=USERS, error: Exception | None = None):
        self.users, self.error, self.calls = users, error, 0

    def list_users_with_sign_in_activity(self):
        self.calls += 1
        if self.error:
            raise self.error
        return self.users


def result_lines(out: str) -> list[dict]:
    return [json.loads(line[len(RESULT_PREFIX):]) for line in out.splitlines() if line.startswith(RESULT_PREFIX)]


# ------------------------------------------------------------ the result


def test_result_lists_dormant_and_never_signed_in_with_counts_and_threshold():
    result = investigate(FakeClient(), now=NOW, inactive_days=90)
    assert result == {
        "task_id": "dormant-account-investigation",
        "inactive_days": 90,
        "evaluated_at": "2026-10-01T12:00:00Z",
        "users_evaluated": 7,
        "counts": {"active": 1, "dormant": 2, "never_signed_in": 1, "too_new_to_judge": 1, "disabled": 2},
        "dormant": [
            {"id": "a-dormant", "userPrincipalName": "a-dormant@contoso.test", "displayName": "User a-dormant",
             "last_sign_in": "2026-07-03T12:00:00Z"},
            {"id": "d-dormant", "userPrincipalName": "d-dormant@contoso.test", "displayName": "User d-dormant",
             "last_sign_in": "2026-03-15T12:00:00Z"},
        ],
        "never_signed_in": [
            {"id": "c-never", "userPrincipalName": "c-never@contoso.test", "displayName": "User c-never",
             "created": "2025-08-27T12:00:00Z"},
        ],
        "note": task.NOTE,
    }


def test_disabled_and_new_accounts_are_counted_not_listed():
    result = investigate(FakeClient(), now=NOW, inactive_days=90)
    listed = {entry["id"] for entry in result["dormant"] + result["never_signed_in"]}
    assert not listed & {"b-active", "e-new", "f-disabled", "g-disabled"}


def test_threshold_changes_the_result():
    result = investigate(FakeClient(), now=NOW, inactive_days=365)
    assert [u["id"] for u in result["dormant"]] == []
    assert result["counts"]["active"] == 3 and result["inactive_days"] == 365


def test_empty_directory():
    result = investigate(FakeClient(users=[]), now=NOW, inactive_days=90)
    assert result["users_evaluated"] == 0 and set(result["counts"].values()) == {0}


def test_non_text_identity_fields_become_null():
    result = investigate(FakeClient(users=[graph_user("x", success=200) | {"displayName": {"a": 1}}]),
                         now=NOW, inactive_days=90)
    assert result["dormant"][0]["displayName"] is None


def test_malformed_user_stops_the_task():
    with pytest.raises(ValueError):
        investigate(FakeClient(users=USERS + [graph_user("bad") | {"accountEnabled": "yes"}]),
                    now=NOW, inactive_days=90)


# ------------------------------------------------------------ the entry point


def test_main_emits_exactly_one_result_line(capsys):
    assert main(["--inactive-days", "90"], client=FakeClient(), now=NOW) == 0
    captured = capsys.readouterr()
    assert captured.out.count(RESULT_PREFIX) == 1 and len(captured.out.splitlines()) == 1
    assert result_lines(captured.out) == [investigate(FakeClient(), now=NOW, inactive_days=90)]


def test_main_defaults_to_the_manifest_default(capsys):
    assert main([], client=FakeClient(), now=NOW) == 0
    assert result_lines(capsys.readouterr().out)[0]["inactive_days"] == MANIFEST["params"]["inactive_days"]["default"]


def test_bounds_match_the_manifest():
    spec = MANIFEST["params"]["inactive_days"]
    assert (task.DEFAULT_INACTIVE_DAYS, task.MIN_INACTIVE_DAYS, task.MAX_INACTIVE_DAYS) == (
        spec["default"], spec["minimum"], spec["maximum"])
    assert task.TASK_ID == MANIFEST["id"]


@pytest.mark.parametrize("argv", [["--inactive-days", "29"], ["--inactive-days", "366"], ["--inactive-days", "0"],
                                  ["--inactive-days", "x"], ["--inactive-days", "90.0"], ["--inactive", "90"],
                                  ["--path", "/users"], ["90"]])
def test_bad_arguments_call_nothing_and_emit_nothing(argv, capsys):
    client = FakeClient()
    assert main(argv, client=client, now=NOW) == 2
    assert client.calls == 0 and RESULT_PREFIX not in capsys.readouterr().out


@pytest.mark.parametrize("error, reason", [
    (OperationDenied("not_in_manifest"), "not_in_manifest"),
    (BrokerError("licence_required", status_code=502), "licence_required"),
    (BrokerError("broker_unreachable"), "broker_unreachable"),
])
def test_broker_refusal_emits_no_result(error, reason, capsys):
    assert main([], client=FakeClient(error=error), now=NOW) == 1
    captured = capsys.readouterr()
    assert RESULT_PREFIX not in captured.out and reason in captured.err


def test_malformed_user_emits_no_result_and_no_user_data(capsys):
    users = [graph_user("secret-upn-value") | {"createdDateTime": "not-a-date"}]
    assert main([], client=FakeClient(users=users), now=NOW) == 1
    captured = capsys.readouterr()
    assert RESULT_PREFIX not in captured.out
    assert "secret-upn-value" not in captured.err and "not-a-date" not in captured.err


def test_missing_environment_is_a_configuration_error(monkeypatch, capsys):
    monkeypatch.delenv("CLW_RUN_TOKEN", raising=False)
    monkeypatch.delenv("CLW_BROKER_URL", raising=False)
    assert main([], now=NOW) == 2
    captured = capsys.readouterr()
    assert RESULT_PREFIX not in captured.out and "CLW_RUN_TOKEN" in captured.err


# ------------------------------------------------------------ imports (architecture.md §4.1)


def _imported_roots(path: Path) -> set[str]:
    roots = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add("." if node.level else node.module.split(".")[0])
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "__import__":
            roots.add("__import__")
    return roots


def test_tasks_import_only_stdlib_the_sdk_and_tasks():
    # "tasks ──▶ task_sdk only": no httpx, no third-party client of their own.
    # Hygiene on trusted code, not a security boundary (SD-008).
    allowed = set(sys.stdlib_module_names) - {"subprocess", "socket", "ssl", "urllib", "http", "importlib",
                                             "ctypes", "multiprocessing", "asyncio"}
    allowed |= {"clw_task_sdk", "tasks", "__future__", "."}
    bad = {str(p.relative_to(REPO)): sorted(_imported_roots(p) - allowed)
           for p in sorted(TASKS.rglob("*.py")) if "__pycache__" not in p.parts}
    assert {k: v for k, v in bad.items() if v} == {}


@pytest.mark.parametrize("source", ["import httpx", "import urllib.request", "from http import client",
                                    "import requests", "__import__('socket')", "import importlib"])
def test_import_check_catches_network_imports(tmp_path, source):
    path = tmp_path / "probe.py"
    path.write_text(source, encoding="utf-8")
    allowed = set(sys.stdlib_module_names) - {"subprocess", "socket", "ssl", "urllib", "http", "importlib",
                                             "ctypes", "multiprocessing", "asyncio"}
    assert _imported_roots(path) - (allowed | {"clw_task_sdk", "tasks", "__future__", "."})
