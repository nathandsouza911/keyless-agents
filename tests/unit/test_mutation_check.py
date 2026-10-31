"""The mutation check counts a mutation as KILLED only for attributable test
failures; collection errors and infrastructure failures are BROKEN (gate 1,
third review: any non-zero exit used to count as killed)."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "audit_mutation_check.py"
_spec = importlib.util.spec_from_file_location("audit_mutation_check", _PATH)
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)


def _run(code: int, out: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr="")


@pytest.mark.parametrize("code, out, expected", [
    (0, "...\n12 passed in 1.0s", "SURVIVED"),
    (1, "FAILED tests/unit/audit/test_x.py::test_a - AssertionError: assert 1 == 2\n1 failed, 5 passed in 1s", "KILLED"),
    (1, "FAILED tests/unit/audit/test_x.py::test_a - Failed: DID NOT RAISE <class 'ValueError'>\n1 failed in 1s", "KILLED"),
    (2, "ERROR tests/db/test_x.py - SyntaxError\n1 error in 0.5s", "BROKEN"),            # collection error
    (1, "ERROR tests/db/test_x.py::test_a - asyncpg.exceptions.X\n1 failed, 1 error in 1s", "BROKEN"),  # setup error
    (1, "FAILED tests/db/test_x.py::test_a - ConnectionRefusedError: [WinError 1225]\n1 failed in 1s", "BROKEN"),
    (1, "FAILED tests/db/test_x.py::test_a - OSError: [Errno 10061] Connect call failed\n1 failed in 1s", "BROKEN"),
    (1, "FAILED tests/db/test_x.py::test_a - asyncpg.exceptions.InvalidPasswordError: x\n1 failed in 1s", "BROKEN"),
    (1, "FAILED tests/unit/test_x.py::test_a - ModuleNotFoundError: No module named 'x'\n1 failed in 1s", "BROKEN"),
    (1, "1 failed in 1s", "BROKEN"),                                                      # no FAILED line
    (3, "INTERNALERROR> boom", "BROKEN"),
    (4, "ERROR: usage", "BROKEN"),
    (5, "no tests ran in 0.01s", "BROKEN"),
])
def test_classification(code, out, expected):
    assert mc.classify(_run(code, out))[0] == expected


def test_every_expectation_names_a_real_mutation():
    names = {m[0] for m in mc.MUTATIONS}
    assert set(mc.EXPECT) <= names


def test_every_mutation_target_occurs_exactly_once():
    for name, path, _tests, old, _new in mc.MUTATIONS:
        text = (_PATH.parents[1] / path).read_text(encoding="utf-8")
        assert text.count(old) == 1, name


def test_mutation_names_are_unique():
    names = [m[0] for m in mc.MUTATIONS]
    assert len(names) == len(set(names))


# ------------------------------------------- hinted runs (speed, same verdicts)

def _fake_runs(monkeypatch, results):
    """results: list of (expected tests arg, CompletedProcess) consumed in order."""
    calls = []

    def fake(tests, *extra):
        calls.append((list(tests), extra))
        assert results, f"unexpected pytest call {tests} {extra}"
        return results.pop(0)

    monkeypatch.setattr(mc, "_pytest", fake)
    return calls


HINT = "tests/db/test_audit_writer.py"  # must exist: missing hint files are ignored
KILL = _run(1, "FAILED tests/db/test_a.py::test_x - AssertionError: no\n1 failed, 3 passed in 1s")
PASS = _run(0, "4 passed in 1s")
ERR = _run(1, "ERROR tests/db/test_a.py::test_x - boom\n1 error in 1s")


def test_hint_that_kills_decides_without_running_the_full_set(monkeypatch):
    calls = _fake_runs(monkeypatch, [KILL])
    assert mc.run_mutation("m", ["tests/db"], {"m": HINT})[0] == "KILLED"
    assert calls == [([HINT], ("-x",))]


def test_hint_that_passes_falls_back_to_the_full_set_before_any_survivor(monkeypatch):
    calls = _fake_runs(monkeypatch, [PASS, PASS])
    assert mc.run_mutation("m", ["tests/db"], {"m": HINT})[0] == "SURVIVED"
    assert [c[0] for c in calls] == [[HINT], ["tests/db"]]


def test_hint_with_a_broken_run_falls_back_and_cannot_count_as_killed(monkeypatch):
    calls = _fake_runs(monkeypatch, [ERR, KILL])
    assert mc.run_mutation("m", ["tests/db"], {"m": HINT})[0] == "KILLED"
    assert [c[0] for c in calls] == [[HINT], ["tests/db"]]
    calls = _fake_runs(monkeypatch, [ERR, ERR])
    assert mc.run_mutation("m", ["tests/db"], {"m": HINT})[0] == "BROKEN"


def test_hint_outside_the_mutation_test_set_is_ignored(monkeypatch):
    calls = _fake_runs(monkeypatch, [KILL])
    mc.run_mutation("m", ["tests/unit/audit"], {"m": HINT})
    assert calls == [(["tests/unit/audit"], ("-x",))]



def test_hint_in_a_directory_that_only_shares_a_prefix_is_ignored(monkeypatch):
    # Final review I-4: "tests/db" must not admit "tests/dbx/...".
    calls = _fake_runs(monkeypatch, [KILL])
    mc.run_mutation("m", ["tests/d"], {"m": HINT})
    assert calls == [(["tests/d"], ("-x",))]

def test_expect_rerun_skipped_only_when_the_failing_test_matches(monkeypatch):
    monkeypatch.setitem(mc.EXPECT, "m", "test_x or other")
    calls = _fake_runs(monkeypatch, [KILL])
    assert mc.run_mutation("m", ["tests/db"], {"m": HINT})[0] == "KILLED"
    assert len(calls) == 1
    monkeypatch.setitem(mc.EXPECT, "m", "test_y")
    calls = _fake_runs(monkeypatch, [KILL, PASS])
    status, detail = mc.run_mutation("m", ["tests/db"], {"m": HINT})
    assert status == "BROKEN" and "expected tests" in detail
    assert calls[1] == (["tests/db"], ("-k", "test_y"))


def test_hints_file_names_only_real_mutations_and_test_files():
    import json

    hints = json.loads(mc.HINTS_FILE.read_text(encoding="utf-8"))
    names = {m[0] for m in mc.MUTATIONS}
    root = _PATH.parents[1]
    for name, path in hints.items():
        assert name in names, name
        assert (root / path).exists() and path.startswith("tests/"), path
