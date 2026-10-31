"""Every test a marketing claim cites as evidence exists (docs/marketing/claims.md; CLAUDE.md: claim only what
tests demonstrate). A renamed or deleted test must not leave a public claim standing on nothing."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLAIMS_FILE = ROOT / "docs" / "marketing" / "claims.md"
if not CLAIMS_FILE.is_file():  # the public tree carries no marketing claims file
    pytest.skip("docs/marketing/claims.md is not in this tree", allow_module_level=True)
CLAIMS = CLAIMS_FILE.read_text(encoding="utf-8")
TESTS = {p: p.read_text(encoding="utf-8") for p in (ROOT / "tests").rglob("*.py")}


def test_every_cited_test_file_and_test_exists():
    missing = []
    for path, name in re.findall(r"`(tests/[\w/]+\.py)((?:::\w+)?)`", CLAIMS):
        source = TESTS.get(ROOT / path)
        if source is None:
            missing.append(path)
        elif name and f"def {name[2:]}(" not in source:
            missing.append(path + name)
    for name in re.findall(r"`::(\w+)`", CLAIMS):
        if not any(f"def {name}(" in source for source in TESTS.values()):
            missing.append(name)
    assert missing == []


def _rows() -> dict[str, tuple[str, str]]:
    rows = {}
    for line in CLAIMS.splitlines():
        if line.startswith("| `"):
            cells = [c.strip() for c in line.split("|")]
            rows[cells[1].strip("`")] = (cells[3], cells[4])
    return rows


def test_no_proven_claim_without_cited_evidence():
    rows = _rows()
    for claim, (evidence, status) in rows.items():
        if status.startswith("proven (as summary)"):
            # A summary stands on other claims: every claim it names must itself be proven.
            named = [c for c in re.findall(r"`([a-z0-9-]+)`", evidence) if c in rows]
            assert named and all(rows[c][1].startswith("proven") for c in named), claim
        elif status.startswith("proven"):
            assert "tests/" in evidence or "docs/validation/" in evidence, claim
