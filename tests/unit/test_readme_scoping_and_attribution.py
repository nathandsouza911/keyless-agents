"""The README's data-scoping table and sample audit record match the code (public feedback, 2026-11-01)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from clw.broker import operations
from clw.db.models.audit_event import AuditEventRow

REPO = Path(__file__).resolve().parents[2]
# public/README.md here; README.md at the root of the exported public tree.
README = next(p for p in (REPO / "public" / "README.md", REPO / "README.md") if p.is_file()).read_text(encoding="utf-8")


def _section(title: str) -> str:
    return README.split(f"## {title}", 1)[1].split("\n## ", 1)[0]


def _fields(cell: str) -> set[str]:
    return set(re.findall(r"`([^`]+)`", cell.split(":", 1)[-1]))


@pytest.mark.parametrize("row", [line for line in _section("Data scoping: which fields reach the agent").splitlines()
                                 if line.startswith("| `")])
def test_the_scoping_table_lists_exactly_what_the_registry_returns(row):
    name_cell, fields_cell, nested_cell = [c.strip() for c in row.strip("|").split("|")]
    spec = operations.get(re.search(r"`([^`]+)`", name_cell).group(1))
    assert set(re.findall(r"`([^`]+)`", fields_cell)) == set(spec.response_properties)
    nested = dict(spec.nested_properties or {})
    if nested_cell == "none":
        assert not nested
    else:
        key = re.match(r"`([^`]+)`", nested_cell).group(1)
        assert set(nested) == {key} and _fields(nested_cell) == set(nested[key])


def test_the_sample_record_uses_real_audit_columns_and_fictional_ids():
    sample = json.loads(re.search(r"```json\n(.*?)\n```", _section("Identity and attribution"), re.S).group(1))
    columns = set(AuditEventRow.__table__.columns.keys())
    assert set(sample) <= columns
    assert {"run_id", "graph_request_id", "record_hash", "previous_hash"} <= set(sample)
    assert sample["tenant_id"] == "d3e0d3e0-0000-4000-8000-000000000001"  # the quick start's reserved fictional tenant
