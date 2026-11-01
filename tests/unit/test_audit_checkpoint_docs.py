"""The off-host checkpoint guide and the README's audit wording (SD-006: public wording)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from clw import cli

REPO = Path(__file__).resolve().parents[2]
GUIDE = REPO / "docs" / "audit-checkpoints.md"
COMMANDS = sorted(set(re.findall(r"clw\.cli ([a-z-]+)", GUIDE.read_text(encoding="utf-8"))))


def test_the_guide_covers_the_whole_cycle():
    assert set(COMMANDS) >= {"audit-keygen", "audit-checkpoint", "audit-verify-checkpoint", "audit-verify"}


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_in_the_guide_exists(command):
    with pytest.raises(SystemExit) as exc:  # --help exits 0; an unknown command exits 2
        cli.main([command, "--help"])
    assert exc.value.code == 0


def test_the_guide_names_the_key_variables_the_cli_reads():
    text = GUIDE.read_text(encoding="utf-8")
    assert cli.KEY_ENV in text and cli.PUBKEY_ENV in text


def test_the_readme_qualifies_tamper_evidence():
    # public/README.md here; README.md at the root of the exported public tree.
    readme = next(p for p in (REPO / "public" / "README.md", REPO / "README.md") if p.is_file()).read_text(encoding="utf-8")
    for line in readme.splitlines():
        if "tamper-evident" in line.lower():
            assert "checkpoint" in line, line
    assert "docs/audit-checkpoints.md" in readme
