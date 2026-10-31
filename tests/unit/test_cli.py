"""CLI behaviour that needs no database: key creation (L4), exit codes (L2)."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from clw.cli import CONFIG, OK, OPERATIONAL, main


def _keygen(tmp_path, name="ck"):
    priv, pub = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub.pem"
    return priv, pub, main(["audit-keygen", "--private", str(priv), "--public", str(pub)])


def test_keygen_writes_keypair(tmp_path):
    priv, pub, code = _keygen(tmp_path)
    assert code == OK
    assert b"PRIVATE KEY" in priv.read_bytes() and b"PUBLIC KEY" in pub.read_bytes()


@pytest.mark.parametrize("existing", ["private", "public"])
def test_keygen_refuses_to_overwrite_and_leaves_existing_files_untouched(tmp_path, existing):
    priv, pub = tmp_path / "ck.pem", tmp_path / "ck.pub.pem"
    target = priv if existing == "private" else pub
    target.write_bytes(b"precious")
    assert main(["audit-keygen", "--private", str(priv), "--public", str(pub)]) == CONFIG
    assert target.read_bytes() == b"precious"
    other = pub if existing == "private" else priv
    assert not other.exists()  # no half-written key pair left behind


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_key_is_owner_only_on_posix(tmp_path):
    priv, _, _ = _keygen(tmp_path)
    assert (priv.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_private_key_acl_is_owner_only_on_windows(tmp_path):
    priv, _, _ = _keygen(tmp_path)
    acl = subprocess.run(["icacls", str(priv)], capture_output=True, text=True).stdout
    grants = [line for line in acl.splitlines() if ":(" in line]
    assert len(grants) == 1, acl  # exactly one ACE: the current user
    assert os.environ.get("USERNAME", "").lower() in grants[0].lower()
    for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
        assert broad not in acl


@pytest.mark.parametrize("command", [
    ["audit-checkpoint", "--chain", "c", "--out", "{tmp}"],
])
def test_missing_signing_key_env_is_a_config_error(monkeypatch, tmp_path, capsys, command):
    monkeypatch.delenv("CLW_AUDIT_CHECKPOINT_KEY_PATH", raising=False)
    assert main([a.replace("{tmp}", str(tmp_path)) for a in command]) == CONFIG
    assert "CLW_AUDIT_CHECKPOINT_KEY_PATH" in capsys.readouterr().err


@pytest.mark.parametrize("content", [None, b"not a pem", "public"])
def test_missing_or_invalid_signing_key_file_is_a_config_error(monkeypatch, tmp_path, capsys, content):
    _, pub, _ = _keygen(tmp_path, "real")
    path = tmp_path / "key.pem"
    if content == "public":
        path.write_bytes(pub.read_bytes())  # wrong kind of key
    elif content is not None:
        path.write_bytes(content)
    monkeypatch.setenv("CLW_AUDIT_CHECKPOINT_KEY_PATH", str(path))
    assert main(["audit-checkpoint", "--chain", "c", "--out", str(tmp_path / "out")]) == CONFIG
    assert "Traceback" not in capsys.readouterr().err


def test_missing_public_key_env_is_a_config_error(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("CLW_AUDIT_CHECKPOINT_PUBKEY_PATH", raising=False)
    cp = tmp_path / "cp.json"
    cp.write_text("{}")
    assert main(["audit-verify-checkpoint", "--chain", "c", "--checkpoint", str(cp)]) == CONFIG
    assert "CLW_AUDIT_CHECKPOINT_PUBKEY_PATH" in capsys.readouterr().err


def test_missing_database_url_is_a_config_error(monkeypatch, tmp_path):
    from clw.common import config
    from clw.db import session

    _, pub, _ = _keygen(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    try:
        assert main(["audit-verify", "--chain", "c"]) == CONFIG
    finally:
        config.get_settings.cache_clear()
        session.get_sessionmaker.cache_clear()


def test_unreachable_database_is_an_operational_error(monkeypatch):
    from clw.common import config
    from clw.db import session

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@127.0.0.1:1/none")
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    try:
        assert main(["audit-verify", "--chain", "c"]) == OPERATIONAL
    finally:
        config.get_settings.cache_clear()
        session.get_sessionmaker.cache_clear()


def test_unknown_command_is_a_usage_error():
    with pytest.raises(SystemExit) as info:
        main(["nope"])
    assert info.value.code == CONFIG


def test_module_entrypoint_exit_code_for_config_error(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "CLW_AUDIT_CHECKPOINT_KEY_PATH"}
    r = subprocess.run([sys.executable, "-m", "clw.cli", "audit-checkpoint", "--chain", "c", "--out", str(tmp_path)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == CONFIG, r.stderr
