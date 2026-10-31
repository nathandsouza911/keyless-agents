"""Checkpoint, verify and recover CLI end to end against Postgres
(SD-006; review findings H2, M2, L3)."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from clw.audit.writer import AuditWriter
from clw.cli import CONFIG, FAILED, OK, main

from tests.unit.audit.helpers import rehash, standard_events

pytestmark = pytest.mark.pg

FLIP = dict(status="allowed", reason="allowed", http_method="PATCH", path_template="/users/{user_id}")


@pytest.fixture
def cli_env(monkeypatch, tmp_path, pg_dsn):
    from clw.common import config
    from clw.db import session

    priv, pub = tmp_path / "ck.pem", tmp_path / "ck.pub.pem"
    assert main(["audit-keygen", "--private", str(priv), "--public", str(pub)]) == OK
    monkeypatch.setenv("DATABASE_URL", pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    monkeypatch.setenv("CLW_AUDIT_CHECKPOINT_KEY_PATH", str(priv))
    monkeypatch.setenv("CLW_AUDIT_CHECKPOINT_PUBKEY_PATH", str(pub))
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    yield tmp_path
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()


async def _run(argv):
    # main() uses asyncio.run internally; run it in a worker thread.
    return await asyncio.to_thread(main, argv)


async def _write_run(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    return [await writer.append(chain_id=chain_id, event={**e, "tenant_id": chain_id}) for e in standard_events()]


def _files(out_dir):
    return sorted(out_dir.glob("*.json"))


async def _superuser_edit(admin_conn, sql, *args):
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        await admin_conn.execute(sql, *args)
    finally:
        await admin_conn.execute("SET session_replication_role = origin")


async def test_export_then_verify_ok(sessionmaker, chain_id, cli_env):
    await _write_run(sessionmaker, chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    [cp_file] = _files(out)
    assert json.loads(cp_file.read_text())["status"] == "VALID"
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == OK
    assert await _run(["audit-verify", "--chain", chain_id]) == OK


async def test_existing_checkpoint_is_never_overwritten(sessionmaker, chain_id, cli_env):
    await _write_run(sessionmaker, chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    [cp_file] = _files(out)
    original = cp_file.read_bytes()
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == CONFIG  # same head seq
    assert _files(out) == [cp_file] and cp_file.read_bytes() == original


async def test_full_rewrite_caught_by_checkpoint(sessionmaker, admin_conn, chain_id, cli_env):
    records = await _write_run(sessionmaker, chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    rewritten = list(records[:6])
    for r in records[6:]:
        rewritten.append(rehash(replace(replace(r, **FLIP) if r.seq == 7 else r, previous_hash=rewritten[-1].record_hash)))
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        for r in rewritten[6:]:
            await admin_conn.execute(
                "UPDATE audit_events SET status=$1, reason=$2, previous_hash=$3, record_hash=$4, "
                "http_method=$7, path_template=$8 WHERE chain_id=$5 AND seq=$6",
                r.status, r.reason, r.previous_hash, r.record_hash, chain_id, r.seq, r.http_method, r.path_template)
    finally:
        await admin_conn.execute("SET session_replication_role = origin")
    assert await _run(["audit-verify", "--chain", chain_id]) == OK  # the chain alone is fooled
    [cp_file] = _files(out)
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED


async def test_content_edit_with_stored_hash_untouched_fails_verification(sessionmaker, admin_conn, chain_id, cli_env, capsys):
    # M2: flip the denial at seq 7 but leave record_hash as stored.
    await _write_run(sessionmaker, chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    await _superuser_edit(admin_conn,
                          "UPDATE audit_events SET status='allowed', reason='allowed', http_method='PATCH', "
                          "path_template='/users/{user_id}' WHERE chain_id=$1 AND seq=7", chain_id)
    [cp_file] = _files(out)
    capsys.readouterr()
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False and output["checkpoint"] == "rewritten"


async def test_tampered_chain_not_checkpointed_without_flag(sessionmaker, admin_conn, chain_id, cli_env):
    await _write_run(sessionmaker, chain_id)
    await _superuser_edit(admin_conn, "UPDATE audit_events SET reason='edited' WHERE chain_id=$1 AND seq=7", chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == FAILED
    assert not out.exists() or _files(out) == []
    assert await _run(["audit-verify", "--chain", chain_id]) == FAILED


async def test_invalid_chain_checkpoint_is_marked_and_never_passes(sessionmaker, admin_conn, chain_id, cli_env):
    await _write_run(sessionmaker, chain_id)
    await _superuser_edit(admin_conn, "UPDATE audit_events SET reason='edited' WHERE chain_id=$1 AND seq=7", chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out), "--allow-invalid"]) == FAILED
    [cp_file] = _files(out)
    assert cp_file.name.endswith("-INVALID.json")
    cp = json.loads(cp_file.read_text())
    assert cp["status"] == "INVALID" and [7, "hash_mismatch"] in cp["findings"]
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED


# ------------------------------------------------------------- recovery CLI


async def test_recover_cli_flow(sessionmaker, app_conn, chain_id, cli_env, capsys):
    from clw.audit.events import PROTECTED_FIELDS

    records = await _write_run(sessionmaker, chain_id)
    head = records[-1]
    bad = replace(head, seq=head.seq + 1, previous_hash=head.record_hash, record_hash="0" * 64, status="bogus")
    cols = [*PROTECTED_FIELDS, "record_hash"]
    args = [json.dumps(v) if c == "details" else v for c, v in bad.stored().items()]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(cols))
    await app_conn.execute(f"INSERT INTO public.audit_events ({', '.join(cols)}) VALUES ({placeholders})", *args)

    base = ["audit-recover", "--chain", chain_id, "--operator", "op:alice", "--reason", "INC-1"]
    assert await _run([*base, "--expected-head-hash", "1" * 64]) == FAILED  # wrong head: refused
    capsys.readouterr()
    assert await _run(["audit-verify", "--chain", chain_id]) == FAILED
    observed = json.loads(capsys.readouterr().out)
    assert await _run([*base, "--expected-head-hash", observed["head_hash"]]) == OK
    assert await _run([*base, "--expected-head-hash", observed["head_hash"]]) == FAILED  # nothing left to recover
    capsys.readouterr()
    assert await _run(["audit-verify", "--chain", chain_id]) == FAILED  # permanently invalid
    after = json.loads(capsys.readouterr().out)
    assert [bad.seq, "hash_mismatch"] in after["acknowledged"]


async def test_checkpoint_ok_but_later_record_tampered_fails_verification(sessionmaker, admin_conn, chain_id, cli_env, capsys):
    # The checkpoint covers seq 1..5 only and still matches; the chain is
    # invalid because of an edit at seq 7. The CLI must fail on the chain.
    records = await _write_run(sessionmaker, chain_id)
    from clw.audit.checkpoint import sign_checkpoint
    from clw.cli import _load_private
    from clw.common.timeutil import utc_now

    from clw.audit.verifier import StoredRecord

    cp = sign_checkpoint([StoredRecord.from_record(r) for r in records[:5]], _load_private(),
                         chain_id=chain_id, issued_at=utc_now())
    cp_file = cli_env / "cp5.json"
    cp_file.write_text(json.dumps(cp))
    await _superuser_edit(admin_conn, "UPDATE audit_events SET reason='edited' WHERE chain_id=$1 AND seq=7", chain_id)
    capsys.readouterr()
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED
    out = json.loads(capsys.readouterr().out)
    assert out["checkpoint"] == "ok" and out["valid"] is False


# ---------------------------------------------- checkpoint v3 (N1, N7, N9)


async def _app_insert(app_conn, record, details_text):
    from clw.audit.events import PROTECTED_FIELDS

    cols = [*PROTECTED_FIELDS, "record_hash"]
    args = [details_text if c == "details" else v for c, v in record.stored().items()]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(cols))
    await app_conn.execute(f"INSERT INTO public.audit_events ({', '.join(cols)}) VALUES ({placeholders})", *args)


async def test_legitimate_max_depth_chain_checkpoints_as_valid(sessionmaker, chain_id, cli_env):
    value = 1
    for _ in range(14):
        value = {"a": value}
    events = [{**e, "tenant_id": chain_id} for e in standard_events()]
    events[6] = {**events[6], "details": value}
    writer = AuditWriter(sessionmaker)
    for e in events:
        await writer.append(chain_id=chain_id, event=e)
    out = cli_env / "cp"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    [cp_file] = _files(out)
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == OK


@pytest.mark.parametrize("details_text", ['{"x": 1.5}', '{"x": 99999999999999999999}'])
async def test_poison_with_float_or_bigint_checkpoints_as_invalid(sessionmaker, app_conn, chain_id, cli_env, details_text):
    records = (await _write_run(sessionmaker, chain_id))
    head = records[-1]
    bad = replace(head, seq=head.seq + 1, previous_hash=head.record_hash, record_hash="0" * 64)
    await _app_insert(app_conn, bad, details_text)
    out = cli_env / "cp"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out), "--allow-invalid"]) == FAILED
    [cp_file] = _files(out)
    cp = json.loads(cp_file.read_text())
    assert cp["status"] == "INVALID" and [bad.seq, "hash_mismatch"] in cp["findings"]
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED


async def test_fingerprint_detects_numeric_rewrite_json_parsing_would_hide(sessionmaker, app_conn, admin_conn, chain_id, cli_env, capsys):
    records = await _write_run(sessionmaker, chain_id)
    head = records[-1]
    bad = replace(head, seq=head.seq + 1, previous_hash=head.record_hash, record_hash="0" * 64)
    await _app_insert(app_conn, bad, '{"x": 1.5}')
    out = cli_env / "cp"
    await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out), "--allow-invalid"])
    [cp_file] = _files(out)
    await _superuser_edit(admin_conn, "UPDATE audit_events SET details = '{\"x\": 1.50}'::jsonb "
                          "WHERE chain_id=$1 AND seq=$2", chain_id, bad.seq)
    assert json.loads(await admin_conn.fetchval(
        "SELECT details::text FROM audit_events WHERE chain_id=$1 AND seq=$2", chain_id, bad.seq)) == {"x": 1.5}
    capsys.readouterr()
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(cp_file)]) == FAILED
    assert json.loads(capsys.readouterr().out)["checkpoint"] == "rewritten"


async def test_unreadable_chain_can_be_recorded_as_unavailable(monkeypatch, cli_env, chain_id):
    from clw.cli import OPERATIONAL
    from clw.common import config
    from clw.db import session

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@127.0.0.1:1/none")
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    out = cli_env / "cp"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OPERATIONAL
    assert not out.exists()
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out), "--record-unavailable"]) == OPERATIONAL
    [cp_file] = _files(out)
    assert cp_file.name.endswith("-UNAVAILABLE.json")
    assert json.loads(cp_file.read_text())["status"] == "UNAVAILABLE"


@pytest.mark.parametrize("bad_chain", ["../../etc/x", "a/b", "..", "", "x" * 200, "a b", "a\nb"])
async def test_chain_id_validated_before_use_in_file_names(cli_env, bad_chain):
    out = cli_env / "cp"
    assert await _run(["audit-checkpoint", "--chain", bad_chain, "--out", str(out)]) == CONFIG
    assert not out.exists()


async def test_deeply_nested_checkpoint_file_is_a_config_error(sessionmaker, chain_id, cli_env, capsys):
    await _write_run(sessionmaker, chain_id)
    deep = cli_env / "deep.json"
    deep.write_text("[" * 200_000 + "]" * 200_000)
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(deep)]) == CONFIG
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("bad_key_id", ["é" * 64, "A" * 64, "a" * 63, "١" * 64])
async def test_malformed_key_id_is_reported_malformed_not_a_crash(sessionmaker, chain_id, cli_env, capsys, bad_key_id):
    """Gate 1 L-2: a non-ASCII key_id crashed hmac.compare_digest (TypeError).
    It is now rejected as malformed: exit 1 (verification failure), no traceback."""
    await _write_run(sessionmaker, chain_id)
    out = cli_env / "checkpoints"
    assert await _run(["audit-checkpoint", "--chain", chain_id, "--out", str(out)]) == OK
    [cp_file] = _files(out)
    tampered = cli_env / "tampered.json"
    tampered.write_text(json.dumps({**json.loads(cp_file.read_text()), "key_id": bad_key_id}), encoding="utf-8")
    capsys.readouterr()
    assert await _run(["audit-verify-checkpoint", "--chain", chain_id, "--checkpoint", str(tampered)]) == FAILED
    captured = capsys.readouterr()
    assert json.loads(captured.out)["checkpoint"] == "malformed"
    assert "Traceback" not in captured.err
