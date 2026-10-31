"""Operator commands.

  python -m clw.cli audit-keygen --private PATH --public PATH
  python -m clw.cli audit-verify --chain ID
  python -m clw.cli audit-checkpoint --chain ID --out DIR [--allow-invalid] [--record-unavailable]
  python -m clw.cli audit-verify-checkpoint --chain ID --checkpoint FILE
  python -m clw.cli audit-recover --chain ID --operator WHO --reason TEXT --expected-head-hash HASH

The signing key is read from CLW_AUDIT_CHECKPOINT_KEY_PATH and the
verification key from CLW_AUDIT_CHECKPOINT_PUBKEY_PATH; neither is ever
stored in the database (SD-006). Checkpoint files should be copied to
storage the database operator cannot modify. Recovery: see
docs/runbooks/audit-chain-recovery.md.

Exit codes:
  0  ok
  1  integrity or verification failure (chain invalid, checkpoint mismatch, recovery refused)
  2  usage or configuration error (bad arguments, missing/invalid key files,
     unreadable checkpoint, checkpoint file already exists, existing key files)
  3  operational error (database unavailable; also after writing an UNAVAILABLE checkpoint)

Checkpoint statuses (format v3): VALID verifies as ok; INVALID and
UNAVAILABLE are signed evidence of an observed state and never verify as ok.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

KEY_ENV = "CLW_AUDIT_CHECKPOINT_KEY_PATH"
PUBKEY_ENV = "CLW_AUDIT_CHECKPOINT_PUBKEY_PATH"
OK, FAILED, CONFIG, OPERATIONAL = 0, 1, 2, 3


class _ConfigError(Exception):
    pass


def _err(message: str) -> None:
    print(message, file=sys.stderr)


# ------------------------------------------------------------------ keys


def _load_key(env: str, loader, kind):
    value = os.environ.get(env)
    if not value:
        raise _ConfigError(f"{env} is not set")
    try:
        key = loader(Path(value).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise _ConfigError(f"cannot load key from {env}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(key, kind):
        raise _ConfigError(f"{env} is not an Ed25519 key of the expected kind")
    return key


def _load_private() -> Ed25519PrivateKey:
    return _load_key(KEY_ENV, lambda b: load_pem_private_key(b, password=None), Ed25519PrivateKey)


def _load_public() -> Ed25519PublicKey:
    return _load_key(PUBKEY_ENV, load_pem_public_key, Ed25519PublicKey)


# SYSTEM, BUILTIN\Administrators, OWNER RIGHTS: explicit ACEs Windows adds to
# new files in some locations; removed so the current user is the only grant.
# (An administrator can still take ownership; Windows is a development
# platform only, production keys live in Linux containers.)
_WINDOWS_EXTRA_SIDS = ("*S-1-5-18", "*S-1-5-32-544", "*S-1-3-4")


def _restrict_to_owner_windows(path: Path) -> None:
    """Remove inherited and default ACEs; grant full control to the current user only."""
    domain = os.environ.get("USERDOMAIN")
    user = domain + "\\" + getpass.getuser() if domain else getpass.getuser()
    for args in (["/inheritance:r", "/grant:r", f"{user}:(F)"], ["/remove:g", *_WINDOWS_EXTRA_SIDS]):
        result = subprocess.run(["icacls", str(path), *args], capture_output=True, text=True)
        if result.returncode != 0:
            raise OSError(f"icacls failed: {result.stdout.strip()} {result.stderr.strip()}")


def _create_exclusive(path: Path, data: bytes, *, private: bool) -> None:
    """Create a new file atomically (O_EXCL); never follows or replaces an
    existing path. Private files are owner-only before any bytes are written."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600 if private else 0o644)
    try:
        if private and os.name == "nt":
            _restrict_to_owner_windows(path)
        os.write(fd, data)
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)


def _keygen(private: Path, public: Path) -> int:
    key = Ed25519PrivateKey.generate()
    priv_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_bytes = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    try:
        _create_exclusive(private, priv_bytes, private=True)
    except FileExistsError:
        _err(f"refusing to overwrite existing {private}")
        return CONFIG
    except OSError as exc:
        _err(f"cannot create {private}: {exc}")
        return CONFIG
    try:
        _create_exclusive(public, pub_bytes, private=False)
    except OSError as exc:
        private.unlink(missing_ok=True)
        _err(f"refusing to overwrite existing {public}" if isinstance(exc, FileExistsError) else f"cannot create {public}: {exc}")
        return CONFIG
    print(f"wrote {private} (owner-only) and {public}")
    return OK


# -------------------------------------------------------------- database


# Tenant / chain identifiers: Entra tenant GUIDs in practice. Validated before
# any use, in particular before being placed in a file name (N9).
_CHAIN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


def _chain_id(value: str) -> str:
    if not _CHAIN_ID_RE.fullmatch(value):
        raise _ConfigError("invalid --chain: letters, digits, '-' and '_' only (max 128)")
    return value


async def _with_stored(chain_id: str):
    from clw.audit.verifier import load_stored_chain
    from clw.db.session import get_sessionmaker

    maker = get_sessionmaker()
    try:
        async with maker() as session:
            return await load_stored_chain(session, chain_id=chain_id)
    finally:
        await maker.kw["bind"].dispose()


async def _with_records(chain_id: str):
    return [s.record for s in await _with_stored(chain_id)]


def _report_json(report) -> dict:
    return {
        "chain_id": report.chain_id,
        "valid": report.valid,
        "integrity_state": report.integrity_state,
        "total": report.total,
        "head_seq": report.head_seq,
        "head_hash": report.head_hash,
        "errors": [[e.seq, e.issue, e.detail] for e in report.errors],
        "acknowledged": [[e.seq, e.issue] for e in report.acknowledged],
        "provisional": [[e.seq, e.issue] for e in report.provisional],
        "recoveries": [
            {"seq": r.seq, "valid": r.valid, "operator": r.operator, "reason": r.reason,
             "acknowledged": [list(a) for a in r.acknowledged]}
            for r in report.recoveries
        ],
        "intents_without_outcome": list(report.intents_without_outcome),
    }


async def _verify(chain_id: str) -> int:
    from clw.audit.chain import verify_records

    report = verify_records(await _with_records(chain_id), chain_id=chain_id)
    print(json.dumps(_report_json(report), indent=2))
    return OK if report.valid else FAILED


def _write_checkpoint(out_dir: Path, chain_id: str, checkpoint: dict) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    status = checkpoint["status"]
    seq = checkpoint["seq_to"] if checkpoint["seq_to"] is not None else 0
    suffix = "" if status == "VALID" else f"-{status}"
    stamp = checkpoint["issued_at"].replace(":", "").replace("-", "").replace(".", "")
    name = f"{chain_id}-{seq:010d}{suffix}.json" if status != "UNAVAILABLE" else f"{chain_id}-{stamp}{suffix}.json"
    path = out_dir / name
    try:
        _create_exclusive(path, json.dumps(checkpoint, indent=2, sort_keys=True).encode("utf-8"), private=False)
    except FileExistsError:
        _err(f"checkpoint {path} already exists; earlier checkpoints are never overwritten")
        return CONFIG
    print(f"checkpoint {path} seq={checkpoint['seq_to']} status={status}")
    return OK if status == "VALID" else (OPERATIONAL if status == "UNAVAILABLE" else FAILED)


async def _checkpoint(chain_id: str, out_dir: Path, allow_invalid: bool, record_unavailable: bool) -> int:
    from clw.audit.checkpoint import sign_checkpoint, sign_unavailable
    from clw.common.timeutil import utc_now

    key = _load_private()
    try:
        stored = await _with_stored(chain_id)
    except Exception as exc:
        if not record_unavailable:
            raise
        reason = f"chain could not be read: {type(exc).__name__}"
        _err(f"{reason}; recording an UNAVAILABLE checkpoint")
        return _write_checkpoint(out_dir, chain_id, sign_unavailable(key, chain_id=chain_id, issued_at=utc_now(), reason=reason))
    try:
        checkpoint = sign_checkpoint(stored, key, chain_id=chain_id, issued_at=utc_now(), allow_invalid=allow_invalid)
    except ValueError as exc:
        _err(f"no checkpoint written: {exc}")
        return FAILED
    return _write_checkpoint(out_dir, chain_id, checkpoint)


async def _verify_checkpoint(chain_id: str, checkpoint_file: Path) -> int:
    from clw.audit.chain import verify_records
    from clw.audit.checkpoint import verify_against_checkpoint

    public = _load_public()
    try:
        checkpoint = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:  # N7: deeply nested files too
        raise _ConfigError(f"cannot read checkpoint: {type(exc).__name__}") from exc
    stored = await _with_stored(chain_id)
    report = verify_records([s.record for s in stored], chain_id=chain_id)
    result = verify_against_checkpoint(stored, checkpoint, public, chain_id=chain_id)
    print(json.dumps({**_report_json(report), "checkpoint": result,
                      "checkpoint_status": checkpoint.get("status") if isinstance(checkpoint, dict) else None,
                      "checkpoint_seq": checkpoint.get("seq_to") if isinstance(checkpoint, dict) else None}, indent=2))
    return OK if (report.valid and result == "ok") else FAILED


async def _recover(chain_id: str, operator: str, reason: str, expected_head_hash: str) -> int:
    from clw.audit.writer import AuditRecoveryIncomplete, AuditRecoveryRefused, AuditWriter
    from clw.db.session import get_sessionmaker

    maker = get_sessionmaker()
    try:
        record = await AuditWriter(maker).append_recovery(
            chain_id=chain_id, operator=operator, reason=reason, expected_head_hash=expected_head_hash)
    except AuditRecoveryRefused as exc:
        _err(f"recovery refused (nothing written): {exc}")
        return FAILED
    except AuditRecoveryIncomplete as exc:
        _err(f"RECOVERY INCOMPLETE: {exc}")
        return FAILED
    finally:
        await maker.kw["bind"].dispose()
    print(json.dumps({"recovery_seq": record.seq, "acknowledged": record.details["acknowledged"]}, indent=2))
    return OK


async def _redact(chain_id: str, run_id: str, operator: str, reason: str) -> int:
    from clw.audit.redaction import RedactionRefused, redact_result
    from clw.audit.writer import AuditWriter
    from clw.db.session import get_sessionmaker

    maker = get_sessionmaker()
    try:
        done = await redact_result(maker, AuditWriter(maker), chain_id=chain_id, run_id=run_id,
                                   operator=operator, reason=reason)
    except RedactionRefused as exc:
        _err(f"redaction refused (nothing recorded or removed): {exc}")
        return FAILED
    finally:
        await maker.kw["bind"].dispose()
    print(json.dumps({"run_id": done.run_id, "result_sha256": done.result_sha256,
                      "redaction_seq": done.redaction_seq, "resumed": done.resumed}, indent=2))
    return OK


async def _hash_value(chain_id: str, option: str, value: str) -> int:
    from clw.broker.facade.hashing import digest_for
    from clw.db.session import get_sessionmaker

    maker = get_sessionmaker()
    try:
        digest = await digest_for(maker, chain_id, option, value)
    finally:
        await maker.kw["bind"].dispose()
    if digest is None:
        _err("this tenant has no audit value key (none was ever created, or it was deleted)")
        return FAILED
    print(json.dumps({"chain_id": chain_id, "option": option, "digest": digest}))
    return OK


async def _db_admin(command: str, args) -> int:
    import os

    from clw.db import admin
    from clw.db.session import get_sessionmaker

    maker = get_sessionmaker()
    try:
        if command == "db-provision-roles":
            names = {"api": "CLW_API_DATABASE_URL", "broker": "CLW_BROKER_DATABASE_URL",
                     "runner": "CLW_RUNNER_DATABASE_URL"}
            missing = [env for env in names.values() if not os.environ.get(env)]
            if missing:
                raise _ConfigError(f"set {', '.join(missing)} (the URLs the services use)")
            roles = await admin.provision_roles(maker, [
                admin.credential_from_url(component, os.environ[env]) for component, env in names.items()])
            print(json.dumps({"provisioned": roles}))
        elif command == "tenant-add":
            created = await admin.add_tenant(maker, tenant_id=args.tenant, display_name=args.name)
            print(json.dumps({"tenant": args.tenant, "created": created}))
        else:
            created = await admin.add_member(maker, tenant_id=args.tenant, oid=args.oid, role=args.role)
            print(json.dumps({"tenant": args.tenant, "oid": args.oid, "role": args.role, "created": created}))
    except admin.AdminRefused as exc:
        _err(f"refused (nothing changed): {exc}")
        return FAILED
    finally:
        await maker.kw["bind"].dispose()
    return OK


# ------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clw")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("audit-keygen")
    p.add_argument("--private", type=Path, required=True)
    p.add_argument("--public", type=Path, required=True)
    p = sub.add_parser("audit-verify")
    p.add_argument("--chain", required=True)
    p = sub.add_parser("audit-checkpoint")
    p.add_argument("--chain", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--allow-invalid", action="store_true",
                   help="record an invalid chain as an INVALID checkpoint (never verifies as ok)")
    p.add_argument("--record-unavailable", action="store_true",
                   help="if the chain cannot be read, write a signed UNAVAILABLE checkpoint (never verifies as ok)")
    p = sub.add_parser("audit-verify-checkpoint")
    p.add_argument("--chain", required=True)
    p.add_argument("--checkpoint", type=Path, required=True)
    p = sub.add_parser("audit-recover")
    p.add_argument("--chain", required=True)
    p.add_argument("--operator", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--expected-head-hash", required=True)
    p = sub.add_parser("audit-redact-result", help="remove a completed run's stored result, recorded in the chain")
    p.add_argument("--chain", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--operator", required=True)
    p.add_argument("--reason", required=True)
    sub.add_parser("db-provision-roles", help="create or update the api, broker and runner database roles")
    p = sub.add_parser("audit-hash-value", help="the digest a $filter/$search value has in a tenant's audit chain")
    p.add_argument("--chain", required=True)
    p.add_argument("--option", required=True, choices=["$filter", "$search"])
    p.add_argument("--value", required=True)
    p = sub.add_parser("facade-ca-init", help="create this deployment's facade CA and the proxy's Graph-host certificate")
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("tenant-add", help="register an Entra tenant")
    p.add_argument("--tenant", required=True)
    p.add_argument("--name", required=True)
    p = sub.add_parser("member-add", help="give a tenant user workbench membership")
    p.add_argument("--tenant", required=True)
    p.add_argument("--oid", required=True)
    p.add_argument("--role", required=True, choices=["analyst", "security_lead"])
    args = parser.parse_args(argv)

    from pydantic import ValidationError
    from sqlalchemy.exc import SQLAlchemyError

    from clw.audit.events import AuditUnavailable

    try:
        if args.command == "audit-keygen":
            return _keygen(args.private, args.public)
        if args.command == "facade-ca-init":
            from clw.broker.facade.ca import create

            try:
                made = create(args.out)
            except FileExistsError as exc:
                _err(str(exc))
                return FAILED
            print(json.dumps({"ca_cert": str(made.ca_cert), "proxy_cert": str(made.leaf_cert),
                              "proxy_key": str(made.leaf_key), "keep_offline": str(args.out / "ca.key")}))
            return OK
        if args.command == "audit-hash-value":
            return asyncio.run(_hash_value(_chain_id(args.chain), args.option, args.value))
        if args.command in ("db-provision-roles", "tenant-add", "member-add"):
            return asyncio.run(_db_admin(args.command, args))
        args.chain = _chain_id(args.chain)
        if args.command == "audit-verify":
            return asyncio.run(_verify(args.chain))
        if args.command == "audit-checkpoint":
            return asyncio.run(_checkpoint(args.chain, args.out, args.allow_invalid, args.record_unavailable))
        if args.command == "audit-verify-checkpoint":
            return asyncio.run(_verify_checkpoint(args.chain, args.checkpoint))
        if args.command == "audit-redact-result":
            return asyncio.run(_redact(args.chain, args.run, args.operator, args.reason))
        return asyncio.run(_recover(args.chain, args.operator, args.reason, args.expected_head_hash))
    except _ConfigError as exc:
        _err(str(exc))
        return CONFIG
    except ValidationError as exc:  # settings, e.g. DATABASE_URL missing or wrong driver
        _err(f"configuration error: {exc.error_count()} invalid setting(s): "
             f"{', '.join(str(e['loc'][0]) for e in exc.errors())}")
        return CONFIG
    except (AuditUnavailable, SQLAlchemyError) as exc:
        _err(f"audit store unavailable: {exc}")
        return OPERATIONAL
    except OSError as exc:  # connection refused, DNS, etc.
        _err(f"operational error: {type(exc).__name__}: {exc}")
        return OPERATIONAL


if __name__ == "__main__":
    sys.exit(main())
