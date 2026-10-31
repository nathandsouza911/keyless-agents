"""Signed audit-chain checkpoints, format v3 (SD-006; review findings M2, N1).

Fingerprinting (total: works for any value PostgreSQL can store):
  record_fingerprint = SHA-256 over a length-prefixed encoding of every
      persisted column, in a fixed order, with details taken verbatim as the
      text PostgreSQL returns. No JSON parsing or re-serialization is
      involved, so a stored float, a large integer or a deeply nested value
      is fingerprinted exactly as stored and cannot be silently converted.
  chain_fingerprint = SHA-256 over the ordered list of record fingerprints.

Fingerprinting is not validation. Whether the chain is VALID is decided by
verify_records; the checkpoint only binds that verdict to what was observed.

Statuses:
  VALID        every integrity and structural check passed (findings empty)
  INVALID      at least one check failed; the findings are signed with the
               observed state. Evidence of an invalid state, NEVER a valid
               integrity attestation: it can never verify as "ok".
  UNAVAILABLE  the state could not be determined (e.g. the chain could not
               be read); carries a reason and no fingerprint. Never "ok".

Each checkpoint binds tenant_id, chain_id, the sequence range, record
count, head record hash, chain fingerprint, status, findings, issue time and
signing key id, signed with Ed25519 over canonical JSON of those fields.

Limits: records after the newest checkpoint are not covered, and the
protection is only as good as the separation between the signing key and
checkpoint storage on one side and the database operator on the other.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clw.audit.canonical import CanonicalizationError, canonical_json
from clw.audit.chain import verify_records
from clw.audit.events import HEX64_RE, PROTECTED_FIELDS
from clw.audit.verifier import StoredRecord
from clw.common.timeutil import to_rfc3339_utc

FORMAT = "clw-audit-checkpoint-v3"
_RECORD_DOMAIN = b"clw-record-fp-v1\n"
_CHAIN_DOMAIN = b"clw-chain-fp-v1\n"
_COLUMN_ORDER = (*PROTECTED_FIELDS, "record_hash")

_KEYS = (
    "format", "tenant_id", "chain_id", "seq_from", "seq_to", "record_count", "head_record_hash",
    "chain_fingerprint", "status", "findings", "reason", "issued_at", "key_id",
)

CheckpointResult = Literal[
    "ok", "checkpoint_marks_chain_invalid", "checkpoint_unavailable", "truncated", "rewritten",
    "bad_signature", "unknown_key", "wrong_chain", "malformed", "checkpoint_inconsistent",
]


def key_id(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def _encode(value: object, *, details: bool = False) -> bytes:
    if value is None:
        return b"N"
    if details and isinstance(value, str):
        raw = value.encode("utf-8", "surrogatepass")
        return b"J" + str(len(raw)).encode() + b":" + raw
    if isinstance(value, bool):
        return b"B1" if value else b"B0"
    if isinstance(value, int):
        return b"I" + str(value).encode()
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogatepass")
        return b"S" + str(len(raw)).encode() + b":" + raw
    # Not producible by PostgreSQL for these columns; still deterministic.
    raw = repr(value).encode("utf-8", "surrogatepass")
    return b"R" + type(value).__name__.encode() + b":" + str(len(raw)).encode() + b":" + raw


def record_fingerprint(stored: StoredRecord) -> str:
    h = hashlib.sha256(_RECORD_DOMAIN)
    for name in _COLUMN_ORDER:
        value = stored.details_text if name == "details" else getattr(stored.record, name)
        h.update(name.encode() + b"=" + _encode(value, details=name == "details") + b"\n")
    return h.hexdigest()


def chain_fingerprint(stored: Sequence[StoredRecord]) -> str:
    h = hashlib.sha256(_CHAIN_DOMAIN)
    for s in stored:
        h.update(record_fingerprint(s).encode() + b"\n")
    return h.hexdigest()


def _sign(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    payload = {**payload, "key_id": key_id(private_key.public_key())}
    assert set(payload) == set(_KEYS)
    signature = private_key.sign(canonical_json(payload))
    return {**payload, "signature": base64.b64encode(signature).decode("ascii")}


def _int_or_none(v: object) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def sign_checkpoint(
    stored: Sequence[StoredRecord],
    private_key: Ed25519PrivateKey,
    *,
    chain_id: str,
    issued_at: datetime,
    allow_invalid: bool = False,
) -> dict:
    """Sign the chain's observed state. Refuses an invalid chain unless
    allow_invalid, in which case the checkpoint is marked INVALID."""
    stored = list(stored)
    if not stored:
        raise ValueError("refusing to checkpoint an empty chain")
    report = verify_records([s.record for s in stored], chain_id=chain_id)
    if not report.valid and not allow_invalid:
        raise ValueError("refusing to checkpoint a chain that does not verify (use allow_invalid to record it as INVALID)")
    findings = sorted([e.seq, e.issue] for e in report.errors)
    seq_from, seq_to, head = _range_of(stored)
    if seq_from == 0 and not findings:  # cannot happen for a chain that verifies; be explicit anyway
        findings = [[-1, "invalid_record"]]
    return _sign({
        "format": FORMAT,
        "tenant_id": chain_id,  # one chain per tenant in Phase 1
        "chain_id": chain_id,
        "seq_from": seq_from,
        "seq_to": seq_to,
        "record_count": len(stored),
        "head_record_hash": head,
        "chain_fingerprint": chain_fingerprint(stored),
        "status": "VALID" if report.valid else "INVALID",
        "findings": findings,
        "reason": None,
        "issued_at": to_rfc3339_utc(issued_at),
    }, private_key)


def sign_unavailable(private_key: Ed25519PrivateKey, *, chain_id: str, issued_at: datetime, reason: str) -> dict:
    """Signed statement that the chain's state could not be determined."""
    return _sign({
        "format": FORMAT, "tenant_id": chain_id, "chain_id": chain_id, "seq_from": None, "seq_to": None,
        "record_count": None, "head_record_hash": None, "chain_fingerprint": None, "status": "UNAVAILABLE",
        "findings": [], "reason": (reason or "unavailable")[:500], "issued_at": to_rfc3339_utc(issued_at),
    }, private_key)


def _range_of(stored: Sequence[StoredRecord]) -> tuple[int, int, str | None]:
    """(seq_from, seq_to, head_record_hash) as signed for these records; 0, 0
    when the sequence numbers are not usable integers in order."""
    first, last = stored[0].record, stored[-1].record
    seq_from, seq_to = _int_or_none(first.seq), _int_or_none(last.seq)
    if seq_from is None or seq_to is None or seq_from > seq_to:
        seq_from = seq_to = 0
    return seq_from, seq_to, last.record_hash if isinstance(last.record_hash, str) else None


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _well_formed(cp: object) -> bool:
    if not isinstance(cp, Mapping) or set(cp) != {*_KEYS, "signature"}:
        return False
    if cp["format"] != FORMAT or not all(
            isinstance(cp[k], str) for k in ("tenant_id", "chain_id", "issued_at", "key_id", "signature", "status")):
        return False
    if not HEX64_RE.fullmatch(cp["key_id"]):  # L-2: compare_digest needs ASCII; key ids are SHA-256 hex
        return False
    findings = cp["findings"]
    if not (isinstance(findings, list) and all(
            isinstance(f, list) and len(f) == 2 and _is_int(f[0]) and isinstance(f[1], str) for f in findings)):
        return False
    status = cp["status"]
    numbers = (cp["seq_from"], cp["seq_to"], cp["record_count"])
    if status == "UNAVAILABLE":
        return (all(v is None for v in (*numbers, cp["head_record_hash"], cp["chain_fingerprint"]))
                and findings == [] and isinstance(cp["reason"], str) and cp["reason"] != "")
    if status not in ("VALID", "INVALID"):
        return False
    if not (all(_is_int(v) for v in numbers) and cp["record_count"] >= 1 and cp["seq_from"] <= cp["seq_to"]):
        return False
    head = cp["head_record_hash"]
    if not (head is None or isinstance(head, str)):
        return False
    if not (isinstance(cp["chain_fingerprint"], str) and HEX64_RE.fullmatch(cp["chain_fingerprint"])
            and cp["reason"] is None):
        return False
    if status == "VALID" and not (cp["seq_from"] == 1 and isinstance(head, str) and HEX64_RE.fullmatch(head)):
        return False
    return (status == "INVALID") == bool(findings)


def verify_against_checkpoint(
    stored: Sequence[StoredRecord],
    checkpoint: object,
    public_key: Ed25519PublicKey,
    *,
    chain_id: str,
) -> CheckpointResult:
    """Compare a chain with a checkpoint. Run verify_records separately:
    "ok" here says nothing about records after the checkpoint."""
    if not _well_formed(checkpoint):
        return "malformed"
    assert isinstance(checkpoint, Mapping)
    try:
        signature = base64.b64decode(checkpoint["signature"], validate=True)
    except (binascii.Error, ValueError):
        return "malformed"
    if not hmac.compare_digest(checkpoint["key_id"], key_id(public_key)):
        return "unknown_key"
    payload = {name: checkpoint[name] for name in _KEYS}
    try:
        public_key.verify(signature, canonical_json(payload))
    except (InvalidSignature, CanonicalizationError):
        return "bad_signature"

    if checkpoint["chain_id"] != chain_id or checkpoint["tenant_id"] != chain_id:
        return "wrong_chain"
    if checkpoint["status"] == "UNAVAILABLE":
        return "checkpoint_unavailable"
    # The first record_count stored records must be exactly what was observed.
    covered = list(stored[: checkpoint["record_count"]])
    if len(covered) != checkpoint["record_count"]:
        return "truncated"
    if not hmac.compare_digest(chain_fingerprint(covered), checkpoint["chain_fingerprint"]):
        return "rewritten"
    # Gate 1 F-4 (fourth review): the signed range and head must describe the
    # covered records, so a signed-but-inconsistent checkpoint is never ok.
    if (checkpoint["seq_from"], checkpoint["seq_to"], checkpoint["head_record_hash"]) != _range_of(covered):
        return "checkpoint_inconsistent"
    if checkpoint["status"] != "VALID":
        return "checkpoint_marks_chain_invalid"
    return "ok"
