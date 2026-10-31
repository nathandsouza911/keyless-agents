"""Checkpoint format v3 (SD-006; review findings M2, N1, Requirement A).

Fingerprints are computed per record over persisted values (details as
stored text) and then over the ordered list; VALID / INVALID / UNAVAILABLE
are distinct, and only VALID can verify as ok."""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clw.audit.chain import verify_records
from clw.audit.checkpoint import (
    chain_fingerprint,
    key_id,
    record_fingerprint,
    sign_checkpoint,
    sign_unavailable,
    verify_against_checkpoint,
)
from clw.audit.verifier import StoredRecord

from .helpers import CHAIN, OTHER_CHAIN, T0, build_chain, ev, rehash, standard_events

FLIP = dict(status="allowed", reason="allowed", http_method="PATCH", path_template="/users/{user_id}")


def stored(records):
    return [StoredRecord.from_record(r) for r in records]


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _cp(records, key, **kw):
    return sign_checkpoint(stored(records), key, chain_id=CHAIN, issued_at=T0, **kw)


def _verify(records_or_stored, cp, key, chain_id=CHAIN):
    s = records_or_stored if records_or_stored and isinstance(records_or_stored[0], StoredRecord) else stored(records_or_stored)
    return verify_against_checkpoint(s, cp, key.public_key(), chain_id=chain_id)


def _rewrite_from(records, index, **changes):
    out = list(records[:index])
    for r in records[index:]:
        if r.seq == records[index].seq:
            r = replace(r, **changes)
        out.append(rehash(replace(r, previous_hash=out[-1].record_hash if out else r.previous_hash)))
    return out


def _deep(n):
    v = 1
    for _ in range(n):
        v = {"a": v}
    return v


# ------------------------------------------------------------ VALID basics


def test_checkpoint_binds_tenant_chain_range_head_fingerprint_status(key):
    records = build_chain()
    cp = _cp(records, key)
    assert (cp["tenant_id"], cp["chain_id"], cp["seq_from"], cp["seq_to"], cp["record_count"]) == (CHAIN, CHAIN, 1, 8, 8)
    assert cp["head_record_hash"] == records[-1].record_hash
    assert cp["chain_fingerprint"] == chain_fingerprint(stored(records))
    assert cp["status"] == "VALID" and cp["findings"] == [] and cp["reason"] is None
    assert cp["key_id"] == key_id(key.public_key())
    assert _verify(records, cp, key) == "ok"


def test_legitimate_max_depth_record_can_be_checkpointed(key):
    # N1: the legitimate writer's maximum-depth details previously broke checkpoints.
    events = standard_events()
    events[6] = {**events[6], "details": _deep(14)}  # details 15 levels deep: the allowed maximum
    records = build_chain(events)
    assert verify_records(records, chain_id=CHAIN).valid
    cp = _cp(records, key)
    assert cp["status"] == "VALID" and _verify(records, cp, key) == "ok"


def test_chain_growth_after_checkpoint_still_ok(key):
    records = build_chain()
    assert _verify(records, _cp(records[:5], key), key) == "ok"


# --------------------------------------------- fingerprint is total and exact


@pytest.mark.parametrize("details_text", [
    '{"x": 1.5}', '{"x": 99999999999999999999}', '{"x": 1.0}', '{"x": 1}', '{"x": 1e400}',
    '{"a": ' * 3000 + "1" + "}" * 3000, "not json at all", "",
])
def test_fingerprint_handles_any_stored_details_text(details_text):
    record = build_chain()[0]
    assert len(record_fingerprint(StoredRecord(record, details_text))) == 64


def test_fingerprint_distinguishes_values_json_parsing_would_conflate():
    record = build_chain()[0]
    texts = ['{"x": 1}', '{"x": 1.0}', '{"x": 1.00}', '{"x": 10e-1}']
    assert len({record_fingerprint(StoredRecord(record, t)) for t in texts}) == len(texts)


def test_fingerprint_is_length_prefixed_and_unambiguous():
    record = build_chain()[0]
    a = record_fingerprint(StoredRecord(replace(record, reason="ab", outcome="c"), "{}"))
    b = record_fingerprint(StoredRecord(replace(record, reason="a", outcome="bc"), "{}"))
    assert a != b


@pytest.mark.parametrize("change", [{"seq": ["x"]}, {"seq": True}, {"run_id": {"a": 1}}, {"created_at": None}])
def test_fingerprint_never_raises_on_malformed_records(change):
    assert len(record_fingerprint(StoredRecord(replace(build_chain()[0], **change), "{}"))) == 64


# ---------------------------------------------------- INVALID checkpoints


def _poisoned(details_text):
    chain = build_chain()[:3]
    bad = replace(chain[-1], seq=4, previous_hash=chain[-1].record_hash, record_hash="0" * 64,
                  details={"x": 1.5})
    return [*stored(chain), StoredRecord(bad, details_text)]


@pytest.mark.parametrize("details_text", ['{"x": 1.5}', '{"x": 99999999999999999999}'])
def test_poison_with_float_or_bigint_can_be_checkpointed_as_invalid(key, details_text):
    # N1: allow_invalid previously failed before signing.
    s = _poisoned(details_text)
    cp = sign_checkpoint(s, key, chain_id=CHAIN, issued_at=T0, allow_invalid=True)
    assert cp["status"] == "INVALID" and [4, "hash_mismatch"] in cp["findings"]
    assert _verify(s, cp, key) == "checkpoint_marks_chain_invalid"


def test_invalid_chain_refused_without_allow_invalid(key):
    with pytest.raises(ValueError):
        sign_checkpoint(_poisoned('{"x": 1.5}'), key, chain_id=CHAIN, issued_at=T0)


def test_invalid_checkpoint_detects_later_changes_to_covered_records(key):
    s = _poisoned('{"x": 1.5}')
    cp = sign_checkpoint(s, key, chain_id=CHAIN, issued_at=T0, allow_invalid=True)
    changed = [*s[:3], StoredRecord(s[3].record, '{"x": 1.50}')]  # same number to a JSON parser
    assert _verify(changed, cp, key) == "rewritten"
    assert _verify(s[:3], cp, key) == "truncated"


def test_relabelling_invalid_checkpoint_as_valid_fails_signature(key):
    s = _poisoned('{"x": 1.5}')
    cp = sign_checkpoint(s, key, chain_id=CHAIN, issued_at=T0, allow_invalid=True)
    assert _verify(s, {**cp, "status": "VALID", "findings": []}, key) == "bad_signature"


def test_invalid_checkpoint_never_ok_even_when_state_matches(key):
    records = build_chain()
    records[2] = replace(records[2], status="tampered")
    cp = _cp(records, key, allow_invalid=True)
    assert _verify(records, cp, key) == "checkpoint_marks_chain_invalid"


# ------------------------------------------------- UNAVAILABLE checkpoints


def test_unavailable_checkpoint_is_signed_and_never_ok(key):
    cp = sign_unavailable(key, chain_id=CHAIN, issued_at=T0, reason="chain could not be read: OperationalError")
    assert cp["status"] == "UNAVAILABLE" and cp["chain_fingerprint"] is None
    assert _verify(build_chain(), cp, key) == "checkpoint_unavailable"
    assert _verify(build_chain(), {**cp, "status": "VALID"}, key) == "malformed"


# --------------------------------------------- truncation / rewrite / edits


def test_truncation_below_checkpoint_detected(key):
    records = build_chain()
    assert _verify(records[:3], _cp(records, key), key) == "truncated"


def test_deleted_middle_record_detected(key):
    records = build_chain()
    cp = _cp(records[:5], key)
    assert _verify([*records[:2], *records[3:]], cp, key) == "rewritten"


def test_full_rewrite_before_checkpoint_detected(key):
    records = build_chain()
    cp = _cp(records, key)
    rewritten = _rewrite_from(records, 6, **FLIP)
    assert verify_records(rewritten, chain_id=CHAIN).valid  # chain alone cannot tell
    assert _verify(rewritten, cp, key) == "rewritten"


@pytest.mark.parametrize("position", range(8))
def test_content_edit_with_stored_hash_untouched_detected(key, position):
    records = build_chain()
    cp = _cp(records, key)
    edited = list(records)
    edited[position] = replace(records[position], reason="edited")
    assert _verify(edited, cp, key) == "rewritten"


def test_rewrite_after_checkpoint_is_not_detected(key):
    # SD-006 residual risk: records newer than the last checkpoint are exposed.
    records = build_chain()
    cp = _cp(records[:5], key)
    assert _verify(_rewrite_from(records, 6, **FLIP), cp, key) == "ok"


# ------------------------------------------------------ signature / shape


@pytest.mark.parametrize("field, value", [
    ("seq_to", 3), ("record_count", 3), ("head_record_hash", "0" * 64), ("chain_id", OTHER_CHAIN),
    ("tenant_id", OTHER_CHAIN), ("issued_at", "2030-01-01T00:00:00.000000Z"), ("chain_fingerprint", "0" * 64),
])
def test_edited_checkpoint_fails_signature(key, field, value):
    cp = {**_cp(build_chain(), key), field: value}
    assert _verify(build_chain(), cp, key) == "bad_signature"


def test_checkpoint_signed_by_another_key_rejected(key):
    assert _verify(build_chain(), _cp(build_chain(), Ed25519PrivateKey.generate()), key) == "unknown_key"


def test_checkpoint_for_another_chain_rejected(key):
    assert _verify(build_chain(), _cp(build_chain(), key), key, chain_id=OTHER_CHAIN) == "wrong_chain"


def test_checkpoint_naming_another_tenant_for_this_chain_rejected(key):
    """A correctly signed checkpoint whose chain_id matches but whose
    tenant_id does not must be rejected (third review: untested comparison)."""
    from clw.audit.checkpoint import _KEYS, _sign

    good = _cp(build_chain(), key)
    forged = _sign({k: v for k, v in good.items() if k in _KEYS and k != "key_id"} | {"tenant_id": OTHER_CHAIN}, key)
    assert forged["chain_id"] == CHAIN and forged["tenant_id"] == OTHER_CHAIN
    assert _verify(build_chain(), forged, key) == "wrong_chain"
    assert _verify(build_chain(), good, key) == "ok"


@pytest.mark.parametrize("mangle", [
    lambda cp: {k: v for k, v in cp.items() if k != "signature"},
    lambda cp: {**cp, "signature": "not base64!"},
    lambda cp: {**cp, "format": "clw-audit-checkpoint-v2"},
    lambda cp: {**cp, "seq_to": "8"},
    lambda cp: {**cp, "seq_to": True},
    lambda cp: {**cp, "seq_from": 9},
    lambda cp: {**cp, "seq_from": 2},  # a VALID checkpoint must start at seq 1
    lambda cp: {**cp, "record_count": 0},
    lambda cp: {**cp, "status": "MAYBE"},
    lambda cp: {**cp, "status": "INVALID"},  # INVALID must carry findings
    lambda cp: {**cp, "findings": [["1", "x"]]},
    lambda cp: {**cp, "chain_fingerprint": "XYZ"},
    lambda cp: {**cp, "chain_fingerprint": "a" * 64 + "\n"},
    lambda cp: {**cp, "reason": "x"},  # only UNAVAILABLE carries a reason
    lambda cp: {**cp, "extra": 1},
    lambda cp: "not a dict",
    # L-2: key_id must be exactly 64 lowercase hex characters
    lambda cp: {**cp, "key_id": "é" * 64},  # crashed hmac.compare_digest before
    lambda cp: {**cp, "key_id": cp["key_id"].upper()},
    lambda cp: {**cp, "key_id": cp["key_id"][:63]},
    lambda cp: {**cp, "key_id": cp["key_id"] + "\n"},
    lambda cp: {**cp, "key_id": 7},
])
def test_malformed_checkpoints_rejected(key, mangle):
    assert _verify(build_chain(), mangle(_cp(build_chain(), key)), key) == "malformed"


def test_refuses_to_sign_an_empty_chain(key):
    with pytest.raises(ValueError):
        sign_checkpoint([], key, chain_id=CHAIN, issued_at=T0, allow_invalid=True)


def test_malformed_record_chain_can_still_be_checkpointed_as_invalid(key):
    chain = build_chain()
    chain[3] = replace(chain[3], seq=["unhashable"])
    cp = _cp(chain, key, allow_invalid=True)
    assert cp["status"] == "INVALID"
    assert _verify(chain, cp, key) == "checkpoint_marks_chain_invalid"


# ---------------------------- fingerprint encoding spec (independent verifiers)

from clw.audit.checkpoint import _encode


@pytest.mark.parametrize("value, details, expected", [
    (None, False, b"N"),
    (7, False, b"I7"),
    (-12, False, b"I-12"),
    ("ab", False, b"S2:ab"),
    ("é", False, b"S2:\xc3\xa9"),  # length is UTF-8 bytes, not characters
    ('{"x": 1.5}', True, b'J10:{"x": 1.5}'),
    (None, True, b"N"),
])
def test_fingerprint_encoding_is_length_prefixed_and_stable(value, details, expected):
    assert _encode(value, details=details) == expected


# ------------------------------------------- F-4: signed range cross-check


def _resigned(cp, key, **changes):
    """A checkpoint re-signed with the real key after changing fields: what a
    holder of the signing key, or a bug in the signer, could produce."""
    from clw.audit.checkpoint import _KEYS, _sign

    return _sign({k: v for k, v in cp.items() if k in _KEYS and k != "key_id"} | changes, key)


@pytest.mark.parametrize("changes, expected", [
    ({"seq_to": 7}, "checkpoint_inconsistent"),
    ({"seq_to": 9}, "checkpoint_inconsistent"),
    ({"head_record_hash": "a" * 64}, "checkpoint_inconsistent"),
    ({"head_record_hash": None}, "malformed"),  # a VALID checkpoint must name its head
], ids=["seq_to-short", "seq_to-long", "head-other", "head-missing"])
def test_signed_but_inconsistent_range_or_head_is_never_ok(key, changes, expected):
    chain = build_chain()
    good = _cp(chain, key)
    assert _verify(chain, good, key) == "ok"
    bad = _resigned(good, key, **changes)
    assert _verify(chain, bad, key) == expected


def test_signed_but_inconsistent_seq_from_on_an_invalid_checkpoint(key):
    chain = build_chain()
    chain[3] = replace(chain[3], status="bogus")  # make it INVALID
    invalid = _cp(chain, key, allow_invalid=True)
    assert invalid["status"] == "INVALID" and invalid["seq_from"] == 1
    assert _verify(chain, invalid, key) == "checkpoint_marks_chain_invalid"
    assert _verify(chain, _resigned(invalid, key, seq_from=2), key) == "checkpoint_inconsistent"


def test_range_check_applies_to_the_covered_prefix_after_growth(key):
    chain = build_chain()
    cp = _cp(chain[:5], key)
    assert _verify(chain, cp, key) == "ok"  # later records are not covered
    assert _verify(chain, _resigned(cp, key, seq_to=8, head_record_hash=chain[-1].record_hash), key) == \
        "checkpoint_inconsistent"


# ------------------------------------------- I-1 gaps 4 and 6 (fifth review)


def test_single_record_chain_checkpoints_as_valid_and_verifies_ok(key):
    chain = build_chain()[:1]
    cp = _cp(chain, key)
    assert (cp["status"], cp["seq_from"], cp["seq_to"], cp["record_count"]) == ("VALID", 1, 1, 1)
    assert _verify(chain, cp, key) == "ok"
    assert _verify(build_chain(), cp, key) == "ok"  # growth after the checkpoint


def test_valid_checkpoint_carrying_findings_is_malformed_even_if_signed(key):
    chain = build_chain()
    cp = _cp(chain, key)
    assert _verify(chain, _resigned(cp, key, findings=[[3, "hash_mismatch"]]), key) == "malformed"
