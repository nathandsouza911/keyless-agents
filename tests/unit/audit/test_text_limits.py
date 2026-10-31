"""Gate 1 L-1: text limits in UTF-8 bytes, applied by the writer and reported
by the verifier for stored records (the database side is in tests/db)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from clw.audit.chain import next_record, verify_records
from clw.audit.events import MAX_REQUEST_TARGET_BYTES, MAX_TEXT_BYTES, AuditEventInvalid, text_too_long

from tests.unit.audit.helpers import CHAIN, T0, build_chain, rehash, standard_events


@pytest.mark.parametrize("value, over", [
    ("a" * MAX_TEXT_BYTES, False), ("a" * (MAX_TEXT_BYTES + 1), True),
    ("é" * 512, False), ("é" * 512 + "a", True),          # 2-byte characters
    ("😀" * 256, False), ("😀" * 256 + "a", True),          # 4-byte characters
    ("€" * 341 + "a", False), ("€" * 342, True),             # 3-byte characters: 1024 vs 1026
])
def test_limit_counts_utf8_bytes_not_characters(value, over):
    assert text_too_long("reason", value) is over


def test_request_target_has_its_own_limit():
    assert not text_too_long("request_target", "a" * MAX_REQUEST_TARGET_BYTES)
    assert text_too_long("request_target", "a" * (MAX_REQUEST_TARGET_BYTES + 1))
    assert text_too_long("reason", "a" * MAX_REQUEST_TARGET_BYTES)


def test_writer_refuses_an_over_limit_field():
    with pytest.raises(AuditEventInvalid, match="reason exceeds 1024 UTF-8 bytes"):
        next_record(None, chain_id=CHAIN, created_at=T0,
                    event={**standard_events()[6], "reason": "é" * 513})


def test_verifier_flags_a_stored_over_limit_record():
    chain = build_chain()
    chain[6] = rehash(replace(chain[6], reason="x" * (MAX_TEXT_BYTES + 1)))
    for i in range(7, len(chain)):
        chain[i] = rehash(replace(chain[i], previous_hash=chain[i - 1].record_hash))
    found = {(e.seq, e.issue) for e in verify_records(chain, chain_id=CHAIN, now=T0).errors}
    assert found == {(7, "invalid_event_shape")}


def test_over_limit_chain_id_is_an_invalid_record():
    long_id = "c" * (MAX_TEXT_BYTES + 1)
    record = rehash(replace(build_chain()[0], chain_id=long_id, tenant_id=long_id))
    assert (1, "invalid_record") in {(e.seq, e.issue) for e in verify_records([record], chain_id=long_id, now=T0).errors}
