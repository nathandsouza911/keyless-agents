"""SD-005: the verifier detects tampering with every protected field on every
record and structural edits. Run-transition rules (SD-014) are tested in
test_transitions.py."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest

from clw.audit.chain import GENESIS, compute_record_hash, verify_records, verify_run_result
from clw.audit.events import PROTECTED_FIELDS, AuditRecord

from .helpers import CHAIN, OTHER_CHAIN, RESULT, build_chain, ev, rehash, standard_events, tamper

N = len(standard_events())


def issues(report):
    return {(e.seq, e.issue) for e in report.errors}


# ------------------------------------------------------------------ baseline


def test_untampered_chain_is_valid_and_complete():
    report = verify_records(build_chain(), chain_id=CHAIN)
    assert report.valid, report.errors
    assert report.total == N
    assert report.head_seq == N
    assert report.intents_without_outcome == ()


def test_record_dataclass_covers_exactly_the_protected_fields():
    names = [f.name for f in fields(AuditRecord)]
    assert names == [*PROTECTED_FIELDS, "record_hash"]


def test_hash_requires_exactly_the_protected_fields():
    record = build_chain()[0]
    good = {f: getattr(record, f) for f in PROTECTED_FIELDS}
    assert compute_record_hash(good) == record.record_hash
    with pytest.raises(ValueError):
        compute_record_hash({k: v for k, v in good.items() if k != "status"})
    with pytest.raises(ValueError):
        compute_record_hash({**good, "extra": 1})


def test_details_key_order_does_not_affect_hash():
    record = build_chain()[-1]
    reordered = replace(record, details=dict(reversed(list(record.details.items()))))
    assert verify_records([*build_chain()[:-1], reordered], chain_id=CHAIN).valid


# ------------------------------------------------- every field, every record

FIELDS_UNDER_TEST = [f for f in PROTECTED_FIELDS if f != "seq"]  # seq has dedicated tests


@pytest.mark.parametrize("position", range(N))
@pytest.mark.parametrize("field", FIELDS_UNDER_TEST)
def test_tampering_any_field_on_any_record_is_detected(field, position):
    chain = build_chain()
    chain[position] = tamper(chain[position], field)
    report = verify_records(chain, chain_id=CHAIN)
    assert not report.valid
    assert (position + 1, "hash_mismatch") in issues(report)


@pytest.mark.parametrize("position", range(N - 1))
@pytest.mark.parametrize("field", [f for f in FIELDS_UNDER_TEST if f != "previous_hash"])
def test_tamper_with_recomputed_own_hash_breaks_the_next_link(field, position):
    chain = build_chain()
    chain[position] = rehash(tamper(chain[position], field))
    report = verify_records(chain, chain_id=CHAIN)
    assert not report.valid
    assert (position + 2, "link_mismatch") in issues(report)


def test_tamper_with_recomputed_hash_on_last_record_is_not_detectable_without_checkpoint():
    # SD-006 limit: the head has no successor whose link would break.
    # Signed checkpoints (Task 2c) are what detect this.
    chain = build_chain()
    chain[-1] = rehash(replace(chain[-1], details={**chain[-1].details, "counts": {"dormant": 0}}))
    assert verify_records(chain, chain_id=CHAIN).valid


def test_tampered_record_hash_detected():
    chain = build_chain()
    chain[2] = replace(chain[2], record_hash="0" * 64)
    report = verify_records(chain, chain_id=CHAIN)
    assert (3, "hash_mismatch") in issues(report)
    assert (4, "link_mismatch") in issues(report)


# ------------------------------------------------------- structural edits


def test_deleted_record_is_a_seq_gap():
    chain = build_chain()
    del chain[3]
    report = verify_records(chain, chain_id=CHAIN)
    assert (5, "seq_gap") in issues(report)
    assert (5, "link_mismatch") in issues(report)


def test_reordered_records_detected():
    chain = build_chain()
    chain[2], chain[3] = chain[3], chain[2]
    report = verify_records(chain, chain_id=CHAIN)
    assert not report.valid
    assert {i for _, i in issues(report)} & {"seq_gap", "link_mismatch"}


def test_duplicate_seq_detected():
    chain = build_chain()
    chain.insert(3, chain[2])
    assert (3, "seq_duplicate") in issues(verify_records(chain, chain_id=CHAIN))


def test_forged_insert_with_valid_own_hash_detected():
    chain = build_chain()
    forged = rehash(replace(chain[3], seq=4, details={"forged": True}))
    chain.insert(4, forged)  # renumbering successors would break their hashes instead
    report = verify_records(chain, chain_id=CHAIN)
    assert not report.valid


def test_tampered_seq_detected():
    chain = build_chain()
    chain[4] = replace(chain[4], seq=9)
    report = verify_records(chain, chain_id=CHAIN)
    assert (9, "hash_mismatch") in issues(report)
    assert any(i in {"seq_gap"} for _, i in issues(report))


def test_first_record_must_link_to_genesis():
    chain = build_chain()
    chain[0] = rehash(replace(chain[0], previous_hash="f" * 64))
    assert (1, "first_not_genesis") in issues(verify_records(chain, chain_id=CHAIN))
    assert build_chain()[0].previous_hash == GENESIS


def test_record_spliced_from_another_chain_detected():
    chain = build_chain()
    foreign = build_chain(chain_id=OTHER_CHAIN, events=[
        {**e, "tenant_id": OTHER_CHAIN} for e in standard_events()
    ])
    chain[2] = foreign[2]
    report = verify_records(chain, chain_id=CHAIN)
    assert (3, "chain_id_mismatch") in issues(report)


def test_tail_truncation_not_detectable_without_checkpoint():
    # SD-006 limit, stated as a test so it cannot silently change.
    assert verify_records(build_chain()[:5], chain_id=CHAIN).valid


def test_empty_chain_is_valid():
    report = verify_records([], chain_id=CHAIN)
    assert report.valid and report.head_seq is None and report.head_hash is None


# ------------------------------------------------------ verified outcome


def test_completion_binds_the_stored_result():
    completion = build_chain()[-1]
    assert verify_run_result(completion, RESULT) == "ok"


def test_altered_stored_result_is_detected():
    completion = build_chain()[-1]
    altered = {**RESULT, "dormant": []}
    assert verify_run_result(completion, altered) == "result_mismatch"


def test_result_check_only_applies_to_completion_records():
    assert verify_run_result(build_chain()[0], RESULT) == "not_a_completion_record"
