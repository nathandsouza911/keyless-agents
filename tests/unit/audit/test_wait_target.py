"""Which record the recovery retry message names (final review I-2).

_wait_target picks the latest timestamp ahead of the database clock (the
time to wait for) and the first record carrying it (where it came from)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from clw.audit.writer import _wait_target
from clw.common.timeutil import to_rfc3339_utc

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def _at(minutes: float) -> str:
    return to_rfc3339_utc(NOW + timedelta(minutes=minutes))


def _chain(*stamps: str):
    return [SimpleNamespace(seq=i, created_at=t) for i, t in enumerate(stamps, start=1)]


def test_nothing_ahead_of_the_clock():
    assert _wait_target(_chain(_at(-3), _at(-1)), NOW) is None
    assert _wait_target([], NOW) is None


def test_a_record_exactly_at_the_clock_is_not_ahead():
    assert _wait_target(_chain(_at(-1), _at(0)), NOW) is None


def test_latest_timestamp_wins_not_the_latest_seq():
    # Several provisional records out of order: seq 1 is the latest-stamped.
    assert _wait_target(_chain(_at(9), _at(6), _at(4)), NOW) == (1, _at(9))
    assert _wait_target(_chain(_at(6), _at(9), _at(4)), NOW) == (2, _at(9))


def test_a_tie_names_the_first_record_with_that_timestamp():
    # seq 3 is ahead; seq 4 and 5 copied its timestamp (next_record does that).
    assert _wait_target(_chain(_at(-2), _at(-1), _at(4), _at(4), _at(4)), NOW) == (3, _at(4))


def test_a_recovery_copying_the_head_never_becomes_the_target():
    records = _chain(_at(-1), _at(4))
    copy = SimpleNamespace(seq=3, created_at=_at(4))  # a recovery built from that head
    assert _wait_target(records, NOW) == (2, _at(4))
    assert _wait_target([*records, copy], NOW) == (2, _at(4))


def test_malformed_timestamps_and_seqs_are_ignored():
    # Sorts after any real timestamp as text, but is not a timestamp.
    bogus = "9999-99-99T99:99:99.999999Z"
    records = [*_chain(_at(-1), _at(2)), SimpleNamespace(seq=3, created_at=bogus),
               SimpleNamespace(seq="4", created_at=_at(8)), SimpleNamespace(seq=5, created_at=None)]
    assert _wait_target(records, NOW) == (2, _at(2))
