from datetime import datetime, timedelta, timezone

from clw.common.timeutil import ensure_utc, to_naive_utc, utc_now

IST = timezone(timedelta(hours=5, minutes=30))


def test_utc_now_is_aware_utc():
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_ensure_utc_treats_naive_as_utc():
    assert ensure_utc(datetime(2026, 1, 1, 12, 0)) == datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_ensure_utc_converts_offsets():
    assert ensure_utc(datetime(2026, 1, 1, 17, 30, tzinfo=IST)) == datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_ensure_utc_passes_none():
    assert ensure_utc(None) is None


def test_to_naive_utc_strips_after_converting():
    assert to_naive_utc(datetime(2026, 1, 1, 17, 30, tzinfo=IST)) == datetime(2026, 1, 1, 12, 0)
    assert to_naive_utc(None) is None


# ---- to_rfc3339_utc: the only timestamp format allowed in audit hashes (SD-005)
import re

import pytest

from clw.common.timeutil import to_rfc3339_utc

RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def test_rfc3339_fixed_shape_with_microseconds():
    assert to_rfc3339_utc(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)) == "2026-01-01T12:00:00.000000Z"


def test_rfc3339_converts_offsets_to_utc():
    assert to_rfc3339_utc(datetime(2026, 1, 1, 17, 30, 0, 5, tzinfo=IST)) == "2026-01-01T12:00:00.000005Z"


def test_rfc3339_equal_instants_format_identically():
    a = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert to_rfc3339_utc(a) == to_rfc3339_utc(a.astimezone(IST))


def test_rfc3339_rejects_naive_datetimes():
    # A naive value has an unknown zone; it must never be silently assumed UTC
    # inside audit evidence.
    with pytest.raises(ValueError):
        to_rfc3339_utc(datetime(2026, 1, 1, 12, 0))


def test_rfc3339_matches_shape_for_now():
    assert RFC3339_UTC.match(to_rfc3339_utc(utc_now()))


# Gate 1 L-C (fifth review): strftime("%Y") does not zero-pad years below 1000
# on glibc but does on Windows. The format is now built field by field, so
# these exact strings must come out on every platform.
@pytest.mark.parametrize("year, expected", [
    (1, "0001-01-02T03:04:05.000006Z"),
    (9, "0009-01-02T03:04:05.000006Z"),
    (99, "0099-01-02T03:04:05.000006Z"),
    (500, "0500-01-02T03:04:05.000006Z"),
    (999, "0999-01-02T03:04:05.000006Z"),
    (1000, "1000-01-02T03:04:05.000006Z"),
    (2026, "2026-01-02T03:04:05.000006Z"),
    (9999, "9999-01-02T03:04:05.000006Z"),
])
def test_rfc3339_year_is_always_four_digits(year, expected):
    assert to_rfc3339_utc(datetime(year, 1, 2, 3, 4, 5, 6, tzinfo=timezone.utc)) == expected


def test_no_strftime_in_application_code():
    """strftime output is platform-dependent (L-C). The year-padding tests
    above catch it only on glibc, so also forbid it in the source tree, which
    catches a regression on every platform, including the Windows dev box."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src" / "clw"
    offenders = [str(p.relative_to(root)) for p in root.rglob("*.py") if "strftime(" in p.read_text(encoding="utf-8")]
    assert offenders == []
