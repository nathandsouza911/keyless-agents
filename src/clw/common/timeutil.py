from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_naive_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def to_rfc3339_utc(dt: datetime) -> str:
    """Fixed-shape UTC timestamp used inside audit hashes (SD-005).

    Always ``YYYY-MM-DDTHH:MM:SS.ffffffZ``. Naive datetimes are rejected
    rather than assumed to be UTC: audit evidence must not depend on a guess
    about the zone a value was produced in.
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("to_rfc3339_utc requires a timezone-aware datetime")
    u = dt.astimezone(timezone.utc)
    # Every field formatted explicitly: the C library's "%Y" is platform-dependent
    # (glibc does not zero-pad years below 1000; Windows does), and audit
    # verification must give the same answer on every platform (gate 1 L-C).
    return (f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:{u.minute:02d}:{u.second:02d}"
            f".{u.microsecond:06d}Z")
