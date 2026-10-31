"""Canonical JSON for audit hashing (SD-005).

This is the workbench's own canonical form. It is NOT RFC 8785 (JCS):
JCS sorts object keys by UTF-16 code units, this scheme sorts by Unicode
code point (Python's default string order). The two differ only for keys
mixing U+E000..U+FFFF with supplementary-plane characters; an independent
verifier in another language must sort by code point to reproduce hashes.

One value has exactly one byte representation:
- object keys sorted by code point, separators "," and ":", UTF-8 output
  (no \\u escapes for non-ASCII)
- only dict (str keys), list, str, int, bool and None are accepted
- floats are rejected (no portable canonical form); integers must fit in
  +/-(2**53 - 1) so verifiers in other languages read the same value
- strings must be valid UTF-8 and contain no NUL (Postgres JSONB rejects it)
- nesting deeper than MAX_DEPTH is rejected (bounded recursion; the
  database enforces the same limit on audit_events.details)

Strings are hashed byte-exact; no Unicode normalization is applied.
"""

from __future__ import annotations

import json

MAX_SAFE_INT = 2**53 - 1
# Matches the CHECK constraint on audit_events.details (depth of the top-level
# value counts as 1).
MAX_DEPTH = 16


class CanonicalizationError(ValueError):
    pass


def _check(value: object, path: str, depth: int = 1) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"{path}: nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise CanonicalizationError(f"{path}: integer outside the safe range")
        return
    if isinstance(value, str):
        _check_str(value, path)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check_str(key, f"{path}.<key>")
            _check(item, f"{path}.{key}", depth + 1)
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def _check_str(value: str, path: str) -> None:
    if "\x00" in value:
        raise CanonicalizationError(f"{path}: NUL character not allowed")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{path}: not valid UTF-8") from exc


def canonical_json(value: object) -> bytes:
    _check(value, "$")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
