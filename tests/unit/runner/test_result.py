"""Task result validation and result_sha256 (Task 14; SD-014, SD-034). Pure."""

from __future__ import annotations

import hashlib
import io
import json

import pytest

from clw.audit.canonical import canonical_json
from clw.audit.chain import result_sha256
from clw.runner.result import ResultRejected, parse_result
from clw.runner.sandbox_spec import MAX_RESULT_BYTES
from clw_task_sdk.result import emit_result

RESULT = {"task_id": "dormant-account-investigation", "inactive_days": 90, "counts": {"dormant": 1},
          "dormant": [{"id": "u-1", "displayName": "Zo\u00eb \u2028"}], "note": None, "ok": True}


def sdk_line(payload=RESULT) -> bytes:
    out = io.StringIO()
    emit_result(payload, stream=out)
    return out.getvalue().encode("ascii")


def reason(stdout: bytes) -> str:
    with pytest.raises(ResultRejected) as caught:
        parse_result(stdout)
    return caught.value.reason


def test_sdk_line_is_accepted_and_hashed_canonically():
    result = parse_result(sdk_line())
    assert result.value == RESULT
    assert result.sha256 == hashlib.sha256(canonical_json(RESULT)).hexdigest() == result_sha256(RESULT)


def test_hash_does_not_depend_on_key_order_or_spacing():
    reordered = b"CLW_RESULT " + json.dumps(dict(reversed(list(RESULT.items()))), indent=None).encode() + b"\n"
    assert parse_result(reordered).sha256 == parse_result(sdk_line()).sha256


@pytest.mark.parametrize("stdout, expected", [
    (b"", "result_missing"),
    (b"\n", "result_missing"),
    (b"hello\n", "result_missing"),
    (b"CLW_RESULT {}\nCLW_RESULT {}\n", "result_duplicate"),
    (b"debug\nCLW_RESULT {}\n", "unexpected_output"),
    (b"CLW_RESULT {}\ndebug\n", "unexpected_output"),
    (b"CLW_RESULT {}\n\n", "unexpected_output"),
    (b"CLW_RESULT {}", "unexpected_output"),
    (b"CLW_RESULT{}\n", "result_missing"),
    (b"clw_result {}\n", "result_missing"),
    (b"CLW_RESULT \n", "result_malformed"),
    (b"CLW_RESULT [1]\n", "result_malformed"),
    (b"CLW_RESULT \"x\"\n", "result_malformed"),
    (b"CLW_RESULT null\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":1,\"a\":2}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":NaN}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":Infinity}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":1.5}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":1e3}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":9007199254740992}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":\"\\u0000\"}\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":\"\\ud800\"}\n", "result_malformed"),
    ("CLW_RESULT {\"a\":\"\u00e9\"}\n".encode(), "result_malformed"),
    (b"CLW_RESULT {\"a\":1}\r\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":1} trailing\n", "result_malformed"),
    (b"CLW_RESULT {\"a\":" + b"[" * 15 + b"1" + b"]" * 15 + b"}\n", "result_malformed"),  # 17 levels
    (b"CLW_RESULT " + b"[" * 100_000 + b"\n", "result_malformed"),
], ids=lambda v: v[:48].decode("ascii", "replace") if isinstance(v, bytes) else str(v))
def test_invalid_output_is_rejected(stdout, expected):
    assert reason(stdout) == expected


def test_deepest_allowed_result_is_accepted():
    nested: object = 1
    for _ in range(14):  # the object, 14 lists and the leaf: 16 levels
        nested = [nested]
    assert parse_result(b"CLW_RESULT " + json.dumps({"a": nested}).encode() + b"\n").value == {"a": nested}


def test_size_limit_is_inclusive():
    filler = MAX_RESULT_BYTES - len(b'CLW_RESULT {"x":""}\n')
    exact = b'CLW_RESULT {"x":"' + b"a" * filler + b'"}\n'
    assert len(exact) == MAX_RESULT_BYTES and parse_result(exact).value == {"x": "a" * filler}
    over = b'CLW_RESULT {"x":"' + b"a" * (filler + 1) + b'"}\n'
    assert reason(over) == "result_too_large"


@pytest.mark.parametrize("value", ["CLW_RESULT {}\n", None, bytearray(b"CLW_RESULT {}\n")])
def test_only_bytes_are_parsed(value):
    assert reason(value) == "result_malformed"
