import math

import pytest

from clw.audit.canonical import MAX_SAFE_INT, CanonicalizationError, canonical_json


def test_key_order_does_not_change_output():
    assert canonical_json({"b": 1, "a": {"y": 2, "x": 3}}) == canonical_json({"a": {"x": 3, "y": 2}, "b": 1})


def test_exact_bytes_compact_sorted_utf8():
    assert canonical_json({"b": [1, None, True], "a": "é"}) == '{"a":"é","b":[1,null,true]}'.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1.0},
        {"a": math.nan},
        {"a": math.inf},
        {"a": b"bytes"},
        {"a": (1, 2)},  # tuples are ambiguous with lists; caller must pass a list
        {"a": {1, 2}},
        {1: "non-string key"},
        {"a": MAX_SAFE_INT + 1},
        {"a": -MAX_SAFE_INT - 1},
        {"a": "nul\x00byte"},  # Postgres JSONB cannot store NUL; reject before persisting
        {"a": "\ud800"},  # lone surrogate: not valid UTF-8
        {"a\x00": 1},
    ],
)
def test_rejects_ambiguous_or_unstorable_values(value):
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


def test_rejects_arbitrary_objects():
    from datetime import datetime, timezone

    with pytest.raises(CanonicalizationError):
        canonical_json({"at": datetime.now(timezone.utc)})


def test_bool_is_not_confused_with_int():
    assert canonical_json({"a": True}) != canonical_json({"a": 1})


def test_boundary_ints_allowed():
    assert canonical_json({"a": MAX_SAFE_INT, "b": -MAX_SAFE_INT}) == f'{{"a":{MAX_SAFE_INT},"b":-{MAX_SAFE_INT}}}'.encode()
