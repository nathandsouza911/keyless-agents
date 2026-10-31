"""The task's result line (Task 13).

A task reports its result as one stdout line, `CLW_RESULT <json>`. The JSON
is ASCII-only, so no character in it (U+2028 included) can split the line.
Keys must be strings, at every level, so no two keys can collapse into one.
Accepting exactly one such line, and its size limit, is the runner's job
(Task 14).
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

RESULT_PREFIX = "CLW_RESULT "


def _check_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("result keys must be strings")
            _check_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_keys(item)


def emit_result(payload: dict, *, stream: TextIO | None = None) -> None:
    if not isinstance(payload, dict):
        raise TypeError("the result must be a JSON object")
    _check_keys(payload)
    line = RESULT_PREFIX + json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True,
                                      separators=(",", ":"))
    out = sys.stdout if stream is None else stream
    out.write(line + "\n")
    out.flush()
