"""Graph origin, request targets and nextLink validation (Task 11; T15).

The Graph origin is fixed here; clw.broker.transport re-exports it and is
the only sender. A request target is "/v1.0" + path + query, rendered from
the registry's BuiltRequest exactly as built (its values are
[A-Za-z0-9,] only, so nothing is encoded or reordered).

A nextLink is accepted only if:
  - it starts with exactly https://graph.microsoft.com/v1.0<original path>?
    (scheme, host, no port or user info, version and path, case-sensitive);
  - its query, split on "&" and percent-decoded (a "+" stays a "+"), has
    the original parameters with their original values, in any order
    (Review Focus 3), plus exactly one $skiptoken: no other, missing or
    repeated parameter;
  - the $skiptoken is printable ASCII once decoded (its length is bounded
    by the audit chain's 4096-byte request_target limit).
The broker then sends its OWN canonical target: the original target plus
"&$skiptoken=" and the token percent-encoded, which must still satisfy
the audit chain's target rule and length limit. So Graph's continuation
can carry only an opaque token; it cannot choose a destination, change
the approved parameters, or add one. The shape of a real nextLink is
unverified (A-14): a different but legitimate shape is refused, which
stops paging (fail closed).
"""

from __future__ import annotations

import re
from typing import Literal, get_args
from urllib.parse import quote, unquote

from clw.audit.events import MAX_REQUEST_TARGET_BYTES, target_matches_template
from clw.broker.operations import BuiltRequest

GRAPH_HOST = "graph.microsoft.com"
GRAPH_ORIGIN = f"https://{GRAPH_HOST}"
GRAPH_VERSION = "v1.0"
SKIPTOKEN = "$skiptoken"
MAX_NEXT_LINK_CHARS = 8192

Category = Literal[
    # from the plan
    "licence_required", "forbidden", "not_found", "throttled", "server", "deadline_exceeded",
    "invalid_next_link", "page_cap",
    # added in Task 11 (SD-031)
    "invalid_request", "token_expired", "bad_request", "unauthorized", "client_error", "redirect",
    "timeout", "network", "response_too_large", "invalid_response",
]
_CATEGORIES = frozenset(get_args(Category))

# A raw value: RFC 3986 query characters except the separators "&", ";",
# "#" and "?" (a name holds no "=": the pair is split on the first one).
_RAW_VALUE = re.compile(r"(?:[A-Za-z0-9._~!$'()*+,:@/=-]|%[0-9A-Fa-f]{2})+\Z")
_PRINTABLE = re.compile(r"[\x21-\x7e]+\Z")


class GraphError(Exception):
    """A Graph operation that did not produce data. The message is the
    category only; the fields are for the audit record (Task 12). Nothing
    from a response body is kept except a well-formed Graph error code."""

    def __init__(
        self,
        category: Category,
        *,
        http_status: int | None = None,
        graph_error_code: str | None = None,
        graph_request_id: str | None = None,
    ) -> None:
        if category not in _CATEGORIES:
            raise ValueError("unknown Graph error category")
        super().__init__(category)
        self.category = category
        self.http_status = http_status
        self.graph_error_code = graph_error_code
        self.graph_request_id = graph_request_id


def request_target(request: BuiltRequest) -> str:
    query = "&".join(f"{name}={value}" for name, value in request.query)
    return f"/{GRAPH_VERSION}{request.path}" + (f"?{query}" if query else "")


def _decoded_pairs(query: str) -> list[tuple[str, str]] | None:
    """Names and values percent-decoded ("+" stays "+"). Undecodable bytes
    become U+FFFD, which no expected value or valid token contains."""
    pairs = []
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if not _RAW_VALUE.match(value):
            return None
        pairs.append((unquote(name), unquote(value)))
    return pairs


def _next_target(next_link: object, original: object) -> str | None:
    if type(original) is not BuiltRequest or type(next_link) is not str or len(next_link) > MAX_NEXT_LINK_CHARS:
        return None
    prefix = f"{GRAPH_ORIGIN}/{GRAPH_VERSION}{original.path}?"
    if not next_link.startswith(prefix):
        return None
    pairs = _decoded_pairs(next_link[len(prefix):])
    if pairs is None:
        return None
    names = [name for name, _ in pairs]
    expected = dict(original.query)
    if len(set(names)) != len(names) or set(names) != {*expected, SKIPTOKEN}:
        return None
    values = dict(pairs)
    if any(values[name] != value for name, value in expected.items()):
        return None
    token = values[SKIPTOKEN]
    if not _PRINTABLE.match(token):  # its length is bounded by the audit target limit below
        return None
    base = request_target(original)
    target = f"{base}{'&' if original.query else '?'}{SKIPTOKEN}={quote(token, safe='')}"
    if len(target.encode()) > MAX_REQUEST_TARGET_BYTES or not target_matches_template(target, original.path_template):
        return None
    return target


def validate_next_link(next_link: str, *, original: BuiltRequest) -> str:
    """The canonical request target for a nextLink, or GraphError("invalid_next_link")."""
    target = _next_target(next_link, original)
    if target is None:
        raise GraphError("invalid_next_link")
    return target
