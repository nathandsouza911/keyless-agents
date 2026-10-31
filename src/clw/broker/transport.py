"""Graph transport (Task 11): the only code that sends a Graph request.

`Transport.execute(request, token, ...)` takes the registry's BuiltRequest
(the object the policy approved; Task 12 passes it on unchanged) and a
ValidatedToken from clw.broker.credentials. It sends exactly
GRAPH_ORIGIN + request_target(request), and for later pages only the
canonical targets validate_next_link derives from that same request. There
is no other way in: no URL, host, method, header or body parameter.

Before anything is sent it refuses (invalid_request) a request that is
not a BuiltRequest for an executable registry read, is not GET, or whose
target fails the registry's own character rules or the audit chain's
target rule; and a token that is not a ValidatedToken with a bearer-safe
value. Phase 1 executes GET only, so every retry repeats an idempotent
read, and every attempt, retried or not, goes through the hooks:

  before_attempt(GraphAttempt)  write-ahead audit hook (Task 12). If it
                                raises, execute raises and sends nothing.
  after_attempt(GraphAttempt)   outcome hook, called for every attempt that
                                was sent, failed or not. If it raises,
                                execute raises and returns no data.

Hardening: redirects are never followed (a 3xx is "redirect"), so the
token cannot be forwarded elsewhere; requests are built here, not by the
client, so client default headers, cookies and auth are never added; the
client must not trust environment proxy or CA settings or carry event
hooks (new_graph_client builds one that passes). Each attempt has explicit
connect/read/write/pool timeouts no longer than the time left, and the
whole attempt is cut off at the run deadline. Responses must be
uncompressed (we ask for identity, so a decompression bomb cannot occur),
at most max_response_bytes per page and max_total_bytes per call, a JSON
object with a "value" list of objects, no duplicate keys.

Retries: 429, 503 and 504, and timeouts and network errors, up to
max_attempts per page. The wait is Retry-After (seconds or HTTP-date)
capped at max_single_wait_s, or 1, 2, 4 ... seconds without it; if the
wait would reach the deadline the call fails now with deadline_exceeded.

Errors are GraphError: a category plus http_status, a well-formed Graph
error code and request id. No response body, token or exception from
httpx is kept or attached. Nothing here logs.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx

from clw.audit.events import MAX_REQUEST_TARGET_BYTES, target_matches_template
from clw.broker import operations
from clw.broker.credentials import ValidatedToken
from clw.broker.operations import BuiltRequest
from clw.broker.pagination import (
    GRAPH_HOST,
    GRAPH_ORIGIN,
    GRAPH_VERSION,
    GraphError,
    request_target,
    validate_next_link,
)
from clw.common.timeutil import utc_now

__all__ = [
    "FACADE_HEADERS", "FACADE_VERSIONS", "FacadePage", "GRAPH_ORIGIN", "GRAPH_VERSION", "GraphAttempt",
    "GraphError", "Transport",
    "new_graph_client", "parse_retry_after", "validate_next_link",
]

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ERROR_BODY_BYTES = 64 * 1024
LICENCE_REQUIRED_CODE = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"  # A-02, unverified
RETRY_STATUSES = frozenset({429, 503, 504})

_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")
_QUERY_VALUE = re.compile(r"[A-Za-z0-9,]+\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9-]{1,64}\Z")
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.]{1,128}\Z")
_STATUS_CATEGORY = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "throttled"}

Hook = Callable[["GraphAttempt"], Awaitable[None]]


FACADE_VERSIONS = ("/v1.0", "/beta")
FACADE_HEADERS = frozenset({("ConsistencyLevel", "eventual")})


@dataclass(frozen=True, slots=True)
class FacadePage:
    """A facade request's answer from Graph: 200 with its JSON body (and nextLink,
    if any), or a final Graph error status with its bounded body."""

    http_status: int
    body: bytes = field(repr=False)
    graph_request_id: str | None
    next_link: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class GraphAttempt:  # one per HTTP attempt; audited by the caller before/after
    attempt: int
    method: str
    request_target: str  # path + query, no host
    http_status: int | None
    graph_request_id: str | None
    duration_ms: int
    item_count: int | None


def new_graph_client() -> httpx.AsyncClient:
    """A client the transport accepts: no redirects, no environment proxy
    or CA settings, no auth or hooks, bounded timeouts, TLS verified."""
    return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False, trust_env=False)


def parse_retry_after(value: str | None, *, now: datetime) -> float | None:
    """Seconds to wait, from delta-seconds or an HTTP-date; None if absent or unusable."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9]{1,9}", value):
        return float(int(value))
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, (when - now).total_seconds())


def _registry_spec(request: BuiltRequest) -> operations.OperationSpec | None:
    for spec in operations.REGISTRY.values():
        if spec.method == request.method and spec.path_template == request.path_template:
            return spec if spec.kind == "read" and spec.executable else None
    return None


def _checked_target(request: object) -> tuple[str, bool, bool] | None:
    """The request target, whether the operation is paginated and whether it is single, or None."""
    if type(request) is not BuiltRequest or request.method != "GET":
        return None
    if not (isinstance(request.path, str) and type(request.query) is tuple):  # path: target rule below
        return None
    if not all(
        type(item) is tuple and len(item) == 2 and type(item[0]) is str
        and type(item[1]) is str and _QUERY_VALUE.match(item[1])
        for item in request.query
    ):
        return None
    spec = _registry_spec(request)
    # Caller parameters are only those the operation's params model declares ($select, $top); every other
    # parameter must be the registry's own fixed one for this operation, and each of those must be present
    # exactly (SD-053, SD-054).
    if spec is None:
        return None
    caller = {name for field, name in (("select", "$select"), ("top", "$top")) if field in spec.params_model.model_fields}
    if not all(item[0] in caller or item in spec.fixed_query for item in request.query) \
            or not all(item in request.query for item in spec.fixed_query):
        return None
    target = request_target(request)
    if spec is None or len(target) > MAX_REQUEST_TARGET_BYTES or not target_matches_template(target, request.path_template):
        return None
    return target, spec.paginated, spec.single


def _json_object(raw: bytes) -> object:
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)

    def no_constants(name):
        raise ValueError("non-finite number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=no_constants)


def _page(raw: bytes, single: bool = False) -> tuple[list[dict], str | None] | None:
    try:
        body = _json_object(raw)
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        return None
    if not isinstance(body, dict):
        return None
    if single:  # one object (SD-054): never a collection, never a continuation
        if "value" in body or "@odata.nextLink" in body:
            return None
        return [body], None
    value = body.get("value")
    next_link = body.get("@odata.nextLink")
    if type(value) is not list or not all(type(item) is dict for item in value):
        return None
    if next_link is not None and type(next_link) is not str:
        return None
    return value, next_link


def _error_code(raw: bytes) -> str | None:
    try:
        body = _json_object(raw)
    except (ValueError, RecursionError):
        return None
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, str) and _ERROR_CODE.match(code) else None


@dataclass(slots=True)
class _Outcome:
    http_status: int | None = None
    request_id: str | None = None
    body: bytes = b""
    category: str | None = None  # set when the attempt failed before a usable status
    retry_after: str | None = None


class Transport:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        max_attempts: int = 4,
        max_single_wait_s: float = 30.0,
        max_pages: int = 200,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not isinstance(client, httpx.AsyncClient):
            raise ValueError("client must be an httpx.AsyncClient")
        if client.follow_redirects or client.trust_env or client.auth is not None or any(client.event_hooks.values()):
            raise ValueError("client must not follow redirects, trust the environment, or carry auth or event hooks")
        if not (1 <= max_attempts <= 10 and 1 <= max_pages <= 1000 and 0 <= max_single_wait_s <= 300):
            raise ValueError("retry and page bounds out of range")
        if not (0 < max_response_bytes <= max_total_bytes):
            raise ValueError("response size bounds out of range")
        if not all(v is not None and 0 < v <= 60 for v in (timeout.connect, timeout.read, timeout.write, timeout.pool)):
            raise ValueError("every timeout must be set, at most 60 s")
        self._client = client
        self._max_attempts = max_attempts
        self._max_wait = float(max_single_wait_s)
        self._max_pages = max_pages
        self._max_response = max_response_bytes
        self._max_total = max_total_bytes
        self._timeout = timeout
        self._sleep = sleep
        self._clock = clock

    async def execute(
        self,
        request: BuiltRequest,
        token: ValidatedToken,
        *,
        deadline: datetime,
        before_attempt: Hook,
        after_attempt: Hook,
    ) -> list[dict]:
        checked = _checked_target(request)
        if (
            checked is None
            or type(token) is not ValidatedToken
            or not (isinstance(token.access_token, str) and _BEARER.match(token.access_token))
            or not (isinstance(deadline, datetime) and deadline.utcoffset() is not None)
        ):
            raise GraphError("invalid_request")
        target, paginated, single = checked
        items: list[dict] = []
        state = {"attempt": 0, "bytes": 0, "single": single}
        for _ in range(self._max_pages):
            value, next_link = await self._fetch_page(target, token, deadline, state, before_attempt, after_attempt)
            items.extend(value)
            if next_link is None:
                return items
            if not paginated:
                raise GraphError("invalid_next_link")
            target = validate_next_link(next_link, original=request)
        raise GraphError("page_cap")

    async def _fetch_page(
        self, target: str, token: ValidatedToken, deadline: datetime, state: dict, before: Hook, after: Hook
    ) -> tuple[list[dict], str | None]:
        for try_number in range(1, self._max_attempts + 1):
            now = self._clock()
            if now >= deadline:
                raise GraphError("deadline_exceeded")
            if token.expires_at <= now:
                raise GraphError("token_expired")
            state["attempt"] += 1
            attempt = state["attempt"]
            await before(GraphAttempt(attempt, "GET", target, None, None, 0, None))

            started = time.monotonic()
            outcome = await self._send(target, token, (deadline - now).total_seconds())
            duration_ms = int((time.monotonic() - started) * 1000)

            page = None
            category = outcome.category
            if category is None:
                status = outcome.http_status
                if status == 200:
                    page = _page(outcome.body, state["single"])
                    if page is None:
                        category = "invalid_response"
                    elif state["bytes"] + len(outcome.body) > self._max_total:
                        page, category = None, "response_too_large"
                elif 300 <= status < 400:
                    category = "redirect"
                elif status < 300:
                    category = "invalid_response"
                elif status == 403 and _error_code(outcome.body) == LICENCE_REQUIRED_CODE:
                    category = "licence_required"
                elif status in _STATUS_CATEGORY:
                    category = _STATUS_CATEGORY[status]
                else:
                    category = "server" if status >= 500 else "client_error"

            await after(GraphAttempt(
                attempt, "GET", target, outcome.http_status, outcome.request_id, duration_ms,
                len(page[0]) if page is not None else None,
            ))
            if page is not None:
                state["bytes"] += len(outcome.body)
                return page

            retryable = category in ("timeout", "network") or outcome.http_status in RETRY_STATUSES
            if retryable and try_number < self._max_attempts:
                wait = parse_retry_after(outcome.retry_after, now=self._clock())
                wait = min(self._max_wait, float(2 ** (try_number - 1)) if wait is None else wait)
                if self._clock() + timedelta(seconds=wait) >= deadline:
                    raise GraphError("deadline_exceeded", http_status=outcome.http_status,
                                     graph_request_id=outcome.request_id)
                await self._sleep(wait)
                continue
            code = _error_code(outcome.body) if outcome.http_status is not None and outcome.http_status >= 400 else None
            raise GraphError(category, http_status=outcome.http_status, graph_error_code=code,  # type: ignore[arg-type]
                             graph_request_id=outcome.request_id)
        raise AssertionError("unreachable")  # pragma: no cover

    async def fetch_target(
        self,
        target: str,
        *,
        template: str,
        headers: tuple[tuple[str, str], ...],
        token: ValidatedToken,
        deadline: datetime,
        before_attempt: Hook,
        after_attempt: Hook,
    ) -> FacadePage:
        """One page of a facade request (SD-041): the canonical `target` (path and
        query, /v1.0 or /beta) the facade policy approved, sent with the same
        hardening, limits, retries and audit hooks as `execute`. Only the
        allowlisted headers are forwarded. A final Graph error is returned (status
        and bounded body) for the script to see; a redirect, timeout, unusable 200
        or anything else that is not Graph's answer raises GraphError."""
        if (
            not isinstance(target, str)
            or not target.startswith(FACADE_VERSIONS)
            or len(target.encode()) > MAX_REQUEST_TARGET_BYTES
            or not target_matches_template(target, template, versions=FACADE_VERSIONS)
            or type(headers) is not tuple
            or not all(item in FACADE_HEADERS for item in headers)
            or type(token) is not ValidatedToken
            or not (isinstance(token.access_token, str) and _BEARER.match(token.access_token))
            or not (isinstance(deadline, datetime) and deadline.utcoffset() is not None)
        ):
            raise GraphError("invalid_request")
        for try_number in range(1, self._max_attempts + 1):
            now = self._clock()
            if now >= deadline:
                raise GraphError("deadline_exceeded")
            if token.expires_at <= now:
                raise GraphError("token_expired")
            await before_attempt(GraphAttempt(try_number, "GET", target, None, None, 0, None))
            started = time.monotonic()
            outcome = await self._send(target, token, (deadline - now).total_seconds(), extra_headers=headers)
            duration_ms = int((time.monotonic() - started) * 1000)

            category, document = outcome.category, None
            status = outcome.http_status
            if category is None and status == 200:
                try:
                    document = _json_object(outcome.body)
                except (ValueError, RecursionError):
                    document = None
                if not isinstance(document, dict):
                    category = "invalid_response"
            elif category is None and status is not None and status < 400:
                category = "redirect" if 300 <= status < 400 else "invalid_response"
            items = None
            if isinstance(document, dict):
                value = document.get("value")
                items = len(value) if isinstance(value, list) else 1
            await after_attempt(GraphAttempt(try_number, "GET", target, status, outcome.request_id, duration_ms, items))
            if isinstance(document, dict):
                link = document.get("@odata.nextLink")
                return FacadePage(200, outcome.body, outcome.request_id, link if isinstance(link, str) else None)

            retryable = category in ("timeout", "network") or status in RETRY_STATUSES
            if retryable and try_number < self._max_attempts:
                wait = parse_retry_after(outcome.retry_after, now=self._clock())
                wait = min(self._max_wait, float(2 ** (try_number - 1)) if wait is None else wait)
                if self._clock() + timedelta(seconds=wait) >= deadline:
                    raise GraphError("deadline_exceeded", http_status=status, graph_request_id=outcome.request_id)
                await self._sleep(wait)
                continue
            if category is None and status is not None and status >= 400:
                return FacadePage(status, outcome.body, outcome.request_id, None)
            raise GraphError(category or "invalid_response", http_status=status,  # type: ignore[arg-type]
                             graph_request_id=outcome.request_id)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _send(self, target: str, token: ValidatedToken, remaining_s: float, *,
                    extra_headers: tuple[tuple[str, str], ...] = ()) -> _Outcome:
        url = httpx.URL(GRAPH_ORIGIN + target)
        if url.scheme != "https" or url.host != GRAPH_HOST or url.port is not None or url.raw_path.decode() != target:
            return _Outcome(category="invalid_request")
        bound = max(0.001, remaining_s)
        t = self._timeout
        timeout = httpx.Timeout(connect=min(t.connect, bound), read=min(t.read, bound),
                                write=min(t.write, bound), pool=min(t.pool, bound))
        request = httpx.Request(
            "GET", url,
            headers={"Authorization": f"Bearer {token.access_token}", "Accept": "application/json",
                     "Accept-Encoding": "identity", **dict(extra_headers)},
            extensions={"timeout": timeout.as_dict()},
        )
        outcome = _Outcome()
        try:
            async with asyncio.timeout(bound):
                response = await self._client.send(request, stream=True, follow_redirects=False, auth=None)
                try:
                    await self._read(response, outcome)
                finally:
                    await response.aclose()
        except TimeoutError:
            outcome = _Outcome(http_status=outcome.http_status, request_id=outcome.request_id,
                               category="deadline_exceeded")
        except httpx.TimeoutException:
            outcome = _Outcome(category="timeout")
        except httpx.HTTPError:
            outcome = _Outcome(category="network")
        return outcome

    async def _read(self, response: httpx.Response, outcome: _Outcome) -> None:
        outcome.http_status = response.status_code
        request_id = response.headers.get("request-id")  # A-16
        outcome.request_id = request_id if request_id and _REQUEST_ID.match(request_id) else None
        outcome.retry_after = response.headers.get("retry-after")
        success = response.status_code == 200
        limit = self._max_response if success else MAX_ERROR_BODY_BYTES
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            outcome.category = "invalid_response"
            return
        declared = response.headers.get("content-length")
        if success and declared is not None and (not declared.isdigit() or int(declared) > limit):
            outcome.category = "response_too_large"
            return
        body = bytearray()
        async for chunk in response.aiter_raw():
            body += chunk
            if len(body) > limit:
                if success:
                    outcome.category = "response_too_large"
                    return
                del body[limit:]
                break
        outcome.body = bytes(body)
