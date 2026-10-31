"""GraphSecurityClient: the task's only way to reach Graph (Task 13; SD-002).

A task names an operation and its parameters; the broker decides, builds the
Graph request, and returns the data. The client sends exactly
`POST <broker>/v1/ops` with `Authorization: RunToken <token>` and the body
`{"op": ..., "params": ...}`: no path, URL, method or header of the task's
own, and no tenant (the broker takes it from the run).

It reads only CLW_RUN_TOKEN and CLW_BROKER_URL, and only in from_env(). The
HTTP client ignores the environment (no proxy, netrc, certificate or
SSLKEYLOGFILE variables; OpenSSL itself may consult its own when the broker
URL is https) and follows no redirects. Nothing is retried: the broker retries
Graph itself, and a client retry would execute the operation again.

Replies (SD-032):
  200 {"status": "ok", "data": [...]}         the result of call()
  401/403 {"status": "denied", "reason"}      OperationDenied(reason)
  502 {"status": "failed", "reason"}          BrokerError(reason): the run has failed
  503 {"status": "error", "reason"}           BrokerError(reason): the run is halted
Anything else is BrokerError("invalid_broker_response"), and a request that
gets no reply is BrokerError("broker_unreachable"). OperationDenied is a
BrokerError, so a task that catches BrokerError cannot miss a denial.
The token never appears in a message, repr or traceback.
"""

from __future__ import annotations

import json
import os
import re
import ssl

import httpx

ENV_RUN_TOKEN = "CLW_RUN_TOKEN"
ENV_BROKER_URL = "CLW_BROKER_URL"
OPS_PATH = "/v1/ops"
LIST_USERS = "users.list_with_sign_in_activity"
# What the Dormant Account task classifies and reports; nothing more is requested.
USER_FIELDS = ("id", "userPrincipalName", "displayName", "accountEnabled", "createdDateTime", "signInActivity")

_ORIGIN = re.compile(r"(?P<scheme>https?)://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
                     r"(?::(?P<port>[0-9]{1,5}))?/?\Z")
_RUN_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")  # the broker's issued shape (SD-032)
_REASON = re.compile(r"[a-z0-9_]{1,64}\Z")
# The broker bounds every operation by the run's deadline (at most 900 s,
# the longest manifest timeout); the read timeout is only a backstop.
_TIMEOUT = httpx.Timeout(10.0, read=960.0)


class BrokerError(Exception):
    """The broker did not return data. The message is the reason only."""

    def __init__(self, reason: str, *, status_code: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class OperationDenied(BrokerError):
    """The broker refused the operation (401/403)."""


def _reason(value: object) -> str:
    return value if isinstance(value, str) and _REASON.match(value) else "unknown"


def _tls_context() -> ssl.SSLContext:
    # Built here, not by ssl.create_default_context() (which httpx would call):
    # that one reads SSLKEYLOGFILE from the environment and would write TLS
    # session keys to the file it names.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies certificate and hostname
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs()
    return context


def _ops_url(broker_url: object) -> str:
    match = _ORIGIN.match(broker_url) if isinstance(broker_url, str) else None
    port = match["port"] if match else None
    if match is None or (port is not None and not 1 <= int(port) <= 65535):
        raise ValueError(f"{ENV_BROKER_URL} must be http(s)://host[:port] with nothing else")
    return f"{match['scheme']}://{match['host']}{':' + port if port else ''}{OPS_PATH}"


class GraphSecurityClient:
    __slots__ = ("_url", "_authorization", "_http")

    def __init__(self, broker_url: str, run_token: str, *, http_client: httpx.Client | None = None) -> None:
        self._url = _ops_url(broker_url)
        if not (isinstance(run_token, str) and _RUN_TOKEN.match(run_token)):
            raise ValueError(f"{ENV_RUN_TOKEN} does not have the shape of a run token")
        self._authorization = f"RunToken {run_token}"
        self._http = http_client or httpx.Client(verify=_tls_context(), timeout=_TIMEOUT, trust_env=False,
                                                 follow_redirects=False)

    @classmethod
    def from_env(cls) -> GraphSecurityClient:
        token = os.environ.get("CLW_RUN_TOKEN")
        url = os.environ.get("CLW_BROKER_URL")
        for name, value in ((ENV_RUN_TOKEN, token), (ENV_BROKER_URL, url)):
            if not value:
                raise ValueError(f"{name} is not set")
        return cls(url, token)  # type: ignore[arg-type]

    @property
    def broker_url(self) -> str:
        return self._url

    def __repr__(self) -> str:
        return f"GraphSecurityClient({self._url!r})"

    def __enter__(self) -> GraphSecurityClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def call(self, op: str, params: dict) -> dict:
        """POST {op, params}; the broker's reply body when it returned data."""
        if not isinstance(op, str) or not isinstance(params, dict):
            raise TypeError("op must be a string and params a dict")
        content = json.dumps({"op": op, "params": params}, allow_nan=False, separators=(",", ":"))
        try:
            response = self._http.post(self._url, content=content.encode("utf-8"), headers={
                "Authorization": self._authorization, "Content-Type": "application/json",
                "Accept": "application/json"})
        except httpx.HTTPError:
            raise BrokerError("broker_unreachable") from None
        status = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = None
        kind = body.get("status") if isinstance(body, dict) else None
        if status == 200 and kind == "ok" and isinstance(body.get("data"), list):
            return body
        if status in (401, 403) and kind == "denied":
            raise OperationDenied(_reason(body.get("reason")), status_code=status)
        if (status, kind) in ((502, "failed"), (503, "error")):
            raise BrokerError(_reason(body.get("reason")), status_code=status)
        raise BrokerError("invalid_broker_response", status_code=status)

    def list_users_with_sign_in_activity(self) -> list[dict]:
        """Every user in the run's tenant, with USER_FIELDS (all pages; the broker pages)."""
        data = self.call(LIST_USERS, {"select": list(USER_FIELDS)})["data"]
        if not all(isinstance(user, dict) for user in data):
            raise BrokerError("invalid_broker_response", status_code=200)
        return data
