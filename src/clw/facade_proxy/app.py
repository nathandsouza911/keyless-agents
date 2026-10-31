"""The facade proxy (SD-041): what a script reaches when it calls Graph.

On the script runs' network (`clw_scriptnet`, internal) this container holds
the Graph host's name as a network alias and serves TLS with a certificate
from the deployment's own CA, trusted only inside the PowerShell task image.
It forwards every request, unchanged and undecided, to the broker's
POST /v1/facade over `facadenet` (internal) and returns the broker's answer.

It holds no credential, no policy and no Graph access: the broker decides
everything. It reads the raw request line as received (method, path and
query before any decoding), the Authorization and ConsistencyLevel headers,
and only the length of any body (up to a cap; the body itself is never
forwarded, since the facade refuses every request with one). The broker is
deliberately on neither network that carries the alias, so its own lookups of
the Graph host reach Microsoft.
"""

from __future__ import annotations

import os

import httpx

MAX_BODY_BYTES = 64 * 1024
_TIMEOUT = httpx.Timeout(10.0, read=960.0)  # the broker bounds each request by the run's deadline
_PASSED_HEADERS = ("content-type", "request-id", "cache-control")


def _broker_url() -> str:
    url = os.environ.get("CLW_FACADE_BROKER_URL", "")
    if not url.startswith(("http://", "https://")) or url.count("/") != 2:
        raise RuntimeError("CLW_FACADE_BROKER_URL must be scheme://host[:port]")
    return url


def _header(scope: dict, name: bytes) -> str | None:
    values = [v for k, v in scope.get("headers", []) if k.lower() == name]
    return values[0].decode("latin-1") if len(values) == 1 else None


async def _body_length(receive) -> int:
    length, more = 0, True
    while more:
        message = await receive()
        length += len(message.get("body", b""))
        more = message.get("more_body", False)
        if length > MAX_BODY_BYTES:
            return length  # enough to refuse; the rest is not read
    return length


def create_app(*, broker_url: str | None = None, client: httpx.AsyncClient | None = None):
    target_url = (broker_url or _broker_url()) + "/v1/facade"
    http = client or httpx.AsyncClient(timeout=_TIMEOUT, trust_env=False, follow_redirects=False)

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await http.aclose()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        raw_path = scope.get("raw_path") or scope["path"].encode()
        query = scope.get("query_string", b"")
        target = (raw_path + (b"?" + query if query else b"")).decode("latin-1")
        envelope = {
            "method": scope["method"], "target": target,
            "authorization": _header(scope, b"authorization"),
            "consistency_level": _header(scope, b"consistencylevel"),
            "body_length": await _body_length(receive),
        }
        try:
            reply = await http.post(target_url, json=envelope)
            status, body = reply.status_code, reply.content
            headers = [(k.encode(), v.encode()) for k, v in reply.headers.items() if k.lower() in _PASSED_HEADERS]
        except httpx.HTTPError:
            status = 503
            body = b'{"error":{"code":"serviceNotAvailable","message":"Cloud Locksmith: broker_unreachable",' \
                   b'"innerError":{"clw-reason":"broker_unreachable"}}}'
            headers = [(b"content-type", b"application/json")]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return app


def create_production_app():  # pragma: no cover - wiring only
    return create_app()
