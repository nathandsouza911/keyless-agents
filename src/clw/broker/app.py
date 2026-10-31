"""Broker HTTP service (Task 12): POST /v1/ops on tasknet only.

    POST /v1/ops   Authorization: RunToken <token>
                   {"op": "<name>", "params": {...}}
    POST /v1/agent/ops      Authorization: Bearer <session capability>   (SD-049, from the MCP gateway)
                   the same body and answers, against the session's agent profile
    POST /v1/agent/propose  Authorization: Bearer <session capability>   (SD-054)
                   {"action": "disable_user", "user_id": GUID, "reason": "..."}: filed, never executed
    POST /v1/agent/session  Authorization: Bearer <session capability>   (SD-048)
    200 {"status": "ok", "session": {"id", "expires_at", "profile", "profile_name", "operations"}}
    200 {"status": "ok", "data": [...]}
    401/403 {"status": "denied", "reason": "<code>"}
    502 {"status": "failed", "reason": "<code>"}      the run has ended FAILED
    503 {"status": "error", "reason": "<code>"}       the run is halted

There is no other route besides the facade's (no docs or OpenAPI either). The body is read raw,
at most MAX_BODY_BYTES, and parsed by the service, so a malformed or
over-wide body is denied and audited rather than answered by the framework.
Nothing is built at import; `create_production_app` wires the real
database, writer, transport, credential provider and manifest catalog.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from clw.broker.facade.handler import graph_error
from clw.broker.manifest import TaskManifest, load_manifest
from clw.broker.service import MAX_BODY_BYTES, BrokerService

TASKS_DIR = Path(__file__).resolve().parents[3] / "tasks"
AGENT_PROFILES_DIR = Path(__file__).resolve().parents[3] / "agent_profiles"
_NO_STORE = {"Cache-Control": "no-store"}


async def _read_body(request: Request) -> bytes | None:
    """The body, or None if it is (or declares itself) larger than the limit."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            return None
    return bytes(body)


def _one_authorization(request: Request) -> str | None:
    values = request.headers.getlist("authorization")
    return values[0] if len(values) == 1 else None


def create_app(service: BrokerService) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/ops", name="broker_ops")
    async def ops(request: Request) -> JSONResponse:
        authorization = request.headers.getlist("authorization")
        result = await service.handle_request(authorization[0] if len(authorization) == 1 else None,
                                              await _read_body(request))
        return JSONResponse(result.body, status_code=result.status_code, headers=_NO_STORE)

    @app.post("/v1/agent/ops", name="broker_agent_ops")
    async def agent_ops(request: Request) -> JSONResponse:
        result = await service.handle_agent_request(_one_authorization(request), await _read_body(request))
        return JSONResponse(result.body, status_code=result.status_code, headers=_NO_STORE)

    @app.post("/v1/agent/propose", name="broker_agent_propose")
    async def agent_propose(request: Request) -> JSONResponse:
        result = await service.handle_agent_proposal(_one_authorization(request), await _read_body(request))
        return JSONResponse(result.body, status_code=result.status_code, headers=_NO_STORE)

    @app.post("/v1/agent/session", name="broker_agent_session")
    async def agent_session(request: Request) -> JSONResponse:
        result = await service.describe_agent_session(_one_authorization(request))
        return JSONResponse(result.body, status_code=result.status_code, headers=_NO_STORE)

    @app.post("/v1/facade", name="broker_facade")
    async def facade(request: Request) -> Response:
        """A script's Graph request, as the facade proxy forwards it (SD-041):
        {"method", "target", "authorization", "consistency_level", "body_length"}.
        Everything is decided by the service; a malformed envelope is a refusal."""
        envelope = _facade_envelope(await _read_body(request))
        if envelope is None:
            reply = graph_error(400, "BadRequest", "invalid_request")
        else:
            headers = {"ConsistencyLevel": envelope["consistency_level"]} if envelope["consistency_level"] else {}
            reply = await service.handle_facade(envelope["authorization"], envelope["method"], envelope["target"],
                                                headers, envelope["body_length"])
        extra = {"request-id": reply.graph_request_id} if reply.graph_request_id else {}
        return Response(reply.body, status_code=reply.status_code, media_type="application/json",
                        headers={**_NO_STORE, **extra})

    return app


_ENVELOPE = {"method": str, "target": str, "authorization": (str, type(None)),
             "consistency_level": (str, type(None)), "body_length": int}


def _facade_envelope(raw: bytes | None) -> dict | None:
    import json

    try:
        envelope = json.loads(raw) if raw is not None else None
    except ValueError:
        return None
    if not isinstance(envelope, dict) or set(envelope) != set(_ENVELOPE):
        return None
    if not all(isinstance(envelope[k], t) and not isinstance(envelope[k], bool) for k, t in _ENVELOPE.items()):
        return None
    return envelope if envelope["body_length"] >= 0 else None


def load_catalog(tasks_dir: Path = TASKS_DIR) -> Mapping[str, TaskManifest]:
    """Every tasks/<dir>/manifest.yaml, keyed by manifest id. Any manifest that
    fails to load stops the broker (fail closed)."""
    catalog: dict[str, TaskManifest] = {}
    for path in sorted(Path(tasks_dir).glob("*/manifest.yaml")):
        manifest = load_manifest(path)
        if manifest.id in catalog:
            raise RuntimeError(f"duplicate task id in {path.parent.name}")
        catalog[manifest.id] = manifest
    return MappingProxyType(catalog)


def create_production_app() -> FastAPI:  # pragma: no cover - wiring only; needs the deployment
    from clw.audit.writer import AuditWriter
    from clw.broker.credentials import MsalCertificateProvider
    from clw.broker.facade.approvals import approved_manifest
    from clw.broker.transport import GRAPH_ORIGIN, Transport, new_graph_client
    from clw.db.session import get_sessionmaker

    sessionmaker = get_sessionmaker()
    service = BrokerService(
        sessionmaker=sessionmaker,
        writer=AuditWriter(sessionmaker),
        transport=Transport(new_graph_client()),
        # The token audience is the origin requests go to (SD-004).
        credentials=MsalCertificateProvider(resource=GRAPH_ORIGIN),
        catalog=load_catalog(),
        script_manifests=approved_manifest,
        agent_catalog=load_catalog(AGENT_PROFILES_DIR),  # SD-049  # the facade serves approved script runs only (SD-043)
    )
    return create_app(service)
