"""The public API (Task 16): sign-in, task catalog, runs and tenant-scoped
audit views (architecture.md §5).

Every route except sign-in requires a session; the tenant is always taken
from that session, never from the request. `create_app` wires the database
session factory, the fail-closed audit writer and the task catalog onto the
app, and installs per-route rate limiting (SD-027) as an app-level
dependency. Validation and unexpected errors are turned into small, fixed
JSON bodies, so a 422 never echoes the submitted value and a 500 never
carries a traceback or internal detail.

Nothing is built at import; `create_production_app` reads the deployment's
settings. The API holds no Graph credentials and builds no Graph request:
it imports only the three catalog-facing broker modules (manifest, profiles,
operations), enforced by the import-boundary test.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.api.middleware.rate_limit import enforce_rate_limit
from clw.api.routes.agent_sessions import router as agent_sessions_router
from clw.api.routes.audit import router as audit_router
from clw.api.routes.auth import router as auth_router
from clw.api.routes.runs import router as runs_router
from clw.api.routes.scripts import router as scripts_router
from clw.api.routes.tasks import router as tasks_router
from clw.api.ui.agent_pages import router as agent_ui_router
from clw.api.ui.demo_signin import router as demo_signin_router
from clw.api.ui.pages import set_demo_banner
from clw.api.ui.pages import router as ui_router
from clw.audit.writer import AuditWriter
from clw.auth.redis import verify_redis_available_in_production
from clw.broker.manifest import TaskManifest

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Production refuses to start without a reachable Redis: session
    # revocation and rate limits live there (SD-011, SD-027). Elsewhere a no-op.
    await verify_redis_available_in_production()
    yield


def create_app(
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    writer: AuditWriter,
    catalog: Mapping[str, TaskManifest],
    agent_catalog: Mapping[str, TaskManifest] = MappingProxyType({}),
    rate_limited: bool = True,
    demo_mode: bool = False,
    mcp_public_url: str | None = None,
) -> FastAPI:
    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None,
        dependencies=[Depends(enforce_rate_limit)] if rate_limited else [],
        lifespan=_lifespan,
    )
    app.state.sessionmaker = sessionmaker
    app.state.writer = writer
    app.state.catalog = catalog
    app.state.agent_catalog = agent_catalog
    app.state.demo_mode = demo_mode
    if mcp_public_url:
        app.state.mcp_public_url = mcp_public_url
    set_demo_banner(demo_mode)

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # A fixed body: the default handler echoes the submitted input (a
        # tenant_id value, a bad param), which this never returns.
        return JSONResponse({"detail": "invalid_request"}, status_code=422)

    @app.exception_handler(Exception)
    async def _on_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Never leak an internal exception message or traceback to the client.
        logger.error("api_unhandled_error path=%s type=%s", request.url.path, type(exc).__name__)
        return JSONResponse({"detail": "internal_error"}, status_code=500)

    app.include_router(auth_router)
    app.include_router(tasks_router)
    app.include_router(runs_router)
    app.include_router(scripts_router)
    app.include_router(audit_router)
    app.include_router(agent_sessions_router)  # SD-049
    app.include_router(ui_router)  # the demo pages (SD-045)
    app.include_router(agent_ui_router)  # agent sessions and proposals (SD-049, SD-054)
    if demo_mode:  # the fictional tenant's sign-in (SD-051); the route does not exist otherwise
        app.include_router(demo_signin_router)
    return app


def create_production_app() -> FastAPI:  # pragma: no cover - wiring only; needs the deployment
    from clw.api.catalog import load_agent_catalog, load_api_catalog
    from clw.common.config import get_settings
    from clw.db.session import get_sessionmaker
    from clw.demo import check_api

    settings = get_settings()
    check_api(settings)  # SD-051: demo mode never starts in production or beside real sign-in settings
    sessionmaker = get_sessionmaker()
    return create_app(sessionmaker=sessionmaker, writer=AuditWriter(sessionmaker), catalog=load_api_catalog(),
                      agent_catalog=load_agent_catalog(), demo_mode=settings.CLW_DEMO_MODE,
                      mcp_public_url=settings.CLW_MCP_PUBLIC_URL)
