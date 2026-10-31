"""Sign-in and logout routes (Task 6, SD-029). Route names are the rate-limit
contract (SD-027)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from clw.api.deps import current_session
from clw.api.routes.agent_sessions import end_sessions_started_by
from clw.api.runtime import get_sessionmaker, get_writer
from clw.auth.denylist import RevocationUnavailable, revoke
from clw.auth.session_jwt import SESSION_COOKIE_NAME, SESSION_TTL_SECONDS, SessionClaims
from clw.auth.signin import LOGIN_COOKIE_NAME, LOGIN_TTL_SECONDS, SignInError, complete_sign_in, start_sign_in
from clw.common.config import get_settings
from clw.db.session import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth")

_LOGIN_COOKIE_PATH = "/auth/microsoft/callback"
_CLIENT_DETAIL = {400: "sign_in_failed", 401: "sign_in_failed", 403: "access_denied", 500: "sign_in_unavailable"}


def _secure() -> bool:
    return get_settings().is_production


def _post_login_path() -> str:
    path = get_settings().POST_LOGIN_PATH
    # A fixed local path only: no scheme, no host, no protocol-relative "//".
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "://" in path:
        logger.warning("sign_in_refused reason=post_login_path_invalid (POST_LOGIN_PATH must be a local path)")
        raise HTTPException(status_code=500, detail="sign_in_unavailable")
    return path


def _refused(exc: SignInError) -> JSONResponse:
    logger.warning("sign_in_refused reason=%s detail=%s", exc.reason, exc.detail or "-")
    response = JSONResponse({"detail": _CLIENT_DETAIL[exc.status_code]}, status_code=exc.status_code)
    response.delete_cookie(LOGIN_COOKIE_NAME, path=_LOGIN_COOKIE_PATH)
    return response


@router.get("/microsoft/start", name="auth_microsoft_start")
async def microsoft_start(db: AsyncSession = Depends(get_session)) -> Response:
    try:
        started = await start_sign_in(db)
    except SignInError as exc:
        return _refused(exc)
    response = RedirectResponse(started.authorize_url, status_code=302)
    response.set_cookie(
        LOGIN_COOKIE_NAME, started.login_cookie, max_age=LOGIN_TTL_SECONDS, path=_LOGIN_COOKIE_PATH,
        httponly=True, secure=_secure(), samesite="lax",
    )
    return response


@router.get("/microsoft/callback", name="auth_microsoft_callback")
async def microsoft_callback(request: Request, db: AsyncSession = Depends(get_session)) -> Response:
    # Only `state` and `code` are read. Anything else Microsoft or an attacker
    # appends (tid, session_state, error, ...) is ignored.
    try:
        result = await complete_sign_in(
            db,
            state=request.query_params.get("state"),
            code=request.query_params.get("code"),
            login_cookie=request.cookies.get(LOGIN_COOKIE_NAME),
        )
    except SignInError as exc:
        return _refused(exc)
    response = RedirectResponse(_post_login_path(), status_code=303)
    response.delete_cookie(LOGIN_COOKIE_NAME, path=_LOGIN_COOKIE_PATH)
    response.set_cookie(
        SESSION_COOKIE_NAME, result.session_token, max_age=SESSION_TTL_SECONDS, path="/",
        httponly=True, secure=_secure(), samesite="lax",
    )
    return response


@router.post("/logout", name="auth_logout", status_code=204)
async def logout(session: SessionClaims = Depends(current_session), sessionmaker=Depends(get_sessionmaker),
                 writer=Depends(get_writer)) -> Response:
    try:
        await revoke(session.jti, session.expires_at)
    except RevocationUnavailable:
        # Fail visibly: the session is not revoked, so the cookie is kept.
        raise HTTPException(status_code=503, detail="logout_unavailable") from None
    await end_sessions_started_by(sessionmaker, writer, session.tid, session.oid)  # SD-055
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
