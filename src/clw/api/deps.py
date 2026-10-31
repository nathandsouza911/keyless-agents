"""Request dependencies. current_principal is the ONLY source of tenant for
public routes: it comes from a verified, unrevoked session cookie, never
from the request path, query, headers or body."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from clw.auth.session_jwt import SESSION_COOKIE_NAME, Role, SessionClaims, SessionInvalid, decode_session


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    oid: str
    tid: str
    role: Role


async def current_session(request: Request) -> SessionClaims:
    """The verified session from the session cookie (no Authorization header), or 401."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="not_authenticated")
    try:
        return await decode_session(token)
    except SessionInvalid:
        raise HTTPException(status_code=401, detail="not_authenticated") from None


async def current_principal(session: SessionClaims = Depends(current_session)) -> Principal:
    return Principal(user_id=session.user_id, oid=session.oid, tid=session.tid, role=session.role)


def require_role(*roles: Role):
    """A dependency: the session's principal, or 403 unless its role (from the
    membership row at sign-in, SD-029) is one of `roles` (SD-043)."""
    allowed = frozenset(roles)

    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status_code=403, detail="role_not_allowed")
        return principal

    return dependency
