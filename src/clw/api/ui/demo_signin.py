"""The quick start's sign-in to the fictional tenant (v0.1; SD-051).

    GET  /ui/demo-signin   explain, and offer the sign-in button
    POST /ui/demo-signin   (same origin) sign in as the fictional tenant's one person

Included only when the api runs in demo mode (create_app(demo_mode=True)),
which clw.demo.check_api refuses in production and beside any real Entra
sign-in setting; otherwise the route does not exist. It can sign in only the
reserved fictional tenant's registered person: never another tenant, never a
name or tenant taken from the request.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from clw.api.routes.auth import _secure
from clw.api.runtime import get_sessionmaker
from clw.api.ui.pages import _error, _render, _same_origin, _see_other
from clw.auth.session_jwt import SESSION_COOKIE_NAME, SESSION_TTL_SECONDS, issue_session
from clw.db.models.workbench_user import WorkbenchUser
from clw.demo import DEMO_TENANT_ID, DEMO_USER_OID

router = APIRouter(prefix="/ui")


@router.get("/demo-signin", name="ui_demo_signin")
async def demo_signin_page(request: Request):
    return _render("demo_signin.html")


@router.post("/demo-signin", name="ui_demo_signin_post")
async def demo_signin(request: Request, sessionmaker=Depends(get_sessionmaker)):
    if not _same_origin(request):
        return _error(403, "cross_origin_refused")
    async with sessionmaker() as session:
        user = (await session.execute(select(WorkbenchUser).where(
            WorkbenchUser.tenant_id == DEMO_TENANT_ID, WorkbenchUser.oid == DEMO_USER_OID))).scalar_one_or_none()
    if user is None:
        return _error(503, "demo_tenant_not_set_up")
    token = issue_session(user_id=user.id, oid=user.oid, tid=DEMO_TENANT_ID, role=user.role)
    response = _see_other("/ui/sessions")
    response.set_cookie(SESSION_COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, path="/", httponly=True,
                        secure=_secure(), samesite="lax")
    return response
