"""Server-rendered demo pages for bring-your-own scripts (Part B, M7; SD-045).

    GET  /ui                          sign in, or submit a script and see the tenant's scripts
    POST /ui/scripts                  submit (analyst, security lead)
    GET  /ui/scripts/{sha256}         the analysis: summary, risk flags, proposed manifest
    POST /ui/scripts/{sha256}/approve approve a manifest (security lead; never the submitter)
    POST /ui/scripts/{sha256}/run     run it under its latest approval
    GET  /ui/runs/{run_id}            the run: status, the script's output, its audit trail
    POST /ui/signout                  sign out: revoke the session, clear its cookie

The pages are a thin layer over the JSON routes: each action calls the same
route function, so every check (role, own-script refusal, completed
analysis, write-ahead audit, tenant from the session only) is the API's.
They add only what a browser needs:

  - Everything rendered is escaped (Jinja2 autoescape), and a script's output
    is shown as text in <pre>, never as HTML.
  - No JavaScript at all: the Content-Security-Policy allows none, inline
    styles only, forms to this origin only, no framing.
  - A form post must carry this page's own Origin, on top of the session
    cookie's SameSite=Lax (SD-045): a cross-site form is refused.
  - Forms are application/x-www-form-urlencoded, parsed here with a size
    bound (no multipart dependency).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from sqlalchemy import select

from clw.api.deps import Principal, current_session
from clw.api.routes import runs as runs_routes
from clw.api.routes import scripts as scripts_routes
from clw.api.runtime import get_catalog, get_sessionmaker, get_writer
from clw.auth.denylist import RevocationUnavailable, revoke
from clw.auth.session_jwt import SESSION_COOKIE_NAME
from clw.db.models.script import Script, ScriptAnalysis

router = APIRouter(prefix="/ui")

MAX_FORM_BYTES = 2 * scripts_routes.MAX_SCRIPT_BYTES + 4096  # url-encoding at most doubles UTF-8 text in practice
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
    # same-origin, not no-referrer: under no-referrer browsers send "Origin: null"
    # on form posts, which the origin check refuses (found in the first browser use).
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}
_TEMPLATES = Environment(loader=FileSystemLoader(Path(__file__).with_name("templates")), autoescape=True,
                         undefined=StrictUndefined)


def set_demo_banner(on: bool) -> None:
    """Every page carries the DEMO MODE banner while the app runs in demo mode (SD-051)."""
    _TEMPLATES.globals["demo_mode"] = bool(on)


def _render(name: str, *, status: int = 200, principal: Principal | None = None, **context) -> HTMLResponse:
    html = _TEMPLATES.get_template(name).render(principal=principal, **context)
    return HTMLResponse(html, status_code=status, headers=SECURITY_HEADERS)


def _error(status: int, detail: str, principal: Principal | None = None) -> HTMLResponse:
    # `detail` is always one of the API's fixed codes, never request input.
    return _render("error.html", status=status, principal=principal, status_code=status, detail=detail)


def _see_other(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303, headers=SECURITY_HEADERS)


async def _principal(request: Request) -> Principal | None:
    try:
        session = await current_session(request)
    except HTTPException:
        return None
    return Principal(user_id=session.user_id, oid=session.oid, tid=session.tid, role=session.role)


def _same_origin(request: Request) -> bool:
    return request.headers.get("origin") == f"{request.url.scheme}://{request.url.netloc}"


async def _form(request: Request) -> dict[str, str] | None:
    """The posted fields (one value each), or None if this is not a bounded url-encoded form."""
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/x-www-form-urlencoded":
        return None
    body = await request.body()
    if len(body) > MAX_FORM_BYTES:
        return None
    try:
        fields = parse_qs(body.decode("ascii"), keep_blank_values=True, strict_parsing=bool(body), max_num_fields=4,
                          encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if any(len(values) != 1 for values in fields.values()):
        return None
    return {name: values[0] for name, values in fields.items()}


async def _post_guard(request: Request, roles: tuple[str, ...]) -> tuple[Principal | None, HTMLResponse | None]:
    principal = await _principal(request)
    if principal is None:
        return None, _error(401, "not_authenticated")
    if not _same_origin(request):
        return principal, _error(403, "cross_origin_refused", principal)
    if principal.role not in roles:
        return principal, _error(403, "role_not_allowed", principal)
    return principal, None


@router.get("", name="ui_home")
async def home(request: Request, sessionmaker=Depends(get_sessionmaker)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    async with sessionmaker() as session:
        rows = (await session.execute(
            select(Script.sha256, Script.created_at, ScriptAnalysis.status)
            .join(ScriptAnalysis, ScriptAnalysis.script_id == Script.id, isouter=True)
            .where(Script.tenant_id == principal.tid).order_by(Script.created_at.desc()).limit(50))).all()
    scripts = [{"sha256": r.sha256, "created_at": scripts_routes._dt(r.created_at), "status": r.status} for r in rows]
    return _render("home.html", principal=principal, scripts=scripts)


@router.post("/scripts", name="ui_scripts_submit")
async def submit(request: Request, sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer)):
    principal, refused = await _post_guard(request, ("analyst", "security_lead"))
    if refused is not None:
        return refused
    fields = await _form(request)
    if fields is None or set(fields) != {"text"} or not fields["text"].strip():
        return _error(422, "invalid_request", principal)
    text = fields["text"].replace("\r\n", "\n")  # browsers send CRLF; the script is hashed as LF text
    try:
        created = await scripts_routes.submit(scripts_routes.SubmitBody(text=text), principal=principal,
                                              sessionmaker=sessionmaker, writer=writer)
    except HTTPException as exc:
        return _error(exc.status_code, exc.detail, principal)
    return _see_other(f"/ui/scripts/{created['sha256']}")


@router.get("/scripts/{sha256}", name="ui_scripts_get")
async def script_page(sha256: str, request: Request, sessionmaker=Depends(get_sessionmaker)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    try:
        view = await scripts_routes.get_script(sha256, principal=principal, sessionmaker=sessionmaker)
    except HTTPException as exc:
        return _error(exc.status_code, exc.detail, principal)
    analysis = view["analysis"]
    proposed = json.dumps(analysis["proposed_manifest"], indent=2) if analysis and analysis["proposed_manifest"] else ""
    return _render("script.html", principal=principal, script=view, analysis=analysis, proposed=proposed,
                   pending=analysis is not None and analysis["status"] in ("queued", "running"))


@router.post("/scripts/{sha256}/approve", name="ui_scripts_approve")
async def approve(sha256: str, request: Request, sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer)):
    principal, refused = await _post_guard(request, ("security_lead",))
    if refused is not None:
        return refused
    fields = await _form(request)
    if fields is None or set(fields) != {"manifest"}:
        return _error(422, "invalid_request", principal)
    try:
        manifest = json.loads(fields["manifest"])
    except ValueError:
        return _error(422, "manifest_not_json", principal)
    if not isinstance(manifest, dict):
        return _error(422, "manifest_not_json", principal)
    try:
        await scripts_routes.approve(sha256, scripts_routes.ApproveBody(manifest=manifest), principal=principal,
                                     sessionmaker=sessionmaker, writer=writer)
    except HTTPException as exc:
        # A refused manifest's detail names the rule it broke (no request values).
        return _error(exc.status_code, exc.detail, principal)
    return _see_other(f"/ui/scripts/{sha256}")


@router.post("/scripts/{sha256}/run", name="ui_runs_create")
async def run(sha256: str, request: Request, sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer),
              catalog=Depends(get_catalog)):
    principal, refused = await _post_guard(request, ("analyst", "security_lead"))
    if refused is not None:
        return refused
    fields = await _form(request)
    if fields is None or fields:
        return _error(422, "invalid_request", principal)
    try:
        body = runs_routes.CreateRunBody(script_sha256=scripts_routes._sha(sha256))
        created = await runs_routes.create_run(body, principal=principal, catalog=catalog,
                                               sessionmaker=sessionmaker, writer=writer)
    except HTTPException as exc:
        return _error(exc.status_code, exc.detail, principal)
    return _see_other(f"/ui/runs/{created['id']}")


@router.get("/runs/{run_id}", name="ui_runs_get")
async def run_page(run_id: str, request: Request, sessionmaker=Depends(get_sessionmaker)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    try:
        run_view = await runs_routes.get_run(run_id, principal=principal, sessionmaker=sessionmaker)
        audit = await runs_routes.get_run_audit(run_id, principal=principal, sessionmaker=sessionmaker)
    except HTTPException as exc:
        return _error(exc.status_code, exc.detail, principal)
    result = run_view.get("result")
    other_result = json.dumps(result, indent=2) if result and result.get("kind") != "script_output" else ""
    return _render("run.html", principal=principal, run=run_view, result=result, other_result=other_result,
                   audit=audit, pending=run_view["status"] in ("queued", "running"))


@router.post("/signout", name="ui_sign_out")
async def sign_out(request: Request):
    """Revoke the session (as POST /auth/logout does) and return to the sign-in page."""
    if not _same_origin(request):
        return _error(403, "cross_origin_refused", await _principal(request))
    try:
        session = await current_session(request)
    except HTTPException:
        return _see_other("/ui")  # no valid session: already signed out
    try:
        await revoke(session.jti, session.expires_at)
    except RevocationUnavailable:
        # Fail visibly: the session is not revoked, so its cookie is kept.
        return _error(503, "logout_unavailable", await _principal(request))
    from clw.api.routes.agent_sessions import end_sessions_started_by

    # Signing out ends the person's own running agent sessions too (SD-055).
    await end_sessions_started_by(request.app.state.sessionmaker, request.app.state.writer, session.tid, session.oid)
    response = _see_other("/ui")
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
