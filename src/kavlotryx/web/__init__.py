"""Web console at /ui (FR-IF-04). Server-rendered, no build step, no external assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kavlotryx import OCSF_VERSION, __version__
from kavlotryx.adapters import AdapterError, available_adapters
from kavlotryx.api.auth import INGEST, READ, WRITE, Principal
from kavlotryx.dispatch.base import TrackerError
from kavlotryx.service import Kavlotryx, NotFound
from kavlotryx.web import session, views

HERE = Path(__file__).parent


def _fmt_dt(v) -> str:
    return v.strftime("%Y-%m-%d %H:%M UTC") if v else ""


def _ago(v) -> str:
    if not v:
        return ""
    from kavlotryx.db import utcnow

    now = utcnow()
    if v.tzinfo is None:
        v = v.replace(tzinfo=now.tzinfo)
    secs = int((now - v).total_seconds())
    if secs < 60:
        return "just now"
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return ""


def _short(v: str, n: int = 18) -> str:
    v = v or ""
    return v if len(v) <= n + 1 else v[:n] + "…"


def mount_console(app: FastAPI, svc: Kavlotryx) -> None:
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    env = templates.env
    env.filters.update(dt=_fmt_dt, ago=_ago, short=_short, sev=views.sev_name)
    env.globals.update(version=__version__, ocsf_version=OCSF_VERSION, rule_family=views.rule_family)
    app.mount("/ui/static", StaticFiles(directory=str(HERE / "static")), name="ui-static")

    settings = svc.settings
    dialect = svc.engine.dialect.name
    tracker_label = ("Jira " + urlsplit(settings.jira_url).netloc) if settings.tracker == "jira" else "fake tracker"

    def render(request: Request, name: str, ctx: dict[str, Any], who: Principal, status: int = 200) -> Response:
        summary = svc.summary()
        flash = session.pop_flash(request)
        base = {
            "request": request, "who": who, "csrf": session.csrf_token(request), "flash": flash,
            "metrics": summary["metrics"], "dialect": dialect, "tracker": tracker_label,
            "can_write": who.role in WRITE, "can_ingest": who.role in INGEST,
            "auth_off": request.app.state.tokens is None, "path": request.url.path,
        }
        resp = templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        if flash:
            resp.delete_cookie(session.FLASH, path="/")
        return resp

    @app.exception_handler(session.LoginRequired)
    async def _login(request: Request, _exc: session.LoginRequired):
        nxt = request.url.path if request.method == "GET" else "/ui"
        return RedirectResponse(f"/ui/login?next={nxt}", status_code=303)

    @app.exception_handler(session.CsrfError)
    async def _csrf(request: Request, _exc: session.CsrfError):
        return HTMLResponse("Form expired or came from another site. Go back, reload and try again.",
                            status_code=403)

    @app.exception_handler(session.Forbidden)
    async def _forbidden(request: Request, exc: session.Forbidden):
        return session.redirect(back(request, "/ui"), "error", f"The {exc.role} role cannot do this.")

    def writer(request: Request, csrf: str | None) -> Principal:
        who = session.current(request)
        session.check_csrf(request, csrf)
        if who.role not in WRITE:
            raise session.Forbidden(who.role)
        return who

    def back(request: Request, fallback: str) -> str:
        ref = request.headers.get("referer", "")
        parts = urlsplit(ref)
        if parts.netloc == request.headers.get("host") and parts.path.startswith("/ui"):
            return parts.path + (f"?{parts.query}" if parts.query else "")
        return fallback

    # -- sign in ----------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/ui", status_code=307)

    @app.get("/ui/login", include_in_schema=False)
    def login_form(request: Request, next: str = "/ui", error: str = ""):
        if request.app.state.tokens is None:
            return RedirectResponse("/ui", status_code=303)
        resp = templates.TemplateResponse(request, "login.html", {
            "request": request, "next": next if next.startswith("/ui") else "/ui", "error": error})
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'"
        return resp

    @app.post("/ui/login", include_in_schema=False)
    def login(request: Request, token: str = Form(""), next: str = Form("/ui")):
        tokens = request.app.state.tokens or {}
        h = session.token_hash(token.strip())
        p = tokens.get(h)
        if p is None:
            return RedirectResponse("/ui/login?error=invalid", status_code=303)
        if p.role not in READ:
            return RedirectResponse("/ui/login?error=role", status_code=303)
        resp = RedirectResponse(next if next.startswith("/ui") else "/ui", status_code=303)
        session.issue(resp, request, h)
        return resp

    @app.post("/ui/logout", include_in_schema=False)
    def logout(request: Request, csrf: str = Form("")):
        session.check_csrf(request, csrf)
        resp = RedirectResponse("/ui/login", status_code=303)
        session.clear(resp)
        return resp

    # -- pages ----------------------------------------------------------------

    @app.get("/ui", include_in_schema=False)
    def overview(request: Request):
        who = session.current(request)
        summary = svc.summary()
        with svc.session() as s:
            ladder, total, review = views.rule_ladder(s)
            data = views.overview(s, summary)
        return render(request, "overview.html", {"summary": summary, "ladder": ladder,
                                                 "ladder_total": total, "review": review, **data}, who)

    @app.get("/ui/findings", include_in_schema=False)
    def findings(request: Request, q: str = "", kind: str = "", sev: int = 0, status: str = "open",
                 owner: str = "", conf: str = "", page: int = 1, f: int | None = None, tab: str = "trace"):
        who = session.current(request)
        flt = views.FindingFilter(q=q[:200], kind=kind, sev=sev, status=status, owner=owner, conf=conf, page=page)
        with svc.session() as s:
            ladder, total, review = views.rule_ladder(s)
            data = views.findings_page(s, flt)
            sel_id = f if f is not None else (data["rows"][0].id if data["rows"] else None)
            detail = views.finding_detail(s, sel_id) if sel_id else None
        explain = svc.explain(detail["f"].id) if detail else None
        owners = [o.slug for o in svc.ownership.owners]
        return render(request, "findings.html", {
            "flt": flt, "ladder": ladder, "ladder_total": total, "review": review, **data,
            "detail": detail, "explain": explain, "owner_choices": owners, "tab": tab,
            "limit": svc.policy.confidence_limit}, who)

    @app.post("/ui/findings/{fid}/owner", include_in_schema=False)
    def set_owner(request: Request, fid: int, owner: str = Form(...), match: str = Form("asset"),
                  reason: str = Form(""), csrf: str = Form("")):
        who = writer(request, csrf)
        try:
            svc.set_owner(fid, owner, f"ui:{who.name}", reason[:500], match)
            r = svc.rebuild()
        except (NotFound, ValueError) as e:
            return session.redirect(back(request, "/ui/findings"), "error", str(e))
        return session.redirect(back(request, f"/ui/findings?f={fid}"), "ok",
                                f"Owner set to {owner} ({match}). Rebuilt {r.work_items} work items.")

    @app.get("/ui/workitems", include_in_schema=False)
    def workitems(request: Request, owner: str = "", state: str = ""):
        who = session.current(request)
        with svc.session() as s:
            data = views.workitems_page(s, owner, state)
        return render(request, "workitems.html", {"owner": owner, "state": state, "states": views.STATES,
                                                  "dry": None, **data}, who)

    @app.get("/ui/workitems/{key}", include_in_schema=False)
    def workitem(request: Request, key: str):
        who = session.current(request)
        with svc.session() as s:
            data = views.workitem_detail(s, key)
        if data is None:
            return render(request, "notfound.html", {"what": f"work item {key}"}, who, status=404)
        return render(request, "workitem.html", data, who)

    @app.get("/ui/verify", include_in_schema=False)
    def verify_page(request: Request):
        who = session.current(request)
        with svc.session() as s:
            data = views.verify_page(s)
        adapters = []
        for name, cls in sorted(available_adapters().items()):
            doc = (cls.__module__ and __import__(cls.__module__, fromlist=["_"]).__doc__ or "").strip()
            adapters.append({"name": name, "doc": doc.split("\n")[0]})
        base_url = str(request.base_url).rstrip("/")
        return render(request, "verify.html", {**data, "adapters": adapters, "base_url": base_url}, who)

    # -- actions --------------------------------------------------------------

    @app.post("/ui/actions/{action}", include_in_schema=False)
    def action(request: Request, action: str, csrf: str = Form("")):
        who = writer(request, csrf)
        actor = f"ui:{who.name}"
        try:
            if action == "rebuild":
                r = svc.rebuild()
                msg = (f"Rebuilt: {r.findings} open findings → {r.work_items} work items, "
                       f"{r.needs_review} need owner review.")
            elif action == "dispatch":
                r = svc.dispatch(actor=actor)
                msg = ", ".join(f"{r.count(a)} {a}" for a in ("create", "adopt", "update", "skip", "error")
                                if r.count(a)) or "Nothing to dispatch."
                msg = f"Dispatch: {msg}"
            elif action == "verify":
                r = svc.verify(actor=actor)
                msg = ", ".join(f"{r.count(a)} {a}" for a in ("verified", "pending", "reopened", "resumed",
                                                              "superseded", "missing", "error")
                                if r.count(a)) or "Nothing changed."
                msg = f"Verify: {msg}"
            elif action == "run":
                out = svc.run(actor=actor)
                d = {k: v for k, v in out["dispatch"].items() if v}
                v = {k: n for k, n in out["verify"].items() if n}
                msg = f"Run complete. Dispatch {d or 'no changes'}; verify {v or 'no changes'}."
            elif action == "dry-run":
                svc.rebuild()
                r = svc.dispatch(dry_run=True, actor=actor)
                with svc.session() as s:
                    data = views.workitems_page(s, "", "")
                return render(request, "workitems.html", {"owner": "", "state": "", "states": views.STATES,
                                                          "dry": r.actions, "path": "/ui/workitems", **data}, who)
            else:
                return session.redirect("/ui", "error", f"Unknown action {action}.")
        except TrackerError as e:
            return session.redirect(back(request, "/ui/workitems"), "error", f"Tracker error: {e}")
        return session.redirect(back(request, "/ui/workitems"), "ok", msg)

    @app.post("/ui/scans", include_in_schema=False)
    async def upload(request: Request, scanner: str = Form(...), scope: str = Form(""),
                     file: UploadFile = File(...), csrf: str = Form("")):
        who = session.current(request)
        session.check_csrf(request, csrf)
        if who.role not in INGEST:
            raise session.Forbidden(who.role)
        limit = settings.max_upload_mb * 1024 * 1024
        data = await file.read(limit + 1)
        if len(data) > limit:
            return session.redirect("/ui/verify", "error", f"Upload exceeds {settings.max_upload_mb} MB.")
        try:
            r = svc.ingest(scanner, data, scope=scope.strip() or None, actor=f"ui:{who.name}")
        except (AdapterError, UnicodeDecodeError) as e:
            return session.redirect("/ui/verify", "error", f"Rejected {file.filename}: {e}")
        return session.redirect("/ui/verify", "ok",
                                f"Scan {r.scan_id} ({r.scanner}, {r.scope}): {r.findings_seen} findings, "
                                f"{r.new} new, {r.fixed} fixed, {r.reopened} reopened, {len(r.skipped)} skipped. "
                                "Run the pipeline to update tickets.")
