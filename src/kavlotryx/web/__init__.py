"""Web console at /ui (FR-IF-04). Server-rendered, no build step, no external assets.

Menus: Dashboard (persona) · Vulnerabilities (findings, work items) · Ownership · Scanners · Settings.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kavlotryx import OCSF_VERSION, __version__
from kavlotryx.adapters import AdapterError, available_adapters
from kavlotryx.api.auth import ADMIN, INGEST, READ, WRITE, Principal
from kavlotryx.connectors import CONNECTORS, ConnectorError
from kavlotryx.dispatch.base import TrackerError
from kavlotryx.service import Kavlotryx, NotFound
from kavlotryx.web import pages, session, views

HERE = Path(__file__).parent
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


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


def _hours(h: float | None) -> str:
    if h is None:
        return "never"
    if h < 1:
        return "under 1h"
    return f"{int(h)}h" if h < 48 else f"{int(h // 24)}d"


def _short(v: str, n: int = 18) -> str:
    v = v or ""
    return v if len(v) <= n + 1 else v[:n] + "…"


def _adapters() -> list[dict[str, str]]:
    out = []
    for name, cls in sorted(available_adapters().items()):
        doc = (__import__(cls.__module__, fromlist=["_"]).__doc__ or "").strip().split("\n")[0]
        doc = re.sub(r"\s*\(FR-[A-Z]+-\d+\)|,?\s*FR-[A-Z]+-\d+", "", doc.replace("``", "")).rstrip(" .,:")
        out.append({"name": name, "doc": doc})
    return out


def mount_console(app: FastAPI, svc: Kavlotryx) -> None:
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    env = templates.env
    env.filters.update(dt=_fmt_dt, ago=_ago, short=_short, sev=views.sev_name, hours=_hours)
    env.globals.update(version=__version__, ocsf_version=OCSF_VERSION, rule_family=views.rule_family,
                       personas=pages.PERSONAS)
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
            "can_write": who.role in WRITE, "can_ingest": who.role in INGEST, "is_admin": who.role in ADMIN,
            "auth_off": request.app.state.tokens is None, "path": request.url.path,
        }
        resp = templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status)
        resp.headers["Content-Security-Policy"] = CSP
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

    def back(request: Request, fallback: str) -> str:
        ref = request.headers.get("referer", "")
        parts = urlsplit(ref)
        if parts.netloc == request.headers.get("host") and parts.path.startswith("/ui"):
            return parts.path + (f"?{parts.query}" if parts.query else "")
        return fallback

    @app.exception_handler(session.Forbidden)
    async def _forbidden(request: Request, exc: session.Forbidden):
        return session.redirect(back(request, "/ui"), "error", f"The {exc.role} role cannot do this.")

    def writer(request: Request, csrf: str | None, roles: set[str] = WRITE) -> Principal:
        who = session.current(request)
        session.check_csrf(request, csrf)
        if who.role not in roles:
            raise session.Forbidden(who.role)
        return who

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

    # -- 1. dashboard ---------------------------------------------------------------

    @app.get("/ui", include_in_schema=False)
    def dashboard(request: Request, persona: str = ""):
        who = session.current(request)
        saved, team = svc.get_pref(who.name)
        persona = persona if persona in pages.PERSONA_KEYS else (saved if saved in pages.PERSONA_KEYS else "analyst")
        cfg, policy = svc.ownership, svc.policy
        owners = [o.slug for o in cfg.owners]
        summary = svc.summary()
        with svc.session() as s:
            pipe = pages.pipeline(s, settings, policy)
            data = pages.dashboard(s, persona, team, summary, policy, owners)
        return render(request, "dashboard.html", {"persona": persona, "saved": saved, "team_choices": owners,
                                                  "pipe": pipe, "d": data, "summary": summary}, who)

    @app.post("/ui/prefs", include_in_schema=False)
    def prefs(request: Request, persona: str = Form(""), team: str = Form(""), csrf: str = Form("")):
        who = session.current(request)
        session.check_csrf(request, csrf)
        if persona and persona not in pages.PERSONA_KEYS:
            return session.redirect("/ui", "error", "Unknown persona.")
        if team and team not in {o.slug for o in svc.ownership.owners}:
            return session.redirect("/ui", "error", "Unknown team.")
        svc.set_pref(who.name, persona=persona or None, team=team or None)
        return session.redirect("/ui")

    # -- 2. vulnerabilities -------------------------------------------------------

    def _filter(q: str, sev: list[int], kind: str, status: str, scanner: str, owner: str, rule: str, conf: str,
                account: str, artifact: str, fix: str, prod: str, wi_state: str, ticket: str, age: int, sort: str,
                dir: str, page: int, size: int) -> pages.VulnFilter:
        return pages.VulnFilter(q=q[:200], sev=[x for x in sev if 0 <= x <= 6], kind=kind, status=status,
                                scanner=scanner, owner=owner, rule=rule, conf=conf, account=account,
                                artifact=artifact[:200], fix=fix, prod=prod, wi_state=wi_state, ticket=ticket,
                                age=max(0, age), sort=sort if sort in pages.SORTS else "sev",
                                dir="asc" if dir == "asc" else "desc", page=page, size=size)

    @app.get("/ui/vulnerabilities", include_in_schema=False)
    def vulnerabilities(request: Request, q: str = "", sev: list[int] = Query([]), kind: str = "",  # noqa: B006
                        status: str = "open", scanner: str = "", owner: str = "", rule: str = "", conf: str = "",
                        account: str = "", artifact: str = "", fix: str = "", prod: str = "", wi_state: str = "",
                        ticket: str = "", age: int = 0, sort: str = "sev", dir: str = "desc", page: int = 1,
                        size: int = 50):
        who = session.current(request)
        flt = _filter(q, sev, kind, status, scanner, owner, rule, conf, account, artifact, fix, prod, wi_state,
                      ticket, age, sort, dir, page, size)
        with svc.session() as s:
            data = pages.explorer(s, flt, svc.policy)
        return render(request, "vulnerabilities.html", {"flt": flt, "owners": [o.slug for o in svc.ownership.owners],
                                                        "adapters": sorted(available_adapters()),
                                                        "states": views.STATES, "rule_ladder": views.RULE_LADDER,
                                                        **data}, who)

    @app.get("/ui/vulnerabilities.csv", include_in_schema=False)
    def vulnerabilities_csv(request: Request, q: str = "", sev: list[int] = Query([]), kind: str = "",  # noqa: B006
                            status: str = "open", scanner: str = "", owner: str = "", rule: str = "",
                            conf: str = "", account: str = "", artifact: str = "", fix: str = "", prod: str = "",
                            wi_state: str = "", ticket: str = "", age: int = 0, sort: str = "sev",
                            dir: str = "desc"):
        session.current(request)
        flt = _filter(q, sev, kind, status, scanner, owner, rule, conf, account, artifact, fix, prod, wi_state,
                      ticket, age, sort, dir, 1, 50)
        with svc.session() as s:
            rows = pages.explorer(s, flt, svc.policy, limit_all=50000)["rows"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "severity", "kind", "status", "vulnerability_or_rule", "package", "installed", "fixed",
                    "asset", "artifact", "account", "owner", "owner_rule", "confidence", "needs_review",
                    "work_item", "first_seen", "last_seen", "fingerprint"])
        for f in rows:
            w.writerow([pages.csv_safe(x) for x in (
                f.id, views.sev_name(f.severity_id), f.kind, f.status, f.vuln_id or f.rule_key, f.package,
                f.installed_version, f.fixed_version, f.asset_key, f.artifact, f.account_uid, f.owner_slug,
                f.owner_rule, f"{f.owner_confidence:.2f}", f.needs_review, f.work_item_key,
                _fmt_dt(f.first_seen), _fmt_dt(f.last_seen), f.fingerprint)])
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="kavlotryx-findings.csv"',
                                          "X-Content-Type-Options": "nosniff"})

    @app.get("/ui/vulnerabilities/{fid}", include_in_schema=False)
    def finding(request: Request, fid: int, tab: str = "trace"):
        who = session.current(request)
        with svc.session() as s:
            detail = views.finding_detail(s, fid)
        if detail is None:
            return render(request, "notfound.html", {"what": f"finding {fid}"}, who, status=404)
        return render(request, "finding.html", {"detail": detail, "explain": svc.explain(fid), "tab": tab,
                                                "owner_choices": [o.slug for o in svc.ownership.owners],
                                                "limit": svc.policy.confidence_limit,
                                                "path": "/ui/vulnerabilities"}, who)

    @app.post("/ui/vulnerabilities/{fid}/owner", include_in_schema=False)
    def set_owner(request: Request, fid: int, owner: str = Form(...), match: str = Form("asset"),
                  reason: str = Form(""), csrf: str = Form("")):
        who = writer(request, csrf)
        try:
            svc.set_owner(fid, owner, f"ui:{who.name}", reason[:500], match)
            r = svc.rebuild()
        except (NotFound, ValueError) as e:
            return session.redirect(back(request, f"/ui/vulnerabilities/{fid}"), "error", str(e))
        return session.redirect(back(request, f"/ui/vulnerabilities/{fid}"), "ok",
                                f"Owner set to {owner} ({match}). Rebuilt {r.work_items} work items.")

    @app.get("/ui/workitems", include_in_schema=False)
    def workitems(request: Request, owner: str = "", state: str = ""):
        who = session.current(request)
        with svc.session() as s:
            data = views.workitems_page(s, owner, state)
        return render(request, "workitems.html", {"owner": owner, "state": state, "states": views.STATES,
                                                  "dry": None, "path": "/ui/vulnerabilities", **data}, who)

    @app.get("/ui/workitems/{key}", include_in_schema=False)
    def workitem(request: Request, key: str):
        who = session.current(request)
        with svc.session() as s:
            data = views.workitem_detail(s, key)
        if data is None:
            return render(request, "notfound.html", {"what": f"work item {key}"}, who, status=404)
        return render(request, "workitem.html", {**data, "path": "/ui/vulnerabilities"}, who)

    # old URLs from the first console
    @app.get("/ui/findings", include_in_schema=False)
    def old_findings(request: Request, f: int | None = None):
        if f is not None:
            return RedirectResponse(f"/ui/vulnerabilities/{f}", status_code=308)
        q = urlsplit(str(request.url)).query
        return RedirectResponse("/ui/vulnerabilities" + (f"?{q}" if q else ""), status_code=308)

    @app.get("/ui/verify", include_in_schema=False)
    def old_verify():
        return RedirectResponse("/ui/scanners", status_code=308)

    # -- 3. ownership ---------------------------------------------------------------

    @app.get("/ui/ownership", include_in_schema=False)
    def ownership(request: Request):
        who = session.current(request)
        with svc.session() as s:
            data = pages.ownership(s, svc.ownership, svc.policy, settings)
        return render(request, "ownership.html", {**data, "limit": svc.policy.confidence_limit,
                                                  "cfg": svc.ownership}, who)

    @app.post("/ui/connectors/{name}/sync", include_in_schema=False)
    def connector_sync(request: Request, name: str, csrf: str = Form("")):
        who = writer(request, csrf, ADMIN)
        if name not in CONNECTORS:
            return session.redirect("/ui/ownership", "error", "Unknown connector.")
        try:
            run = svc.sync_connector(name, actor=f"ui:{who.name}")
        except ConnectorError as e:
            return session.redirect("/ui/ownership", "error", f"Sync failed: {e}")
        counts = ", ".join(f"{v} {k}" for k, v in run.counts.items() if isinstance(v, int))
        return session.redirect("/ui/ownership", "ok", f"{name} {run.mode} sync: {counts}. Owners rebuilt.")

    # -- 4. scanners ----------------------------------------------------------------

    @app.get("/ui/scanners", include_in_schema=False)
    def scanners(request: Request):
        who = session.current(request)
        with svc.session() as s:
            data = pages.scanners(s, svc.policy, _adapters())
        return render(request, "scanners.html", {**data, "base_url": str(request.base_url).rstrip("/"),
                                                 "stale_hours": svc.policy.scan_stale_hours}, who)

    @app.post("/ui/scans", include_in_schema=False)
    async def upload(request: Request, scanner: str = Form(...), scope: str = Form(""),
                     file: UploadFile = File(...), csrf: str = Form("")):
        who = writer(request, csrf, INGEST)
        limit = settings.max_upload_mb * 1024 * 1024
        data = await file.read(limit + 1)
        if len(data) > limit:
            return session.redirect("/ui/scanners", "error", f"Upload exceeds {settings.max_upload_mb} MB.")
        try:
            r = svc.ingest(scanner, data, scope=scope.strip() or None, actor=f"ui:{who.name}")
        except (AdapterError, UnicodeDecodeError) as e:
            return session.redirect("/ui/scanners", "error", f"Rejected {file.filename}: {e}")
        warn = " The scope could not be read from the file; pass a scope next time." \
            if not scope.strip() and r.scope == r.scanner else ""
        return session.redirect("/ui/scanners", "ok",
                                f"Scan {r.scan_id} ({r.scanner}, {r.scope}): {r.findings_seen} findings, "
                                f"{r.new} new, {r.fixed} fixed, {r.reopened} reopened, {len(r.skipped)} skipped. "
                                f"Run the pipeline to update tickets.{warn}")

    # -- 5. settings ------------------------------------------------------------------

    @app.get("/ui/settings", include_in_schema=False)
    def settings_view(request: Request):
        who = session.current(request)
        with svc.session() as s:
            data = pages.settings_page(s, settings, svc.policy, svc.ownership, request.app.state.tokens)
        return render(request, "settings.html", data, who)

    @app.post("/ui/settings/policy", include_in_schema=False)
    def settings_policy(request: Request, csrf: str = Form(""), confidence_limit: float = Form(...),
                        due_critical: int = Form(...), due_high: int = Form(...), due_medium: int = Form(...),
                        due_low: int = Form(...), dispatch_min_priority: str = Form(...),
                        dispatch_without_fix: str = Form(""), production_tag_keys: str = Form(""),
                        production_values: str = Form(""), scan_stale_hours: int = Form(...)):
        who = writer(request, csrf, ADMIN)
        split = lambda v: [x.strip() for x in v.split(",") if x.strip()]  # noqa: E731
        updates = {
            "confidence_limit": confidence_limit,
            "due_days": {"Critical": due_critical, "High": due_high, "Medium": due_medium, "Low": due_low},
            "dispatch_min_priority": dispatch_min_priority, "dispatch_without_fix": dispatch_without_fix == "on",
            "production_tag_keys": split(production_tag_keys), "production_values": split(production_values),
            "scan_stale_hours": scan_stale_hours,
        }
        if dispatch_min_priority not in ("Low", "Medium", "High", "Critical"):
            return session.redirect("/ui/settings", "error", "Unknown priority.")
        current = svc.policy.model_dump()
        changed = {k: v for k, v in updates.items() if current.get(k) != v}
        if not changed:
            return session.redirect("/ui/settings", "ok", "Nothing changed.")
        try:
            svc.set_policy(changed, f"ui:{who.name}")
        except ValueError as e:
            return session.redirect("/ui/settings", "error", f"Not saved: {e}")
        r = svc.rebuild()
        return session.redirect("/ui/settings", "ok", f"Saved {', '.join(sorted(changed))}. "
                                                      f"Rebuilt {r.work_items} work items.")

    @app.post("/ui/settings/policy/reset", include_in_schema=False)
    def settings_reset(request: Request, csrf: str = Form("")):
        who = writer(request, csrf, ADMIN)
        svc.reset_policy(f"ui:{who.name}")
        svc.rebuild()
        return session.redirect("/ui/settings", "ok", "Policy reset to policy.yaml and defaults.")

    # -- pipeline actions (from any page) ----------------------------------------

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
                                                          "dry": r.actions, "path": "/ui/vulnerabilities",
                                                          **data}, who)
            else:
                return session.redirect("/ui", "error", f"Unknown action {action}.")
        except TrackerError as e:
            return session.redirect(back(request, "/ui/workitems"), "error", f"Tracker error: {e}")
        return session.redirect(back(request, "/ui/workitems"), "ok", msg)
