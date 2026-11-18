"""REST API v1 (FR-IF-01). OpenAPI 3.1 at /openapi.json."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import select

from kavlotryx import __version__
from kavlotryx.adapters import AdapterError
from kavlotryx.api.auth import ADMIN, INGEST, READ, WRITE, Principal, parse_tokens, require
from kavlotryx.config import Settings
from kavlotryx.db import Finding, FindingSource, Scan, WorkItem, utcnow
from kavlotryx.ocsf.severity import SEVERITY_NAMES
from kavlotryx.service import Kavlotryx, NotFound


class TriageIn(BaseModel):
    kind: str  # risk_acceptance | false_positive
    finding_ids: list[int] = []
    work_item: str = ""  # or: every open finding of this work item
    reason: str
    controls: str = ""
    reference: str = ""
    expires_on: date | None = None


class DecideIn(BaseModel):
    note: str = ""


class NoteIn(BaseModel):
    body: str


class UserIn(BaseModel):
    role: str | None = None  # pins the role
    use_groups: bool = False  # take the role from groups again at the next sign-in
    active: bool | None = None


class OwnerOverrideIn(BaseModel):
    owner: str
    match: str = "asset"  # "asset" | "finding"
    reason: str = ""


def finding_out(f: Finding, sources: list[FindingSource] | None = None) -> dict[str, Any]:
    d = {
        "id": f.id, "fingerprint": f.fingerprint, "kind": f.kind, "status": f.status,
        "severity": SEVERITY_NAMES.get(f.severity_id, "Unknown"), "severity_id": f.severity_id,
        "title": f.title, "asset_key": f.asset_key, "asset_type": f.asset_type,
        "artifact": f.artifact, "vuln_id": f.vuln_id, "package": f.package,
        "installed_version": f.installed_version, "fixed_version": f.fixed_version,
        "rule_key": f.rule_key, "account_uid": f.account_uid, "region": f.region,
        "repo": f.repo, "path": f.path,
        "first_seen": f.first_seen, "last_seen": f.last_seen, "fixed_at": f.fixed_at,
        "owner": {"slug": f.owner_slug, "rule": f.owner_rule, "source": f.owner_source,
                  "confidence": f.owner_confidence, "needs_review": f.needs_review,
                  "evidence": f.owner_evidence},
        "work_item": f.work_item_key or None,
    }
    if sources is not None:
        d["tags"] = f.tags
        d["description"] = f.description
        d["remediation"] = f.remediation
        d["sources"] = [{"scanner": s.scanner, "scope": s.scope, "present": s.present,
                         "last_scan_id": s.last_scan_id} for s in sources]
    return d


def work_item_out(w: WorkItem, today: date) -> dict[str, Any]:
    return {
        "key": w.key, "owner": w.owner_slug, "kind": w.kind, "title": w.title,
        "priority": w.priority, "state": w.state, "dispatchable": w.dispatchable,
        "needs_review": w.needs_review, "due_date": w.due_date,
        "overdue": bool(w.due_date and w.due_date < today and w.state != "verified"),
        "ticket": {"key": w.ticket_key, "url": w.ticket_url} if w.ticket_key else None,
        "created_at": w.created_at, "verified_at": w.verified_at,
    }


def create_app(svc: Kavlotryx | None = None, insecure_no_auth: bool = False) -> FastAPI:
    settings = svc.settings if svc else Settings.from_env()
    svc = svc or Kavlotryx(settings)
    app = FastAPI(title="Kavlotryx", version=__version__,
                  description="Turn security scanner findings into owned, tracked, scan-verified work.")
    tokens = parse_tokens(settings.api_tokens)
    from kavlotryx.sso import configured as sso_configured
    from kavlotryx.sso import parse_role_map

    sso_on = sso_configured(settings)
    parse_role_map(settings.oidc_role_map)  # fail at start on a bad map, not at the first sign-in
    if not tokens and not sso_on and not insecure_no_auth:
        raise RuntimeError("no sign-in configured: set KAVLO_API_TOKENS or KAVLO_OIDC_*, "
                           "or pass --insecure-no-auth for local use")
    app.state.tokens = None if (insecure_no_auth and not tokens and not sso_on) else tokens
    app.state.svc = svc
    max_bytes = settings.max_upload_mb * 1024 * 1024

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> dict[str, str]:
        with svc.session() as s:
            s.execute(select(1))
        return {"status": "ready"}

    # -- scans ----------------------------------------------------------------

    @app.post("/api/v1/scans", status_code=201, tags=["scans"])
    async def post_scan(
        scanner: str = Form(...),
        file: UploadFile = File(...),
        scope: str | None = Form(None),
        who: Principal = Depends(require(INGEST)),
    ) -> dict[str, Any]:
        data = await file.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise HTTPException(413, f"upload exceeds {settings.max_upload_mb} MB")
        try:
            report = svc.ingest(scanner, data, scope=scope, actor=who.name)
        except (AdapterError, UnicodeDecodeError) as e:
            raise HTTPException(422, str(e)) from e
        return report.as_dict()

    @app.post("/api/v1/scans/defectdojo/pull", tags=["scans"])
    def pull_defectdojo(product: list[str] = Query([]), who: Principal = Depends(require(ADMIN))):  # noqa: B006
        """Read findings from KAVLO_DEFECTDOJO_URL (API v2) and ingest one scan per product (FR-IN-09)."""
        from kavlotryx.connectors.base import ConnectorError

        try:
            reports = svc.pull_defectdojo(product or None, actor=who.name)
        except (ConnectorError, AdapterError) as e:
            raise HTTPException(422, str(e)) from e
        return [r.as_dict() for r in reports]

    @app.get("/api/v1/scans", tags=["scans"])
    def list_scans(limit: int = Query(50, le=500), _: Principal = Depends(require(READ))):
        with svc.session() as s:
            rows = s.scalars(select(Scan).order_by(Scan.id.desc()).limit(limit)).all()
            return [{"id": r.id, "scanner": r.scanner, "scope": r.scope, "received_at": r.received_at,
                     "records": r.record_count, "new": r.new_count, "fixed": r.fixed_count,
                     "reopened": r.reopened_count, "skipped": r.skipped_count} for r in rows]

    # -- findings -------------------------------------------------------------

    @app.get("/api/v1/findings", tags=["findings"])
    def list_findings(
        owner: str | None = None, status: str | None = "open", kind: str | None = None,
        min_severity: int = Query(0, ge=0, le=6), needs_review: bool | None = None,
        limit: int = Query(100, le=1000), offset: int = 0,
        _: Principal = Depends(require(READ)),
    ):
        q = select(Finding)
        if owner:
            q = q.where(Finding.owner_slug == owner)
        if status:
            q = q.where(Finding.status == status)
        if kind:
            q = q.where(Finding.kind == kind)
        if min_severity:
            q = q.where(Finding.severity_id >= min_severity)
        if needs_review is not None:
            q = q.where(Finding.needs_review.is_(needs_review))
        q = q.order_by(Finding.severity_id.desc(), Finding.id).limit(limit).offset(offset)
        with svc.session() as s:
            return [finding_out(f) for f in s.scalars(q)]

    @app.get("/api/v1/findings/{finding_id}", tags=["findings"])
    def get_finding(finding_id: int, _: Principal = Depends(require(READ))):
        with svc.session() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            srcs = list(s.scalars(select(FindingSource).where(FindingSource.finding_id == f.id)))
            return finding_out(f, srcs)

    @app.get("/api/v1/findings/{finding_id}/owner/explain", tags=["ownership"])
    def explain(finding_id: int, _: Principal = Depends(require(READ))):
        try:
            return svc.explain(finding_id).as_dict()
        except NotFound as e:
            raise HTTPException(404, str(e)) from e

    @app.put("/api/v1/findings/{finding_id}/owner", tags=["ownership"])
    def set_owner(finding_id: int, body: OwnerOverrideIn, who: Principal = Depends(require(WRITE))):
        try:
            o = svc.set_owner(finding_id, body.owner, who.name, body.reason, body.match)
        except NotFound as e:
            raise HTTPException(404, str(e)) from e
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        return {"override": {"match": o.match_type, "value": o.match_value, "owner": o.owner_slug},
                "next": "POST /api/v1/workitems/rebuild applies it"}

    @app.get("/api/v1/owners", tags=["ownership"])
    def owners(_: Principal = Depends(require(READ))):
        return [o.model_dump() for o in svc.ownership.owners]

    # -- work items -----------------------------------------------------------

    @app.get("/api/v1/workitems", tags=["workitems"])
    def list_items(owner: str | None = None, state: str | None = None, overdue: bool = False,
                   limit: int = Query(200, le=1000), _: Principal = Depends(require(READ))):
        q = select(WorkItem)
        if owner:
            q = q.where(WorkItem.owner_slug == owner)
        if state:
            q = q.where(WorkItem.state == state)
        today = utcnow().date()
        with svc.session() as s:
            rows = [work_item_out(w, today) for w in s.scalars(q.order_by(WorkItem.key).limit(limit))]
        return [r for r in rows if r["overdue"]] if overdue else rows

    @app.post("/api/v1/workitems/rebuild", tags=["workitems"])
    def post_rebuild(_: Principal = Depends(require(WRITE))):
        return svc.rebuild().__dict__

    @app.post("/api/v1/dispatch", tags=["workitems"])
    def post_dispatch(dry_run: bool = False, who: Principal = Depends(require(WRITE))):
        r = svc.dispatch(dry_run=dry_run, actor=who.name)
        return {"dry_run": r.dry_run, "actions": [a.__dict__ for a in r.actions]}

    @app.post("/api/v1/verify", tags=["workitems"])
    def post_verify(dry_run: bool = False, who: Principal = Depends(require(WRITE))):
        r = svc.verify(dry_run=dry_run, actor=who.name)
        return {"dry_run": r.dry_run, "actions": [a.__dict__ for a in r.actions]}

    @app.post("/api/v1/run", tags=["workitems"])
    def post_run(dry_run: bool = False, who: Principal = Depends(require(WRITE))):
        return svc.run(dry_run=dry_run, actor=who.name)

    # -- reports --------------------------------------------------------------

    @app.get("/api/v1/reports/summary", tags=["reports"])
    def summary(_: Principal = Depends(require(READ))):
        return svc.summary()

    # -- triage (FR-IF-06..09) ------------------------------------------------------

    from kavlotryx.core import triage as tr

    def _triage_err(e: Exception) -> HTTPException:
        return HTTPException(404 if "not found" in str(e) else 422, str(e))

    @app.get("/api/v1/triage/decisions", tags=["triage"])
    def list_decisions(state: str | None = None, kind: str | None = None, _: Principal = Depends(require(READ))):
        from kavlotryx.db import TriageDecision

        q = select(TriageDecision).order_by(TriageDecision.id.desc())
        if state:
            q = q.where(TriageDecision.state == state)
        if kind:
            q = q.where(TriageDecision.kind == kind)
        with svc.session() as s:
            return [tr.decision_dict(s, d, with_findings=False) for d in s.scalars(q.limit(1000))]

    @app.get("/api/v1/triage/decisions/{decision_id}", tags=["triage"])
    def get_decision(decision_id: int, _: Principal = Depends(require(READ))):
        with svc.session() as s:
            try:
                d = tr.get(s, decision_id)
            except tr.TriageError as e:
                raise _triage_err(e) from e
            return {**tr.decision_dict(s, d), "notes": [
                {"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at}
                for n in tr.notes_for(s, "decision", str(d.id))]}

    @app.post("/api/v1/triage/decisions", status_code=201, tags=["triage"])
    def post_decision(body: TriageIn, who: Principal = Depends(require(WRITE))):
        kw = {"can_approve": who.role in ADMIN, "controls": body.controls, "reference": body.reference,
              "expires_on": body.expires_on}
        try:
            if body.work_item:
                return svc.triage_propose_work_item(body.work_item, body.kind, body.reason, who.name, **kw)
            return svc.triage_propose(body.kind, body.finding_ids, body.reason, who.name, **kw)
        except tr.TriageError as e:
            raise _triage_err(e) from e

    @app.post("/api/v1/triage/decisions/{decision_id}/{action}", tags=["triage"])
    def decide(decision_id: int, action: str, body: DecideIn, who: Principal = Depends(require(WRITE))):
        """approve and reject need the admin role; revoke needs analyst or admin."""
        if action in ("approve", "reject") and who.role not in ADMIN:
            raise HTTPException(403, f"role {who.role} may not {action}")
        try:
            return svc.triage_decide(decision_id, action, who.name, body.note)
        except tr.TriageError as e:
            raise _triage_err(e) from e

    @app.get("/api/v1/notes/{target_type}/{target_id}", tags=["triage"])
    def get_notes(target_type: str, target_id: str, _: Principal = Depends(require(READ))):
        with svc.session() as s:
            return [{"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at}
                    for n in tr.notes_for(s, target_type, target_id)]

    @app.post("/api/v1/notes/{target_type}/{target_id}", status_code=201, tags=["triage"])
    def post_note(target_type: str, target_id: str, body: NoteIn, who: Principal = Depends(require(WRITE))):
        try:
            return svc.add_note(target_type, target_id, who.name, body.body)
        except tr.TriageError as e:
            raise _triage_err(e) from e

    @app.get("/api/v1/reports/triage", tags=["reports"])
    def triage_report(start: date | None = Query(None, alias="from"), end: date | None = Query(None, alias="to"),
                      owner: str = "", who: Principal = Depends(require(READ))):
        """Audit-ready triage register for a period (default: the last 90 days), with a SHA-256 digest."""
        end = end or utcnow().date()
        start = start or end - timedelta(days=90)
        try:
            return svc.triage_report(start, end, who.name, owner)
        except tr.TriageError as e:
            raise _triage_err(e) from e

    # -- users (FR-IF-10) ---------------------------------------------------------------

    @app.get("/api/v1/users", tags=["admin"])
    def list_users(_: Principal = Depends(require(ADMIN))):
        from kavlotryx.core import users as us
        from kavlotryx.db import User

        with svc.session() as s:
            return [us.as_dict(u) for u in s.scalars(select(User).order_by(User.email))]

    @app.patch("/api/v1/users/{user_id}", tags=["admin"])
    def patch_user(user_id: int, body: UserIn, who: Principal = Depends(require(ADMIN))):
        from kavlotryx.core import users as us

        with svc.session() as s:
            try:
                u = us.get(s, user_id)
                if body.role is not None:
                    us.set_role(s, u, body.role, who.name, who.user_id)
                if body.use_groups:
                    us.use_groups(s, u, who.name, who.user_id)
                if body.active is not None:
                    us.set_active(s, u, body.active, who.name, who.user_id)
            except us.UserError as e:
                raise HTTPException(404 if "not found" in str(e) else 422, str(e)) from e
            return us.as_dict(u)

    @app.get("/api/v1/people", tags=["ownership"])
    def people_view(_: Principal = Depends(require(READ))):
        """Leaders and engineers from the Microsoft Graph cache, with their open findings (FR-OW-09)."""
        from kavlotryx.core import people

        with svc.session() as s:
            org = people.build(s, svc.ownership)
        return {"total_open": org.total_open, "named": org.named_total, "reached": org.reached_total,
                "reached_leader": org.led_total, "unreached": org.unreached,
                "people": [{**org.rows[pid].as_dict(), "depth": org.rows[pid].depth} for pid in org.order]}

    @app.get("/api/v1/connectors", tags=["connectors"])
    def connectors(_: Principal = Depends(require(READ))):
        from kavlotryx.connectors import CONNECTORS, connector_mode, last_runs

        with svc.session() as s:
            runs = last_runs(s)
        return [{"name": n, "mode": connector_mode(svc.settings, n),
                 "last_sync": runs[n].finished_at if runs[n] else None,
                 "status": runs[n].status if runs[n] else None,
                 "counts": runs[n].counts if runs[n] else {}} for n in CONNECTORS]

    @app.post("/api/v1/connectors/{name}/sync", tags=["connectors"])
    def connector_sync(name: str, who: Principal = Depends(require(ADMIN))):
        from kavlotryx.connectors import ConnectorError

        try:
            run = svc.sync_connector(name, actor=who.name)
        except ConnectorError as e:
            raise HTTPException(422, str(e)) from e
        return {"name": name, "mode": run.mode, "status": run.status, "counts": run.counts}

    from kavlotryx.web import mount_console

    mount_console(app, svc)

    @app.get("/api/v1/admin/whoami", tags=["admin"])
    def whoami(who: Principal = Depends(require(ADMIN | READ | INGEST))):
        return {"name": who.name, "role": who.role, "time": datetime.now().isoformat()}

    return app
