"""Read models for the console pages. Every number shown comes from the database."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from kavlotryx.db import AuditEvent, Finding, FindingSource, Observation, Scan, WorkItem, utcnow
from kavlotryx.dispatch.dispatcher import describe, ticket_label
from kavlotryx.ocsf.severity import SEVERITY_NAMES

PAGE_SIZE = 25

# The ownership ladder in rule order. Default and fallback share the last card.
RULE_LADDER = [
    {"key": "override", "n": 1, "tier": "Absolute", "name": "Manual override", "conf": "1.0",
     "desc": "Pinned by a person through the console, CLI or API.", "tone": "violet"},
    {"key": "tag", "n": 2, "tier": "Infra", "name": "Cloud ownership tag", "conf": "0.90",
     "desc": "Resource tag such as team or owner.", "tone": "amber"},
    {"key": "codeowners", "n": 3, "tier": "Source", "name": "Git CODEOWNERS", "conf": "0.85",
     "desc": "Last matching CODEOWNERS line for the file or Dockerfile.", "tone": "ok"},
    {"key": "pattern", "n": 4, "tier": "Glob", "name": "ownership.yaml pattern", "conf": "0.75",
     "desc": "Name, asset or rule glob from the config file.", "tone": "orange"},
    {"key": "default", "n": 5, "tier": "Fallback", "name": "Account or registry default", "conf": "0.50",
     "desc": "No stronger evidence. Below the limit: needs review.", "tone": "warn"},
]

STATES = [
    ("open", "Open", "groups not yet filed"),
    ("dispatched", "Dispatched", "tickets active"),
    ("pending_verification", "Pending verify", "ticket done, scan not clean"),
    ("verified", "Verified", "closed by a clean scan"),
    ("reopened", "Reopened", "finding came back"),
]


def sev_name(sid: int) -> str:
    return SEVERITY_NAMES.get(sid, "Unknown")


def rule_family(rule: str) -> str:
    if not rule:
        return ""
    head = rule.split(":", 1)[0]
    return "default" if head in ("default", "fallback") else head


def pct(a: int, b: int) -> float:
    return round(100.0 * a / b, 1) if b else 0.0


# -- shared -------------------------------------------------------------------


def rule_ladder(s: Session) -> tuple[list[dict[str, Any]], int, int]:
    rows = s.execute(
        select(Finding.owner_rule, Finding.needs_review, func.count())
        .where(Finding.status == "open").group_by(Finding.owner_rule, Finding.needs_review)
    ).all()
    counts: Counter[str] = Counter()
    review = total = 0
    for rule, needs_review, n in rows:
        counts[rule_family(rule)] += n
        total += n
        review += n if needs_review else 0
    ladder = []
    for r in RULE_LADDER:
        n = counts.get(r["key"], 0)
        ladder.append({**r, "count": n, "pct": pct(n, total)})
    return ladder, total, review


# -- overview -----------------------------------------------------------------


def overview(s: Session, summary: dict[str, Any]) -> dict[str, Any]:
    today = utcnow().date()
    items = s.scalars(select(WorkItem)).all()
    observations = s.scalar(select(func.count(Observation.id))) or 0
    findings_total = s.scalar(select(func.count(Finding.id))) or 0
    attention = []
    for w in items:
        reason = ""
        if w.state == "pending_verification":
            reason = "Ticket is Done but scans still report findings"
        elif w.state == "reopened":
            reason = "A fixed finding came back"
        elif w.due_date and w.due_date < today and w.state != "verified":
            reason = f"Overdue since {w.due_date.isoformat()}"
        elif w.needs_review and w.state not in ("verified", "superseded"):
            reason = "Owner below the confidence limit"
        if reason:
            attention.append({"w": w, "reason": reason})
    scans = s.scalars(select(Scan).order_by(Scan.id.desc()).limit(6)).all()
    ticketed = sum(1 for w in items if w.ticket_key)
    stages = [
        ("Observations", observations, "raw rows from scanners"),
        ("Findings", findings_total, "after fingerprint dedupe"),
        ("Work items", len(items), "root cause + owner"),
        ("Tickets", ticketed, "one per work item"),
        ("Verified", sum(1 for w in items if w.state == "verified"), "closed by a clean scan"),
    ]
    return {"attention": attention[:12], "scans": scans, "stages": stages,
            "items_active": sum(1 for w in items if w.state not in ("verified", "superseded")),
            "ticketed": ticketed}


# -- findings -----------------------------------------------------------------


@dataclass
class FindingFilter:
    q: str = ""
    kind: str = ""
    sev: int = 0
    status: str = "open"
    owner: str = ""
    conf: str = ""  # "" | "ok" | "review"
    page: int = 1

    def query_string(self, **override: Any) -> str:
        from urllib.parse import urlencode

        d = {"q": self.q, "kind": self.kind, "sev": self.sev or "", "status": self.status,
             "owner": self.owner, "conf": self.conf, "page": self.page}
        d.update(override)
        return urlencode({k: v for k, v in d.items() if v not in ("", None, 0)})

    def chips(self) -> list[tuple[str, str]]:
        out = []
        if self.q:
            out.append((f"search: {self.q}", self.query_string(q="", page=1)))
        if self.kind:
            out.append((f"kind: {self.kind}", self.query_string(kind="", page=1)))
        if self.sev:
            out.append((f"severity ≥ {sev_name(self.sev)}", self.query_string(sev="", page=1)))
        if self.owner:
            out.append((f"owner: {self.owner}", self.query_string(owner="", page=1)))
        if self.conf:
            out.append((f"confidence: {'needs review' if self.conf == 'review' else '≥ limit'}",
                        self.query_string(conf="", page=1)))
        if self.status != "open":
            out.append((f"status: {self.status or 'any'}", self.query_string(status="open", page=1)))
        return out


def findings_page(s: Session, f: FindingFilter) -> dict[str, Any]:
    q = select(Finding)
    if f.status:
        q = q.where(Finding.status == f.status)
    if f.kind:
        q = q.where(Finding.kind == f.kind)
    if f.sev:
        q = q.where(Finding.severity_id >= f.sev)
    if f.owner:
        q = q.where(Finding.owner_slug == f.owner)
    if f.conf == "review":
        q = q.where(Finding.needs_review.is_(True))
    elif f.conf == "ok":
        q = q.where(Finding.needs_review.is_(False))
    if f.q:
        like = f"%{f.q.strip()}%"
        q = q.where(or_(Finding.vuln_id.ilike(like), Finding.package.ilike(like),
                        Finding.asset_key.ilike(like), Finding.rule_key.ilike(like),
                        Finding.fingerprint.ilike(like), Finding.title.ilike(like),
                        Finding.owner_slug.ilike(like), Finding.artifact.ilike(like)))
    total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(1, f.page), pages)
    rows = s.scalars(q.order_by(Finding.severity_id.desc(), Finding.id)
                     .limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)).all()
    ids = [r.id for r in rows]
    src: dict[int, list[str]] = {}
    if ids:
        for fid, scanner in s.execute(select(FindingSource.finding_id, FindingSource.scanner)
                                      .where(FindingSource.finding_id.in_(ids))):
            src.setdefault(fid, []).append(scanner)
    items = {w.key: w for w in s.scalars(select(WorkItem).where(
        WorkItem.key.in_({r.work_item_key for r in rows if r.work_item_key})))} if rows else {}
    owners = [o for (o,) in s.execute(select(Finding.owner_slug).distinct()) if o]
    return {"rows": rows, "sources": src, "items": items, "total": total, "page": page,
            "pages": pages, "owners": sorted(owners)}


def finding_detail(s: Session, fid: int) -> dict[str, Any] | None:
    f = s.get(Finding, fid)
    if f is None:
        return None
    sources = []
    for src in s.scalars(select(FindingSource).where(FindingSource.finding_id == fid)):
        scan = s.get(Scan, src.last_scan_id)
        sources.append({"s": src, "scan": scan})
    obs = s.scalars(select(Observation).where(Observation.fingerprint == f.fingerprint)
                    .order_by(Observation.id.desc()).limit(1)).first()
    raw = json.dumps(obs.raw, indent=2, default=str) if obs else ""
    if len(raw) > 20000:
        raw = raw[:20000] + "\n… (truncated)"
    obs_count = s.scalar(select(func.count(Observation.id))
                         .where(Observation.fingerprint == f.fingerprint)) or 0
    wi = s.get(WorkItem, f.work_item_key) if f.work_item_key else None
    return {"f": f, "sources": sources, "raw": raw, "obs_count": obs_count, "wi": wi}


# -- work items ---------------------------------------------------------------


def workitems_page(s: Session, owner: str, state: str) -> dict[str, Any]:
    today = utcnow().date()
    all_items = s.scalars(select(WorkItem).order_by(WorkItem.key)).all()
    open_counts: Counter[str] = Counter()
    total_counts: Counter[str] = Counter()
    for key, status in s.execute(select(Finding.work_item_key, Finding.status).where(Finding.work_item_key != "")):
        total_counts[key] += 1
        if status == "open":
            open_counts[key] += 1
    state_counts = Counter(w.state for w in all_items)
    owner_counts = Counter(w.owner_slug for w in all_items if w.state not in ("verified", "superseded"))
    rows = [w for w in all_items if (not owner or w.owner_slug == owner) and (not state or w.state == state)]
    prio_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    state_rank = {"reopened": 0, "pending_verification": 1, "dispatched": 2, "open": 3, "verified": 4,
                  "superseded": 5}
    rows.sort(key=lambda w: (state_rank.get(w.state, 9), prio_rank.get(w.priority, 9), w.key))
    observations = s.scalar(select(func.count(Observation.id))) or 0
    ticketed = sum(1 for w in all_items if w.ticket_key)
    return {
        "rows": rows, "open_counts": open_counts, "total_counts": total_counts,
        "state_counts": state_counts, "owner_counts": owner_counts, "today": today,
        "observations": observations, "ticketed": ticketed,
        "reduction": round(100 - 100.0 * ticketed / observations, 1) if observations and ticketed else None,
        "ratio": round(observations / ticketed, 1) if ticketed else None,
    }


def days_left(due: date | None, today: date) -> int | None:
    return (due - today).days if due else None


def workitem_detail(s: Session, key: str) -> dict[str, Any] | None:
    w = s.get(WorkItem, key)
    if w is None:
        return None
    members = s.scalars(select(Finding).where(Finding.work_item_key == key)
                        .order_by(Finding.status, Finding.severity_id.desc())).all()
    fps = [m.fingerprint for m in members]
    observations = 0
    if fps:
        observations = s.scalar(select(func.count(Observation.id)).where(Observation.fingerprint.in_(fps))) or 0
    lead = next((m for m in members if m.status == "open"), members[0] if members else None)
    events = s.scalars(select(AuditEvent).where(AuditEvent.target == key).order_by(AuditEvent.at)).all()
    fixed_scans = sorted({m.fixed_by_scan_id for m in members if m.fixed_by_scan_id})
    scans = {sc.id: sc for sc in s.scalars(select(Scan).where(Scan.id.in_(fixed_scans)))} if fixed_scans else {}
    timeline = [{"at": w.created_at, "title": "Work item formed",
                 "text": f"{len(members)} findings grouped by root cause and owner.", "tone": "ok"}]
    for e in events:
        detail = e.detail or {}
        title = {"dispatch.create": "Ticket created", "dispatch.adopt": "Existing ticket adopted",
                 "dispatch.update": "Ticket updated", "verify.verified": "Fix verified by scan",
                 "verify.pending": "Held: ticket Done, scan not clean",
                 "verify.reopened": "Reopened: finding returned", "verify.resumed": "Ticket reopened in tracker",
                 "verify.superseded": "Superseded"}.get(e.action, e.action)
        tone = ("ok" if e.action in ("verify.verified", "dispatch.create", "dispatch.adopt")
                else "crit" if e.action == "verify.reopened" else "warn" if e.action == "verify.pending" else "")
        ticket = f" · ticket {detail.get('ticket')}" if detail.get("ticket") else ""
        timeline.append({"at": e.at, "title": title, "tone": tone, "text": f"by {e.actor}{ticket}"})
    assets: dict[str, dict[str, Any]] = {}
    for m in members:
        a = assets.setdefault(m.asset_key, {"key": m.asset_key, "name": m.asset_name, "type": m.asset_type,
                                            "open": 0, "fixed": 0})
        a["open" if m.status == "open" else "fixed"] += 1
    return {
        "w": w, "members": members, "lead": lead, "observations": observations,
        "open": sum(1 for m in members if m.status == "open"),
        "fixed": sum(1 for m in members if m.status == "fixed"),
        "timeline": timeline, "assets": list(assets.values()), "scans": scans,
        "label": ticket_label(w.key), "body": describe(w, list(members)),
        "vulns": len({m.vuln_id for m in members if m.vuln_id}),
        "today": utcnow().date(),
    }


# -- verification & ingest ----------------------------------------------------


def verify_page(s: Session) -> dict[str, Any]:
    scans = s.scalars(select(Scan).order_by(Scan.id.desc()).limit(50)).all()
    events = s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(40)).all()
    proofs = s.scalars(select(AuditEvent).where(AuditEvent.action.in_(
        ["verify.verified", "verify.pending", "verify.reopened", "verify.superseded"]))
        .order_by(AuditEvent.id.desc()).limit(12)).all()
    items = {w.key: w for w in s.scalars(select(WorkItem).where(
        WorkItem.key.in_({e.target for e in proofs})))} if proofs else {}
    state = Counter(w.state for w in s.scalars(select(WorkItem)))
    obs_total = s.scalar(select(func.count(Observation.id))) or 0
    fixed = s.scalar(select(func.count(Finding.id)).where(Finding.status == "fixed")) or 0
    reopened = s.scalar(select(func.count(Finding.id)).where(Finding.reopen_count > 0)) or 0
    return {"scans": scans, "events": events, "proofs": proofs, "items": items, "state": state,
            "obs_total": obs_total, "fixed": fixed, "reopened": reopened,
            "scan_total": s.scalar(select(func.count(Scan.id))) or 0}
