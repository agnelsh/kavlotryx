"""Read models for the Triage pages (FR-IF-06..09). Nothing here writes."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import PolicyConfig
from kavlotryx.core import triage
from kavlotryx.db import AuditEvent, Finding, TriageDecision, WorkItem, utcnow

DECISION_STATES = [("proposed", "Waiting for Approval"), ("active", "Active"), ("expired", "Expired"),
                   ("revoked", "Revoked"), ("rejected", "Rejected")]


def triage_page(s: Session, state: str, kind: str) -> dict[str, Any]:
    q = triage.queue(s)
    rows = [d for d in q["decisions"] if (not state or d.state == state) and (not kind or d.kind == kind)]
    counts = {d.id: n for d, n in ((d, len(triage._items(s, d))) for d in rows[:300])}
    return {**q, "rows": rows[:300], "counts": counts, "suggestions": triage.suggestions(s),
            "state": state, "kind": kind, "decision_states": DECISION_STATES}


def decision_page(s: Session, did: int, policy: PolicyConfig) -> dict[str, Any] | None:
    d = s.get(TriageDecision, did)
    if d is None:
        return None
    findings = triage.decision_findings(s, d)
    events = s.scalars(select(AuditEvent).where(AuditEvent.target == f"decision:{d.id}")
                       .order_by(AuditEvent.at, AuditEvent.id)).all()
    today = utcnow().date()
    return {"d": d, "findings": findings, "events": events, "notes": triage.notes_for(s, "decision", str(d.id)),
            "today": today, "days_left": (d.expires_on - today).days if d.expires_on else None,
            "four_eyes": policy.triage_four_eyes,
            "work_items": sorted({f.work_item_key for f in findings if f.work_item_key})}


def triage_box(s: Session, f: Finding, policy: PolicyConfig) -> dict[str, Any]:
    """What the finding page needs: decisions on this finding, notes, and the form limits."""
    today = utcnow().date()
    limit = triage.max_days(policy, f.severity_id)
    ds = triage.decisions_for_finding(s, f)
    return {"decisions": ds, "live": next((d for d in ds if d.state in triage.LIVE), None),
            "notes": triage.notes_for(s, "finding", str(f.id)), "max_days": limit,
            "max_date": (today + timedelta(days=limit)).isoformat(),
            "default_date": (today + timedelta(days=min(30, limit))).isoformat(),
            "min_date": (today + timedelta(days=1)).isoformat()}


def work_item_box(s: Session, w: WorkItem, members: list[Finding], policy: PolicyConfig) -> dict[str, Any]:
    today = utcnow().date()
    open_m = [m for m in members if m.status == "open"]
    top = max((m.severity_id for m in open_m), default=0)
    limit = triage.max_days(policy, top)
    live = triage.covering(s, [m.fingerprint for m in members])
    return {"notes": triage.notes_for(s, "work_item", w.key), "open_ids": [m.id for m in open_m],
            "live": sorted({d.id: d for d in live.values()}.values(), key=lambda d: d.id),
            "max_days": limit, "max_date": (today + timedelta(days=limit)).isoformat(),
            "default_date": (today + timedelta(days=min(30, limit))).isoformat(),
            "min_date": (today + timedelta(days=1)).isoformat(),
            "triaged": sum(1 for m in members if m.status in triage.TRIAGED)}


def report_period(start: str, end: str) -> tuple[date, date]:
    today = utcnow().date()
    try:
        e = date.fromisoformat(end) if end else today
    except ValueError:
        e = today
    try:
        st = date.fromisoformat(start) if start else e - timedelta(days=90)
    except ValueError:
        st = e - timedelta(days=90)
    return st, e
