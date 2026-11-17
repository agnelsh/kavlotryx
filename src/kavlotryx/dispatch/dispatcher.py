"""Create and update one ticket per work item, idempotently (FR-DS-01..05).

Idempotency: each work item has a stable key. The ticket carries the label
``kavlo-<key hash>``. Before a create, the dispatcher searches for that label
and adopts an existing ticket. A repeat run, a crash between create and
commit, or a fresh database never makes a second ticket.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, PolicyConfig
from kavlotryx.db import Finding, WorkItem, audit, utcnow
from kavlotryx.dispatch.base import TicketTracker, TrackerError
from kavlotryx.ocsf.severity import SEVERITY_NAMES

ACTIVE_STATES = ("open", "dispatched", "reopened", "pending_verification")
MAX_LISTED = 50


def ticket_label(wi_key: str) -> str:
    return "kavlo-" + wi_key.removeprefix("wi_")


@dataclass
class DispatchAction:
    work_item: str
    action: str  # create | adopt | update | skip | error
    ticket: str = ""
    detail: str = ""


@dataclass
class DispatchReport:
    dry_run: bool
    actions: list[DispatchAction] = field(default_factory=list)

    def count(self, action: str) -> int:
        return sum(1 for a in self.actions if a.action == action)


def describe(wi: WorkItem, members: list[Finding]) -> str:
    open_m = [m for m in members if m.status == "open"]
    first = open_m[0] if open_m else (members[0] if members else None)
    lines = [
        f"Kavlotryx work item {wi.key}",
        f"Owner: {wi.owner_slug}",
    ]
    if first is not None:
        ev = ", ".join(f"{k}={v}" for k, v in sorted((first.owner_evidence or {}).items()))
        lines.append(f"Why this owner: rule {first.owner_rule} (source {first.owner_source}, "
                     f"confidence {first.owner_confidence:.2f})" + (f"; evidence: {ev}" if ev else ""))
        if wi.needs_review:
            lines.append("Owner confidence is below the limit: please confirm or reassign in Kavlotryx.")
    lines.append(f"Priority: {wi.priority}" + (f"; due {wi.due_date.isoformat()}" if wi.due_date else ""))
    if wi.kind == "vuln-fix":
        lines.append(f"Fix: upgrade {wi.package} to {wi.fixed_version} or later in {wi.artifact}.")
    elif first is not None and first.remediation:
        lines.append(f"Fix: {first.remediation}")
    lines += ["", f"Open findings ({len(open_m)}):"]
    for m in sorted(open_m, key=lambda m: (-m.severity_id, m.vuln_id or m.rule_key, m.asset_key))[:MAX_LISTED]:
        sev = SEVERITY_NAMES.get(m.severity_id, "Unknown")
        if m.kind == "vuln":
            lines.append(f"- {m.vuln_id} ({sev}) {m.package} {m.installed_version}"
                         f" -> {m.fixed_version or 'no fix'} on {m.asset_key}")
        else:
            lines.append(f"- {m.rule_key} ({sev}) on {m.asset_key}" + (f" {m.path}" if m.path else ""))
    if len(open_m) > MAX_LISTED:
        lines.append(f"- ... and {len(open_m) - MAX_LISTED} more")
    lines += ["", "Kavlotryx closes this issue only when a new scan no longer reports these findings."]
    return "\n".join(lines)


def dispatch(
    session: Session,
    tracker: TicketTracker,
    cfg: OwnershipConfig,
    policy: PolicyConfig,
    dry_run: bool = False,
    actor: str = "system",
) -> DispatchReport:
    projects = {o.slug: o.jira_project for o in cfg.owners}
    report = DispatchReport(dry_run=dry_run)
    items = session.scalars(
        select(WorkItem).where(WorkItem.state.in_(ACTIVE_STATES), WorkItem.dispatchable.is_(True))
        .order_by(WorkItem.key)
    ).all()
    today = utcnow().date()

    for wi in items:
        members = list(session.scalars(select(Finding).where(Finding.work_item_key == wi.key)))
        if not any(m.status == "open" for m in members):
            continue  # the verifier handles items with nothing open
        project = projects.get(wi.owner_slug, "")
        if not project:
            report.actions.append(DispatchAction(wi.key, "skip", detail=f"owner {wi.owner_slug} has no jira_project"))
            continue
        try:
            if not wi.ticket_key:
                label = ticket_label(wi.key)
                if dry_run:
                    report.actions.append(DispatchAction(wi.key, "create", detail=f"{project}: {wi.title}"))
                    continue
                existing = tracker.find_by_label(label)
                if existing is not None:
                    wi.ticket_key, wi.ticket_url = existing.key, existing.url
                    action = "adopt"
                else:
                    wi.due_date = today + timedelta(days=policy.due_days.get(wi.priority, 180))
                    t = tracker.create(project, wi.title, describe(wi, members),
                                       policy.jira_priority.get(wi.priority, ""),
                                       ["kavlotryx", label], wi.due_date)
                    wi.ticket_key, wi.ticket_url = t.key, t.url
                    action = "create"
                wi.state = "dispatched" if wi.state in ("open", "reopened") else wi.state
                wi.dispatched_at = utcnow()
                wi.dispatched_hash = wi.content_hash
                audit(session, actor, f"dispatch.{action}", wi.key, ticket=wi.ticket_key)
                session.commit()  # commit per item: a crash loses at most one, and adopt recovers it
                report.actions.append(DispatchAction(wi.key, action, wi.ticket_key, wi.title))
            elif wi.dispatched_hash != wi.content_hash:
                if dry_run:
                    report.actions.append(DispatchAction(wi.key, "update", wi.ticket_key, "content changed"))
                    continue
                tracker.update(wi.ticket_key, wi.title, describe(wi, members),
                               policy.jira_priority.get(wi.priority, ""))
                wi.dispatched_hash = wi.content_hash
                audit(session, actor, "dispatch.update", wi.key, ticket=wi.ticket_key)
                session.commit()
                report.actions.append(DispatchAction(wi.key, "update", wi.ticket_key, wi.title))
        except TrackerError as e:
            session.rollback()
            report.actions.append(DispatchAction(wi.key, "error", wi.ticket_key, str(e)))
    return report
