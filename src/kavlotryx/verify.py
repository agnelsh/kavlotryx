"""Scan-verified closure (FR-VF-01..05).

A ticket status alone never closes a work item. The verifier reads each
ticket's status and compares it with the findings that scans still report:

* all findings fixed by a scan  -> close the ticket, state ``verified``
* ticket Done, findings remain  -> comment, state ``pending_verification``
* verified item, finding back   -> reopen the ticket, state ``dispatched``
* every finding moved to another owner -> close as ``superseded``
* nothing open, the rest risk accepted or false positive -> close as ``triaged``
  (not ``verified``: no scan proved a fix). It reopens when the decision ends.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.core.triage import TRIAGED
from kavlotryx.db import Finding, WorkItem, audit, utcnow
from kavlotryx.dispatch.base import TicketTracker, TrackerError


@dataclass
class VerifyAction:
    work_item: str
    action: str  # verified | triaged | pending | reopened | resumed | superseded | missing | error
    ticket: str = ""
    detail: str = ""


@dataclass
class VerifyReport:
    dry_run: bool
    actions: list[VerifyAction] = field(default_factory=list)

    def count(self, action: str) -> int:
        return sum(1 for a in self.actions if a.action == action)


def _verify_one(wi: WorkItem, members: list[Finding], tracker: TicketTracker, dry_run: bool,
                act: Callable[[str, str], None]) -> None:
    open_m = [m for m in members if m.status == "open"]
    fixed_m = [m for m in members if m.status == "fixed"]
    triaged_m = [m for m in members if m.status in TRIAGED]

    if not open_m and triaged_m:
        if wi.state == "triaged":
            return
        acc = sum(1 for m in triaged_m if m.status == "accepted")
        fp = len(triaged_m) - acc
        what = ", ".join(x for x in (f"{acc} risk accepted" if acc else "", f"{fp} false positive" if fp else "") if x)
        act("triaged", what + (f", {len(fixed_m)} fixed" if fixed_m else ""))
        if dry_run:
            return
        if wi.ticket_key:
            status = tracker.status(wi.ticket_key)
            if status == "missing":
                return
            tracker.comment(wi.ticket_key, f"Kavlotryx: no finding in this issue is open. Triage decisions "
                            f"cover the rest ({what}). Closing as triaged, not as fixed. The issue reopens "
                            f"when a decision expires or is revoked.")
            if status != "done":
                tracker.transition(wi.ticket_key, "done")
        wi.state = "triaged"
        return

    if not wi.ticket_key:
        if not open_m and fixed_m and wi.state != "verified":
            act("verified", "fixed before dispatch")
            if not dry_run:
                wi.state, wi.verified_at = "verified", utcnow()
        return

    status = tracker.status(wi.ticket_key)
    if status == "missing":
        act("missing", "ticket no longer exists")
        return

    if not members:
        act("superseded", "all findings moved to another work item")
        if not dry_run:
            tracker.comment(wi.ticket_key, "Kavlotryx: every finding in this issue now belongs "
                            "to another owner. Closing as superseded.")
            if status != "done":
                tracker.transition(wi.ticket_key, "done")
            wi.state = "superseded"
        return

    if not open_m:
        if wi.state != "verified":
            scan_id = max((m.fixed_by_scan_id or 0) for m in fixed_m)
            act("verified", f"scan {scan_id} no longer reports {len(fixed_m)} findings")
            if not dry_run:
                tracker.comment(wi.ticket_key, f"Kavlotryx verified the fix: scan {scan_id} no "
                                f"longer reports the {len(fixed_m)} findings in this issue.")
                if status != "done":
                    tracker.transition(wi.ticket_key, "done")
                wi.state, wi.verified_at, wi.verified_by_scan_id = "verified", utcnow(), scan_id
        return

    # Some findings are still open.
    if wi.state in ("verified", "reopened", "triaged"):
        act("reopened", f"{len(open_m)} findings are open again")
        if not dry_run:
            if status == "done":
                tracker.transition(wi.ticket_key, "new")
            tracker.comment(wi.ticket_key, f"Kavlotryx reopened this issue: {len(open_m)} of its findings "
                            f"are open again (a new scan reports them, or a triage decision ended).")
            wi.state = "dispatched"
    elif status == "done" and wi.state == "dispatched":
        act("pending", f"ticket is Done but {len(open_m)} findings are still open")
        if not dry_run:
            tracker.comment(wi.ticket_key, f"Kavlotryx: this issue is marked Done, but the latest "
                            f"scans still report {len(open_m)} findings. It stays open in "
                            f"Kavlotryx until a scan confirms the fix.")
            wi.state = "pending_verification"
    elif status != "done" and wi.state == "pending_verification":
        act("resumed", "ticket was reopened in the tracker")
        if not dry_run:
            wi.state = "dispatched"


def verify(session: Session, tracker: TicketTracker, dry_run: bool = False,
           actor: str = "system") -> VerifyReport:
    report = VerifyReport(dry_run=dry_run)
    items = session.scalars(
        select(WorkItem).where(WorkItem.state != "superseded").order_by(WorkItem.key)
    ).all()

    for wi in items:
        members = list(session.scalars(select(Finding).where(Finding.work_item_key == wi.key)))
        before = len(report.actions)

        def act(action: str, detail: str = "", _wi: WorkItem = wi) -> None:
            report.actions.append(VerifyAction(_wi.key, action, _wi.ticket_key, detail))

        try:
            _verify_one(wi, members, tracker, dry_run, act)
        except TrackerError as e:
            session.rollback()
            act("error", str(e))
            continue
        if not dry_run and len(report.actions) > before:
            audit(session, actor, f"verify.{report.actions[-1].action}", wi.key,
                  state=wi.state, ticket=wi.ticket_key)
            session.commit()
    return report
