"""Triage: risk acceptance (FR-IF-06), false positives (FR-IF-07) and notes (FR-IF-08).

A decision names findings by fingerprint and goes through four states::

    proposed --approve--> active --expire / revoke--> expired | revoked
        \\--reject--> rejected      (a proposal can also be withdrawn: revoked)

Only an ``active`` decision changes findings. Its open findings get the status
``accepted`` (risk acceptance) or ``false_positive`` and leave every open
queue, work item and ticket. Rules that keep this auditable:

* every decision has a written reason; a risk acceptance also has an expiry date
  no later than ``policy.acceptance_max_days`` for its highest severity;
* approval needs the admin role, and with ``policy.triage_four_eyes`` (the
  default) the approver must be a different person from the requester;
* a decision never deletes or edits a finding: when it ends, its findings are
  open again, and a scan that no longer reports a finding still fixes it;
* a scanner or DefectDojo flag never triages a finding by itself: it can only
  be shown as a suggestion that a person proposes;
* every step writes an audit event, and notes are append-only.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kavlotryx import __version__
from kavlotryx.config import PolicyConfig
from kavlotryx.db import AuditEvent, Finding, Note, TriageDecision, TriageItem, WorkItem, audit, utcnow
from kavlotryx.ocsf.severity import SEVERITY_NAMES

KINDS = {"risk_acceptance": "accepted", "false_positive": "false_positive"}  # kind -> finding status
KIND_LABEL = {"risk_acceptance": "Risk acceptance", "false_positive": "False positive"}
TRIAGED = tuple(KINDS.values())
LIVE = ("proposed", "active")
NOTE_TARGETS = ("finding", "work_item", "decision")
MIN_REASON = 10
MAX_TEXT = 4000


class TriageError(ValueError):
    pass


def _today() -> date:
    return utcnow().date()


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def max_days(policy: PolicyConfig, severity_id: int) -> int:
    name = SEVERITY_NAMES.get(severity_id, "Low")
    name = {"Fatal": "Critical", "Informational": "Low", "Unknown": "Low"}.get(name, name)
    return int(policy.acceptance_max_days.get(name, policy.acceptance_max_days.get("Low", 365)))


def _text(value: str, what: str, minimum: int = 1) -> str:
    v = (value or "").strip()
    if len(v) < minimum:
        raise TriageError(f"{what} must be at least {minimum} characters")
    if len(v) > MAX_TEXT:
        raise TriageError(f"{what} must be at most {MAX_TEXT} characters")
    return v


# -- lifecycle ----------------------------------------------------------------


def covering(s: Session, fingerprints: list[str], states: tuple[str, ...] = LIVE) -> dict[str, TriageDecision]:
    """Live decisions by fingerprint (one per fingerprint: a finding has at most one live decision)."""
    out: dict[str, TriageDecision] = {}
    for i in range(0, len(fingerprints), 500):
        rows = s.execute(select(TriageItem.fingerprint, TriageDecision)
                         .join(TriageDecision, TriageDecision.id == TriageItem.decision_id)
                         .where(TriageItem.fingerprint.in_(fingerprints[i:i + 500]),
                                TriageDecision.state.in_(states))).all()
        for fp, d in rows:
            out.setdefault(fp, d)
    return out


def active_status(s: Session, fingerprints: list[str]) -> dict[str, str]:
    """Finding status that an active decision imposes, by fingerprint (used by ingest)."""
    return {fp: KINDS[d.kind] for fp, d in covering(s, fingerprints, ("active",)).items()}


def propose(s: Session, policy: PolicyConfig, kind: str, finding_ids: list[int], reason: str, actor: str,
            *, can_approve: bool = False, controls: str = "", reference: str = "",
            expires_on: date | None = None, source: str = "kavlotryx", today: date | None = None) -> TriageDecision:
    """Record a proposal. An admin's proposal activates at once only when four eyes is off."""
    today = today or _today()
    if kind not in KINDS:
        raise TriageError(f"kind must be one of {', '.join(KINDS)}")
    reason = _text(reason, "reason", MIN_REASON)
    controls = (controls or "").strip()[:MAX_TEXT]
    reference = (reference or "").strip()[:128]
    ids = sorted(set(finding_ids))
    if not ids:
        raise TriageError("pick at least one finding")
    if len(ids) > 2000:
        raise TriageError("one decision covers at most 2000 findings")
    found = list(s.scalars(select(Finding).where(Finding.id.in_(ids))))
    if len(found) != len(ids):
        missing = sorted(set(ids) - {f.id for f in found})
        raise TriageError(f"unknown findings: {', '.join(map(str, missing[:10]))}")
    not_open = [f.id for f in found if f.status != "open"]
    if not_open:
        raise TriageError(f"only open findings can be triaged; not open: {', '.join(map(str, not_open[:10]))}")
    taken = covering(s, [f.fingerprint for f in found])
    if taken:
        ds = sorted({d.id for d in taken.values()})
        raise TriageError(f"{len(taken)} findings already have a live decision: #{', #'.join(map(str, ds))}")

    top = max(f.severity_id for f in found)
    if kind == "risk_acceptance":
        limit = max_days(policy, top)
        if expires_on is None:
            raise TriageError("a risk acceptance needs an expiry date")
        if expires_on <= today:
            raise TriageError("the expiry date must be in the future")
        if expires_on > today + timedelta(days=limit):
            raise TriageError(f"a {SEVERITY_NAMES.get(top, 'Low')} risk can be accepted for at most "
                              f"{limit} days (until {today + timedelta(days=limit)})")
        if not controls:
            raise TriageError("a risk acceptance needs the compensating controls, or 'none'")
    else:
        expires_on = None
    owners = Counter(f.owner_slug for f in found)
    d = TriageDecision(kind=kind, state="proposed", reason=reason, controls=controls, reference=reference,
                       owner_slug=owners.most_common(1)[0][0] if len(owners) == 1 else "mixed",
                       max_severity=top, expires_on=expires_on, requested_by=actor, requested_at=utcnow(),
                       source=source[:64])
    s.add(d)
    s.flush()
    for f in found:
        s.add(TriageItem(decision_id=d.id, fingerprint=f.fingerprint, finding_id=f.id))
    audit(s, actor, "triage.propose", f"decision:{d.id}", kind=kind, findings=len(found),
          max_severity=SEVERITY_NAMES.get(top, "Unknown"), expires_on=str(expires_on or ""), source=d.source)
    if can_approve and not policy.triage_four_eyes:
        _activate(s, d, actor, "self-approved: four eyes is off")
    s.commit()
    return d


def _items(s: Session, d: TriageDecision) -> list[Finding]:
    fps = list(s.scalars(select(TriageItem.fingerprint).where(TriageItem.decision_id == d.id)))
    out: list[Finding] = []
    for i in range(0, len(fps), 500):
        out.extend(s.scalars(select(Finding).where(Finding.fingerprint.in_(fps[i:i + 500]))))
    return out


def _activate(s: Session, d: TriageDecision, actor: str, note: str) -> int:
    d.state, d.decided_by, d.decided_at, d.decision_note = "active", actor, utcnow(), note
    status = KINDS[d.kind]
    n = 0
    for f in _items(s, d):
        if f.status == "open":
            f.status = status
            n += 1
    audit(s, actor, "triage.approve", f"decision:{d.id}", kind=d.kind, findings_changed=n, note=note[:300],
          requested_by=d.requested_by)
    return n


def get(s: Session, decision_id: int) -> TriageDecision:
    d = s.get(TriageDecision, decision_id)
    if d is None:
        raise TriageError(f"decision {decision_id} not found")
    return d


def approve(s: Session, policy: PolicyConfig, decision_id: int, actor: str, note: str = "",
            today: date | None = None) -> TriageDecision:
    d = get(s, decision_id)
    if d.state != "proposed":
        raise TriageError(f"decision #{d.id} is {d.state}, not proposed")
    if policy.triage_four_eyes and actor == d.requested_by:
        raise TriageError("four eyes: the approver must be a different person from the requester")
    if d.kind == "risk_acceptance" and d.expires_on and d.expires_on <= (today or _today()):
        raise TriageError("the expiry date has passed; reject this proposal and propose again")
    _activate(s, d, actor, (note or "").strip()[:MAX_TEXT])
    s.commit()
    return d


def reject(s: Session, decision_id: int, actor: str, note: str) -> TriageDecision:
    d = get(s, decision_id)
    if d.state != "proposed":
        raise TriageError(f"decision #{d.id} is {d.state}, not proposed")
    note = _text(note, "the rejection reason", 3)
    d.state, d.decided_by, d.decided_at, d.decision_note = "rejected", actor, utcnow(), note
    audit(s, actor, "triage.reject", f"decision:{d.id}", kind=d.kind, note=note[:300])
    s.commit()
    return d


def _end(s: Session, d: TriageDecision, state: str, actor: str, reason: str) -> int:
    was_active = d.state == "active"
    d.state, d.ended_by, d.ended_at, d.end_reason = state, actor, utcnow(), reason
    n = 0
    if was_active:
        status = KINDS[d.kind]
        for f in _items(s, d):
            if f.status == status:
                f.status = "open"
                n += 1
    audit(s, actor, f"triage.{state}", f"decision:{d.id}", kind=d.kind, findings_reopened=n,
          reason=reason[:300], was=("active" if was_active else "proposed"))
    return n


def revoke(s: Session, decision_id: int, actor: str, reason: str) -> TriageDecision:
    d = get(s, decision_id)
    if d.state not in LIVE:
        raise TriageError(f"decision #{d.id} is {d.state}; only proposed or active decisions can be revoked")
    _end(s, d, "revoked", actor, _text(reason, "the revoke reason", 3))
    s.commit()
    return d


def expire_due(s: Session, today: date | None = None, actor: str = "system") -> int:
    """End active risk acceptances whose expiry date has come. Their findings are open again."""
    today = today or _today()
    due = s.scalars(select(TriageDecision).where(TriageDecision.state == "active",
                                                 TriageDecision.kind == "risk_acceptance",
                                                 TriageDecision.expires_on <= today)).all()
    for d in due:
        _end(s, d, "expired", actor, f"expiry date {d.expires_on} reached")
    if due:
        s.commit()
    return len(due)


# -- notes ---------------------------------------------------------------------


def add_note(s: Session, target_type: str, target_id: str, author: str, body: str) -> Note:
    if target_type not in NOTE_TARGETS:
        raise TriageError(f"notes go on {', '.join(NOTE_TARGETS)}")
    body = _text(body, "a note")
    target_id = str(target_id)
    exists = {
        "finding": lambda: target_id.isdigit() and s.get(Finding, int(target_id)) is not None,
        "work_item": lambda: s.get(WorkItem, target_id) is not None,
        "decision": lambda: target_id.isdigit() and s.get(TriageDecision, int(target_id)) is not None,
    }[target_type]()
    if not exists:
        raise TriageError(f"{target_type.replace('_', ' ')} {target_id} not found")
    n = Note(target_type=target_type, target_id=target_id, author=author, body=body, created_at=utcnow())
    s.add(n)
    s.flush()
    audit(s, author, "note.add", f"{target_type}:{target_id}", note_id=n.id, chars=len(body))
    s.commit()
    return n


def notes_for(s: Session, target_type: str, target_id: str) -> list[Note]:
    return list(s.scalars(select(Note).where(Note.target_type == target_type, Note.target_id == str(target_id))
                          .order_by(Note.created_at, Note.id)))


# -- read models -----------------------------------------------------------------


def decision_findings(s: Session, d: TriageDecision) -> list[Finding]:
    return sorted(_items(s, d), key=lambda f: (-f.severity_id, f.id))


def decisions_for_finding(s: Session, f: Finding) -> list[TriageDecision]:
    return list(s.scalars(select(TriageDecision).join(TriageItem, TriageItem.decision_id == TriageDecision.id)
                          .where(TriageItem.fingerprint == f.fingerprint).order_by(TriageDecision.id.desc())))


def suggestions(s: Session, limit: int = 200) -> list[dict[str, Any]]:
    """Open findings whose latest DefectDojo export marks them false positive or risk accepted."""
    from kavlotryx.db import Observation, Scan

    latest: dict[str, tuple[int, dict[str, Any]]] = {}
    rows = s.execute(select(Observation.fingerprint, Observation.scan_id, Observation.raw)
                     .join(Scan, Scan.id == Observation.scan_id).where(Scan.scanner == "defectdojo")
                     .order_by(Observation.scan_id)).all()
    for fp, scan_id, raw in rows:
        latest[fp] = (scan_id, raw)
    hints = {fp: ((raw.get("unmapped") or {}).get("defectdojo") or {}) for fp, (_, raw) in latest.items()}
    hints = {fp: h for fp, h in hints.items() if h.get("triage")}
    if not hints:
        return []
    live = covering(s, list(hints))
    out = []
    for f in s.scalars(select(Finding).where(Finding.fingerprint.in_(list(hints)), Finding.status == "open")
                       .order_by(Finding.severity_id.desc(), Finding.id)):
        if f.fingerprint in live:
            continue
        h = hints[f.fingerprint]
        out.append({"f": f, "kind": "false_positive" if h["triage"] == "false_positive" else "risk_acceptance",
                    "dd_id": h.get("id"), "product": h.get("product", "")})
        if len(out) >= limit:
            break
    return out


def iso(v: Any) -> Any:
    if isinstance(v, datetime):
        return _aware(v).isoformat(timespec="seconds")
    if isinstance(v, date):
        return v.isoformat()
    return v


def decision_dict(s: Session, d: TriageDecision, with_findings: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": d.id, "kind": d.kind, "state": d.state, "reason": d.reason, "controls": d.controls,
        "reference": d.reference, "owner": d.owner_slug, "max_severity": SEVERITY_NAMES.get(d.max_severity, "Unknown"),
        "expires_on": iso(d.expires_on), "requested_by": d.requested_by, "requested_at": iso(d.requested_at),
        "decided_by": d.decided_by or None, "decided_at": iso(d.decided_at), "decision_note": d.decision_note,
        "ended_by": d.ended_by or None, "ended_at": iso(d.ended_at), "end_reason": d.end_reason,
        "source": d.source, "four_eyes": bool(d.decided_by) and d.decided_by != d.requested_by,
    }
    if with_findings:
        fs = decision_findings(s, d)
        out["findings"] = [{"id": f.id, "fingerprint": f.fingerprint, "severity": SEVERITY_NAMES.get(f.severity_id),
                            "id_or_rule": f.vuln_id or f.rule_key, "title": f.title[:200], "asset": f.asset_key,
                            "package": f.package, "owner": f.owner_slug, "status": f.status} for f in fs]
        out["finding_count"] = len(fs)
        out["by_severity"] = dict(Counter(SEVERITY_NAMES.get(f.severity_id, "Unknown") for f in fs))
    return out


def queue(s: Session, today: date | None = None, soon_days: int = 30) -> dict[str, Any]:
    today = today or _today()
    ds = s.scalars(select(TriageDecision).order_by(TriageDecision.id.desc())).all()
    counts = Counter(f for (f,) in s.execute(select(Finding.status).where(Finding.status.in_(TRIAGED))))
    return {
        "proposed": [d for d in ds if d.state == "proposed"],
        "expiring": sorted([d for d in ds if d.state == "active" and d.expires_on
                            and (d.expires_on - today).days <= soon_days], key=lambda d: d.expires_on),
        "decisions": ds,
        "state_counts": Counter(d.state for d in ds),
        "accepted": counts.get("accepted", 0), "false_positive": counts.get("false_positive", 0),
        "today": today,
    }


# -- audit-ready report (FR-IF-09) ------------------------------------------------------


def digest(body: dict[str, Any]) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode()).hexdigest()


def report(s: Session, policy: PolicyConfig, start: date, end: date, actor: str, owner: str = "",
           today: date | None = None) -> dict[str, Any]:
    """Triage register for one period, with control checks and a SHA-256 digest.

    A decision is in the period when it was live at any time in it: requested on
    or before the end, and not ended or ended on or after the start.
    """
    today = today or _today()
    if end < start:
        raise TriageError("the period end is before its start")
    lo = datetime.combine(start, datetime.min.time(), UTC)
    hi = datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC)
    rows = []
    for d in s.scalars(select(TriageDecision).order_by(TriageDecision.id)):
        req, ended, decided = _aware(d.requested_at), _aware(d.ended_at), _aware(d.decided_at)
        if req >= hi:
            continue
        stop = ended or (decided if d.state == "rejected" else None)
        if stop is not None and stop < lo:
            continue
        if owner and d.owner_slug != owner:
            continue
        rows.append(d)
    decisions = [decision_dict(s, d) for d in rows]
    accept = [x for x in decisions if x["kind"] == "risk_acceptance"]
    fps = [x for x in decisions if x["kind"] == "false_positive"]

    ev_q = (select(AuditEvent).where(AuditEvent.at >= lo, AuditEvent.at < hi,
                                     or_(AuditEvent.action.like("triage.%"), AuditEvent.action == "note.add"))
            .order_by(AuditEvent.at, AuditEvent.id))
    ids = {f"decision:{d.id}" for d in rows}
    events = [{"at": iso(e.at), "actor": e.actor, "action": e.action, "target": e.target, "detail": e.detail}
              for e in s.scalars(ev_q) if not owner or e.target in ids or e.action == "note.add"]
    note_q = select(Note).where(Note.created_at >= lo, Note.created_at < hi).order_by(Note.created_at, Note.id)
    notes = [{"id": n.id, "at": iso(n.created_at), "author": n.author, "target": f"{n.target_type}:{n.target_id}",
              "body": n.body} for n in s.scalars(note_q)]
    if owner:
        events = [e for e in events if e["action"] != "note.add" or e["target"] in ids]
        notes = [n for n in notes if n["target"] in ids]

    # control checks
    approved = [d for d in rows if d.decided_by and d.state in ("active", "expired", "revoked")]
    self_ok = [d.id for d in approved if d.decided_by == d.requested_by]
    over = [d.id for d in rows if d.kind == "risk_acceptance" and d.expires_on and d.decided_at and
            (d.expires_on - _aware(d.decided_at).date()).days > max_days(policy, d.max_severity)]
    no_exp = [d.id for d in rows if d.kind == "risk_acceptance" and not d.expires_on]
    stale = [d.id for d in rows if d.state == "proposed" and (today - _aware(d.requested_at).date()).days > 7]
    soon = [d.id for d in rows if d.state == "active" and d.expires_on and (d.expires_on - today).days <= 14]
    proposed_ev = {e.target for e in s.scalars(select(AuditEvent).where(AuditEvent.action == "triage.propose"))}
    no_trail = [d.id for d in rows if f"decision:{d.id}" not in proposed_ev]
    covered = set(s.scalars(select(TriageItem.fingerprint)
                            .join(TriageDecision, TriageDecision.id == TriageItem.decision_id)
                            .where(TriageDecision.state == "active")))
    orphans = [f.id for f in s.scalars(select(Finding).where(Finding.status.in_(TRIAGED)))
               if f.fingerprint not in covered]

    def check(name: str, bad: list[int], ok: str, fail: str, level: str = "fail") -> dict[str, Any]:
        return {"name": name, "status": "pass" if not bad else level, "detail": ok if not bad else fail,
                "items": bad[:50]}

    checks = [
        check("Segregation of duties", self_ok,
              "Every approved decision was approved by someone other than its requester.",
              f"{len(self_ok)} decisions were approved by their requester (four eyes was off).",
              "warn" if not policy.triage_four_eyes else "fail"),
        check("Expiry within policy", over + no_exp, "Every risk acceptance expires within the policy limit.",
              f"{len(over) + len(no_exp)} risk acceptances run past the policy limit or have no expiry."),
        check("Audit trail", no_trail, "Every decision has its proposal in the append-only audit log.",
              f"{len(no_trail)} decisions have no proposal event."),
        check("Status integrity", orphans, "Every accepted or false-positive finding is covered by an active decision.",
              f"{len(orphans)} findings are triaged without an active decision."),
        check("Pending proposals", stale, "No proposal has waited more than 7 days.",
              f"{len(stale)} proposals have waited more than 7 days for a decision.", "warn"),
        check("Expiring soon", soon, "No active risk acceptance expires in the next 14 days.",
              f"{len(soon)} risk acceptances expire in the next 14 days.", "warn"),
    ]
    open_now = s.scalars(select(Finding).where(Finding.status == "open")).all()
    status_counts = Counter(f for (f,) in s.execute(select(Finding.status)))
    body: dict[str, Any] = {
        "report": "kavlotryx-triage-register",
        "kavlotryx_version": __version__,
        "generated_at": iso(utcnow()),
        "generated_by": actor,
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "filters": {"owner": owner or None},
        "policy": {"four_eyes": policy.triage_four_eyes, "acceptance_max_days": policy.acceptance_max_days},
        "summary": {
            "findings_open": len(open_now),
            "findings_accepted": status_counts.get("accepted", 0),
            "findings_false_positive": status_counts.get("false_positive", 0),
            "findings_fixed": status_counts.get("fixed", 0),
            "decisions": len(decisions),
            "decisions_by_state": dict(Counter(x["state"] for x in decisions)),
            "risk_acceptances": len(accept),
            "false_positives": len(fps),
            "events": len(events), "notes": len(notes),
            "checks_failed": sum(1 for c in checks if c["status"] == "fail"),
            "checks_warned": sum(1 for c in checks if c["status"] == "warn"),
        },
        "controls": checks,
        "risk_acceptances": accept,
        "false_positives": fps,
        "events": events,
        "notes": notes,
    }
    return {**body, "digest": digest(body)}


REGISTER_COLUMNS = ["decision", "kind", "state", "owner", "max_severity", "findings", "reason", "controls",
                    "reference", "expires_on", "requested_by", "requested_at", "decided_by", "decided_at",
                    "four_eyes", "ended_by", "ended_at", "end_reason", "source"]


def register_rows(rep: dict[str, Any]) -> list[list[Any]]:
    out = []
    for x in rep["risk_acceptances"] + rep["false_positives"]:
        out.append([x["id"], x["kind"], x["state"], x["owner"], x["max_severity"], x["finding_count"], x["reason"],
                    x["controls"], x["reference"], x["expires_on"] or "", x["requested_by"], x["requested_at"],
                    x["decided_by"] or "", x["decided_at"] or "", "yes" if x["four_eyes"] else "no",
                    x["ended_by"] or "", x["ended_at"] or "", x["end_reason"], x["source"]])
    return out
