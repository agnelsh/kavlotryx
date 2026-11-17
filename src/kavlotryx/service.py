"""One object that wires settings, database, config and tracker for the API and CLI."""

from __future__ import annotations

from collections import Counter
from functools import cached_property
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kavlotryx.config import EDITABLE_POLICY_KEYS, PolicyConfig, Settings, load_ownership, load_policy
from kavlotryx.core.grouping import rebuild
from kavlotryx.core.ingest import ingest
from kavlotryx.core.ownership import Assignment, resolver_for
from kavlotryx.db import (
    AuditEvent,
    Finding,
    Observation,
    OwnerOverride,
    SettingOverride,
    UserPref,
    WorkItem,
    audit,
    init_db,
    make_engine,
    session_factory,
    utcnow,
)
from kavlotryx.dispatch import TicketTracker, make_tracker
from kavlotryx.dispatch.dispatcher import dispatch
from kavlotryx.ocsf.severity import SEVERITY_NAMES
from kavlotryx.verify import verify


class NotFound(LookupError):
    pass


class Kavlotryx:
    def __init__(self, settings: Settings, tracker: TicketTracker | None = None) -> None:
        self.settings = settings
        self.engine = make_engine(settings.database_url)
        init_db(self.engine)
        self.Session = session_factory(self.engine)
        self._tracker = tracker

    # config is re-read on each use so that an edited YAML file takes effect
    @property
    def ownership(self):
        return load_ownership(self.settings.config_dir)

    @property
    def policy(self) -> PolicyConfig:
        return load_policy(self.settings.config_dir, self.policy_overrides())

    def policy_overrides(self) -> dict:
        with self.session() as s:
            return {o.key: o.value for o in s.scalars(select(SettingOverride))}

    def set_policy(self, updates: dict, actor: str) -> PolicyConfig:
        """Validate and store console policy changes. Unknown keys are refused."""
        bad = sorted(set(updates) - set(EDITABLE_POLICY_KEYS))
        if bad:
            raise ValueError(f"not editable: {', '.join(bad)}")
        current = self.policy.model_dump()
        merged = PolicyConfig.model_validate({**current, **updates})  # raises on bad values
        if not 0 < merged.confidence_limit <= 1:
            raise ValueError("confidence_limit must be between 0 and 1")
        if any(d < 1 for d in merged.due_days.values()) or merged.scan_stale_hours < 1:
            raise ValueError("days and hours must be at least 1")
        with self.session() as s:
            for key, value in updates.items():
                value = getattr(merged, key)
                row = s.get(SettingOverride, key) or SettingOverride(key=key)
                row.value, row.updated_by, row.updated_at = value, actor, utcnow()
                s.add(row)
            audit(s, actor, "settings.policy", "policy", **{k: getattr(merged, k) for k in updates})
            s.commit()
        return self.policy

    def reset_policy(self, actor: str) -> None:
        with self.session() as s:
            keys = [o.key for o in s.scalars(select(SettingOverride))]
            for o in s.scalars(select(SettingOverride)):
                s.delete(o)
            audit(s, actor, "settings.policy.reset", "policy", keys=keys)
            s.commit()

    # -- console preferences ------------------------------------------------------

    def get_pref(self, principal: str) -> tuple[str, str]:
        with self.session() as s:
            p = s.get(UserPref, principal)
        if p and p.persona:
            return p.persona, p.team
        return self.settings.default_personas().get(principal, ""), (p.team if p else "")

    def set_pref(self, principal: str, persona: str | None = None, team: str | None = None) -> None:
        with self.session() as s:
            p = s.get(UserPref, principal) or UserPref(principal=principal)
            if persona is not None:
                p.persona = persona
            if team is not None:
                p.team = team
            p.updated_at = utcnow()
            s.add(p)
            s.commit()

    # -- connectors -----------------------------------------------------------------

    def sync_connector(self, name: str, actor: str = "system", rebuild: bool = True, client=None):
        from kavlotryx.connectors import sync

        with self.session() as s:
            run = sync(s, self.settings, self.ownership, name, actor=actor, client=client)
        if rebuild:
            self.rebuild()
        return run

    @cached_property
    def tracker(self) -> TicketTracker:
        return self._tracker or make_tracker(self.settings)

    def session(self) -> Session:
        return self.Session()

    # -- pipeline ---------------------------------------------------------------

    def ingest(self, scanner: str, data: bytes, scope: str | None = None, actor: str = "system"):
        with self.session() as s:
            return ingest(s, scanner, data, scope=scope, actor=actor)

    def rebuild(self):
        with self.session() as s:
            return rebuild(s, self.ownership, self.policy, self.settings.config_dir)

    def dispatch(self, dry_run: bool = False, actor: str = "system"):
        with self.session() as s:
            return dispatch(s, self.tracker, self.ownership, self.policy, dry_run=dry_run, actor=actor)

    def verify(self, dry_run: bool = False, actor: str = "system"):
        with self.session() as s:
            return verify(s, self.tracker, dry_run=dry_run, actor=actor)

    def run(self, dry_run: bool = False, actor: str = "system") -> dict[str, Any]:
        """rebuild -> dispatch -> verify, the normal cycle after new scans."""
        rb = self.rebuild()
        ds = self.dispatch(dry_run=dry_run, actor=actor)
        vf = self.verify(dry_run=dry_run, actor=actor)
        return {"rebuild": rb.__dict__,
                "dispatch": {a: ds.count(a) for a in ("create", "adopt", "update", "skip", "error")},
                "verify": {a: vf.count(a) for a in ("verified", "pending", "reopened", "resumed",
                                                    "superseded", "missing", "error")}}

    # -- ownership --------------------------------------------------------------

    def explain(self, finding_id: int) -> Assignment:
        with self.session() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise NotFound(f"finding {finding_id}")
            return resolver_for(s, self.ownership, self.policy, self.settings.config_dir).resolve(f)

    def set_owner(self, finding_id: int, owner: str, actor: str, reason: str = "",
                  match: str = "asset") -> OwnerOverride:
        cfg = self.ownership
        known = {o.slug for o in cfg.owners}
        if owner not in known:
            raise ValueError(f"unknown owner {owner!r}; known: {', '.join(sorted(known))}")
        if match not in ("asset", "finding"):
            raise ValueError("match must be 'asset' or 'finding'")
        with self.session() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise NotFound(f"finding {finding_id}")
            value = f.asset_key if match == "asset" else f.fingerprint
            o = s.scalar(select(OwnerOverride).where(OwnerOverride.match_type == match,
                                                     OwnerOverride.match_value == value))
            if o is None:
                o = OwnerOverride(match_type=match, match_value=value, owner_slug=owner,
                                  actor=actor, reason=reason)
                s.add(o)
            else:
                o.owner_slug, o.actor, o.reason, o.created_at = owner, actor, reason, utcnow()
            audit(s, actor, "owner.override", f"finding:{finding_id}", match=match, owner=owner,
                  previous=f.owner_slug, reason=reason)
            s.commit()
            return o

    # -- reports ----------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        limit = self.policy.confidence_limit
        today = utcnow().date()
        with self.session() as s:
            observations = s.scalar(select(func.count(Observation.id))) or 0
            findings = s.scalars(select(Finding)).all()
            items = s.scalars(select(WorkItem)).all()
            reassigned = s.scalar(select(func.count(AuditEvent.id))
                                  .where(AuditEvent.action == "owner.override")) or 0
            verified_events = s.scalar(select(func.count(AuditEvent.id))
                                       .where(AuditEvent.action == "verify.verified")) or 0
            reopen_events = s.scalar(select(func.count(AuditEvent.id))
                                     .where(AuditEvent.action == "verify.reopened")) or 0

        open_f = [f for f in findings if f.status == "open"]
        ticketed = [w for w in items if w.ticket_key]
        by_owner: dict[str, dict[str, int]] = {}
        for w in items:
            if w.state in ("verified", "superseded"):
                continue
            row = by_owner.setdefault(w.owner_slug, {"open_items": 0, "overdue": 0, "needs_review": 0})
            row["open_items"] += 1
            row["overdue"] += int(bool(w.due_date and w.due_date < today))
            row["needs_review"] += int(w.needs_review)

        def pct(a: int, b: int) -> float | None:
            return round(100.0 * a / b, 1) if b else None

        return {
            "findings": {
                "open": len(open_f),
                "fixed": sum(1 for f in findings if f.status == "fixed"),
                "open_by_severity": dict(Counter(SEVERITY_NAMES.get(f.severity_id, "Unknown")
                                                 for f in open_f)),
            },
            "work_items": {"by_state": dict(Counter(w.state for w in items)), "by_owner": by_owner},
            "metrics": {
                "noise_reduction": round(observations / len(ticketed), 1) if ticketed else None,
                "assignment_coverage_pct": pct(sum(1 for f in open_f if f.owner_confidence >= limit),
                                               len(open_f)),
                "ownership_accuracy_pct": pct(max(len(ticketed) - reassigned, 0), len(ticketed)),
                "verified_closures": verified_events,
                "reopen_rate_pct": pct(reopen_events, verified_events),
            },
        }
