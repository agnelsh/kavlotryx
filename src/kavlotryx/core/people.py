"""People view (FR-OW-09): open findings mapped to engineers and their leaders.

The Microsoft Graph cache (``directory_people``) holds each person's Entra
groups, the groups they own and their manager. This module reads only that
cache and the stored owner of each finding. It never changes an owner.

A finding reaches people in three ways:

- **named**: the owner evidence (rule ``directory:graph`` or
  ``leanix:responsible``) or a person tag on the asset names one engineer;
- **team**: the finding's owner maps to Entra groups (``group_map``); every
  member of those groups sees it in the team queue;
- **leader**: owners of those groups lead the team. Each named engineer,
  team member and team lead has a ``manager`` chain. Every person on those
  chains sees the finding in their roll-up.

A finding whose owner has no mapped group with synced people and no named
engineer reaches nobody. The view lists those owners so the gap is visible.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig
from kavlotryx.db import DirectoryPerson, Finding, WorkItem

ACTIVE = ("open", "dispatched", "reopened", "pending_verification")
MAX_DEPTH = 12  # guards against manager cycles in bad directory data


@dataclass
class Stats:
    total: int = 0
    critical: int = 0
    high: int = 0
    overdue: int = 0
    oldest_days: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class PersonRow:
    p: DirectoryPerson
    role: str  # leader | engineer
    depth: int = 0
    teams: list[str] = field(default_factory=list)  # owner slugs through group membership
    leads: list[str] = field(default_factory=list)  # owner slugs through group ownership
    reports: list[str] = field(default_factory=list)  # direct report ids
    named: set[int] = field(default_factory=set)
    team: set[int] = field(default_factory=set)
    rollup: set[int] = field(default_factory=set)
    stats: Stats = field(default_factory=Stats)

    @property
    def findings(self) -> set[int]:
        """What this person answers for: the roll-up for a leader, named + team for an engineer."""
        return self.rollup if self.role == "leader" else self.named | self.team

    def as_dict(self) -> dict[str, Any]:
        p = self.p
        return {"id": p.id, "name": p.display_name, "upn": p.upn or p.mail, "title": p.job_title,
                "department": p.department, "manager_id": p.manager_id or None, "role": self.role,
                "teams": self.teams, "leads": self.leads, "reports": self.reports, "named": len(self.named),
                "team": len(self.team), "rollup": len(self.rollup), "stats": self.stats.as_dict()}


@dataclass
class OrgView:
    rows: dict[str, PersonRow]
    order: list[str]  # depth-first: each leader before their reports
    unreached: list[dict[str, Any]]
    total_open: int
    named_total: int
    reached_total: int
    led_total: int

    def chain(self, pid: str) -> list[DirectoryPerson]:
        """Managers above ``pid``, nearest first."""
        out: list[DirectoryPerson] = []
        seen = {pid}
        cur = self.rows[pid].p.manager_id if pid in self.rows else ""
        while cur and cur in self.rows and cur not in seen and len(out) < MAX_DEPTH:
            out.append(self.rows[cur].p)
            seen.add(cur)
            cur = self.rows[cur].p.manager_id
        return out


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def build(s: Session, cfg: OwnershipConfig, today: date | None = None) -> OrgView:
    today = today or datetime.now(UTC).date()
    people = s.scalars(select(DirectoryPerson).order_by(DirectoryPerson.display_name)).all()
    findings = s.scalars(select(Finding).where(Finding.status == "open")).all()
    keys = {f.work_item_key for f in findings if f.work_item_key}
    items = {w.key: w for w in s.scalars(select(WorkItem).where(WorkItem.key.in_(keys)))} if keys else {}

    gcfg = cfg.connectors.graph
    group_owner = {g.lower(): o for g, o in gcfg.group_map.items()}
    lookup: dict[str, DirectoryPerson] = {}
    for p in people:
        for k in (p.upn, p.mail, p.nickname, p.id.lower()):
            if k:
                lookup.setdefault(k.lower(), p)

    rows: dict[str, PersonRow] = {}
    members: dict[str, set[str]] = defaultdict(set)
    leads: dict[str, set[str]] = defaultdict(set)
    for p in people:
        teams = sorted({group_owner[g.lower()] for g in p.groups or [] if g.lower() in group_owner})
        led = sorted({group_owner[g.lower()] for g in p.leads or [] if g.lower() in group_owner})
        rows[p.id] = PersonRow(p=p, role="engineer", teams=teams, leads=led)
        for o in teams:
            members[o].add(p.id)
        for o in led:
            leads[o].add(p.id)
    for p in people:
        if p.manager_id and p.manager_id in rows and p.manager_id != p.id:
            rows[p.manager_id].reports.append(p.id)
    for r in rows.values():
        if r.reports or r.leads:
            r.role = "leader"

    def ancestors(pid: str) -> list[str]:
        out: list[str] = []
        seen = {pid}
        cur = rows[pid].p.manager_id
        while cur and cur in rows and cur not in seen and len(out) < MAX_DEPTH:
            out.append(cur)
            seen.add(cur)
            cur = rows[cur].p.manager_id
        return out

    anc_cache: dict[str, list[str]] = {}

    def anc(pid: str) -> list[str]:
        if pid not in anc_cache:
            anc_cache[pid] = ancestors(pid)
        return anc_cache[pid]

    owner_leaders: dict[str, set[str]] = {}

    def leaders_of(owner: str) -> set[str]:
        if owner not in owner_leaders:
            out = set(leads.get(owner, set()))
            for pid in members.get(owner, set()) | out:
                out.update(anc(pid))
            owner_leaders[owner] = out
        return owner_leaders[owner]

    tag_keys = [k.lower() for k in gcfg.person_tag_keys]

    def named_person(f: Finding) -> DirectoryPerson | None:
        ev = f.owner_evidence or {}
        for k in ("person", "responsible"):
            v = str(ev.get(k) or "").strip().lower()
            if v and v in lookup:
                return lookup[v]
        for k, v in (f.tags or {}).items():
            if k.lower() in tag_keys and str(v).strip().lower() in lookup:
                return lookup[str(v).strip().lower()]
        return None

    stats_src: dict[int, tuple[int, bool, int]] = {}
    unreached: dict[str, int] = defaultdict(int)
    named_total = reached_total = led_total = 0
    now = datetime.now(UTC)
    for f in findings:
        w = items.get(f.work_item_key)
        overdue = bool(w and w.due_date and w.state in ACTIVE and w.due_date < today)
        stats_src[f.id] = (f.severity_id, overdue, (now - _aware(f.first_seen)).days)
        person = named_person(f)
        reached: set[str] = set()
        if person is not None:
            named_total += 1
            rows[person.id].named.add(f.id)
            reached.add(person.id)
            for a in anc(person.id):
                rows[a].rollup.add(f.id)
                reached.add(a)
        for pid in members.get(f.owner_slug, set()):
            rows[pid].team.add(f.id)
            reached.add(pid)
        top = leaders_of(f.owner_slug)
        for pid in top:
            rows[pid].rollup.add(f.id)
            reached.add(pid)
        if top or (person is not None and anc(person.id)):
            led_total += 1
        if reached:
            reached_total += 1
        else:
            unreached[f.owner_slug] += 1

    for r in rows.values():
        st = Stats()
        for fid in r.findings:
            sev, overdue, age = stats_src[fid]
            st.total += 1
            st.critical += sev == 5
            st.high += sev == 4
            st.overdue += overdue
            st.oldest_days = age if st.oldest_days is None else max(st.oldest_days, age)
        r.stats = st

    order: list[str] = []

    def sort_key(pid: str) -> tuple:
        r = rows[pid]
        return (r.role != "leader", -r.stats.critical, -r.stats.total, r.p.display_name.lower())

    def walk(pid: str, depth: int, seen: set[str]) -> None:
        if pid in seen or depth > MAX_DEPTH:
            return
        seen.add(pid)
        rows[pid].depth = depth
        order.append(pid)
        for c in sorted(rows[pid].reports, key=sort_key):
            walk(c, depth + 1, seen)

    seen: set[str] = set()
    roots = [pid for pid, r in rows.items() if not r.p.manager_id or r.p.manager_id not in rows]
    for pid in sorted(roots, key=sort_key):
        walk(pid, 0, seen)
    for pid in sorted(set(rows) - seen, key=sort_key):  # people inside a manager cycle
        walk(pid, 0, seen)

    mapped = {o for o in group_owner.values()}
    gaps = []
    for owner, n in sorted(unreached.items(), key=lambda x: -x[1]):
        if owner not in mapped:
            why = "no Entra group is mapped to this owner"
        elif not members.get(owner) and not leads.get(owner):
            why = "the mapped Entra group has no synced people"
        else:  # pragma: no cover - members exist means the finding was reached
            why = "no person found"
        gaps.append({"owner": owner, "findings": n, "why": why})
    return OrgView(rows=rows, order=order, unreached=gaps, total_open=len(findings), named_total=named_total,
                   reached_total=reached_total, led_total=led_total)


def findings_for(s: Session, cfg: OwnershipConfig, pid: str) -> set[int] | None:
    """Open finding ids a person answers for, or ``None`` when the person is not in the cache."""
    org = build(s, cfg)
    row = org.rows.get(pid)
    return None if row is None else set(row.findings)
