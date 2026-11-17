"""Page models for the console: dashboards, vulnerability explorer, ownership, scanners, settings.

Every number comes from the database. Nothing here writes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from kavlotryx.config import EDITABLE_POLICY_KEYS, OwnershipConfig, PolicyConfig, Settings
from kavlotryx.connectors import CONNECTORS, connector_mode, last_runs
from kavlotryx.db import (
    AuditEvent,
    CatalogApp,
    DirectoryPerson,
    Finding,
    FindingSource,
    Observation,
    OwnerOverride,
    Scan,
    SettingOverride,
    WorkItem,
    utcnow,
)
from kavlotryx.web.views import RULE_FAMILIES, pct, rule_family, rule_ladder, sev_name

PERSONAS = [
    ("analyst", "Vulnerability analyst", "One prioritized queue across all scanners"),
    ("team_lead", "Engineering team lead", "Only the work that belongs to my team"),
    ("platform", "Cloud platform owner", "Root-cause fixes, not single findings"),
    ("security_manager", "Security manager", "Proof of progress against due dates"),
    ("change_manager", "Change manager", "Fixes that touch production"),
]
PERSONA_KEYS = [p[0] for p in PERSONAS]
ACTIVE = ("open", "dispatched", "reopened", "pending_verification")
PRIO_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    from datetime import UTC

    return v if v.tzinfo else v.replace(tzinfo=UTC)


def _hours_since(v: datetime | None) -> float | None:
    v = _aware(v)
    return (utcnow() - v).total_seconds() / 3600 if v else None


# -- pipeline status (every dashboard) -----------------------------------------


def scopes(s: Session, policy: PolicyConfig) -> list[dict[str, Any]]:
    """One row per scanner + scope: last scan, age, open findings it reports, fresh or stale."""
    last: dict[tuple[str, str], Scan] = {}
    for sc in s.scalars(select(Scan).order_by(Scan.id)):
        last[(sc.scanner, sc.scope)] = sc
    present = Counter()
    for scanner, scope_, n in s.execute(
            select(FindingSource.scanner, FindingSource.scope, func.count())
            .join(Finding, Finding.id == FindingSource.finding_id)
            .where(FindingSource.present.is_(True), Finding.status == "open")
            .group_by(FindingSource.scanner, FindingSource.scope)):
        present[(scanner, scope_)] = n
    rows = []
    for (scanner, scope_), sc in sorted(last.items()):
        age = _hours_since(sc.received_at)
        rows.append({"scanner": scanner, "scope": scope_, "scan": sc, "age_h": age,
                     "open": present.get((scanner, scope_), 0),
                     "stale": age is not None and age > policy.scan_stale_hours})
    return rows


def pipeline(s: Session, settings: Settings, policy: PolicyConfig) -> dict[str, Any]:
    items = s.scalars(select(WorkItem)).all()
    sc = scopes(s, policy)
    runs = last_runs(s)
    stages = [
        ("Observations", s.scalar(select(func.count(Observation.id))) or 0, "raw scanner rows"),
        ("Open findings", s.scalar(select(func.count(Finding.id)).where(Finding.status == "open")) or 0,
         "after dedupe"),
        ("Work items", sum(1 for w in items if w.state in ACTIVE), "active fixes"),
        ("Tickets", sum(1 for w in items if w.ticket_key and w.state in ACTIVE), "open in the tracker"),
        ("Verified", sum(1 for w in items if w.state == "verified"), "closed by a clean scan"),
    ]
    connectors = []
    for n in CONNECTORS:
        r = runs[n]
        connectors.append({"name": n, "label": "Microsoft Graph" if n == "graph" else "LeanIX",
                           "mode": connector_mode(settings, n), "run": r,
                           "age_h": _hours_since(r.finished_at) if r else None})
    last_scan = max((r["scan"].received_at for r in sc), default=None, key=lambda d: _aware(d))
    return {"stages": stages, "scopes": sc, "stale": sum(1 for r in sc if r["stale"]),
            "connectors": connectors, "last_scan": last_scan,
            "review": s.scalar(select(func.count(Finding.id)).where(Finding.status == "open",
                                                                    Finding.needs_review.is_(True))) or 0}


# -- persona dashboards -----------------------------------------------------------


def _open_counts(s: Session) -> Counter[str]:
    c: Counter[str] = Counter()
    for key, in s.execute(select(Finding.work_item_key).where(Finding.status == "open", Finding.work_item_key != "")):
        c[key] += 1
    return c


def dashboard(s: Session, persona: str, team: str, summary: dict[str, Any], policy: PolicyConfig,
              owners: list[str]) -> dict[str, Any]:
    today = utcnow().date()
    items = s.scalars(select(WorkItem)).all()
    active = [w for w in items if w.state in ACTIVE]
    open_counts = _open_counts(s)
    d: dict[str, Any] = {"today": today, "open_counts": open_counts}

    if persona == "analyst":
        open_f = s.scalars(select(Finding).where(Finding.status == "open")).all()
        sev = Counter(f.severity_id for f in open_f)
        d["severity"] = [(sev_name(i), sev.get(i, 0), i) for i in (6, 5, 4, 3, 2, 1, 0) if sev.get(i)]
        d["sev_max"] = max([n for _, n, _ in d["severity"]] or [1])
        src = Counter(sc for sc, in s.execute(
            select(FindingSource.scanner).join(Finding, Finding.id == FindingSource.finding_id)
            .where(Finding.status == "open", FindingSource.present.is_(True))))
        d["scanners"] = src.most_common()
        d["scanner_max"] = max(src.values() or [1])
        multi = Counter(fid for fid, in s.execute(select(FindingSource.finding_id)))
        d["merged"] = sum(1 for n in multi.values() if n > 1)
        d["review_rows"] = sorted((f for f in open_f if f.needs_review), key=lambda f: -f.severity_id)[:8]
        d["newest"] = sorted(open_f, key=lambda f: (_aware(f.first_seen), f.severity_id), reverse=True)[:8]
    elif persona == "team_lead":
        team = team if team in owners else (owners[0] if owners else "")
        mine = sorted((w for w in active if w.owner_slug == team),
                      key=lambda w: (w.due_date or today + timedelta(days=9999), PRIO_RANK.get(w.priority, 9)))
        d["team"] = team
        d["mine"] = mine
        d["overdue"] = sum(1 for w in mine if w.due_date and w.due_date < today)
        d["due_soon"] = sum(1 for w in mine if w.due_date and today <= w.due_date <= today + timedelta(days=7))
        d["verified_30"] = sum(1 for w in items if w.owner_slug == team and w.state == "verified" and w.verified_at
                               and _aware(w.verified_at) >= utcnow() - timedelta(days=30))
        d["team_review"] = s.scalars(select(Finding).where(Finding.status == "open", Finding.owner_slug == team,
                                                           Finding.needs_review.is_(True)).limit(8)).all()
    elif persona == "platform":
        d["top_items"] = sorted(active, key=lambda w: -open_counts.get(w.key, 0))[:10]
        d["top_max"] = max([open_counts.get(w.key, 0) for w in d["top_items"]] or [1])
        spread: dict[str, set[str]] = defaultdict(set)
        rules: dict[str, set[str]] = defaultdict(set)
        titles: dict[str, str] = {}
        for f in s.scalars(select(Finding).where(Finding.status == "open")):
            if f.kind == "vuln":
                spread[f.src_package or f.package].add(f.artifact)
            else:
                rules[f.rule_key].add(f.asset_key)
                titles.setdefault(f.rule_key, f.title)
        d["packages"] = sorted(((p, len(a)) for p, a in spread.items()), key=lambda x: -x[1])[:8]
        d["rules"] = sorted(((r, titles[r], len(a)) for r, a in rules.items()), key=lambda x: -x[2])[:8]
    elif persona == "security_manager":
        m = summary["metrics"]
        dispatched = [w for w in active if w.due_date]
        on_time = sum(1 for w in dispatched if w.due_date >= today)
        sla = pct(on_time, len(dispatched)) if dispatched else None
        d["targets"] = [
            ("Noise reduction", f"{m['noise_reduction']}:1" if m["noise_reduction"] else "—", "≥ 20:1",
             m["noise_reduction"] is not None and m["noise_reduction"] >= 20),
            ("Ownership accuracy", _p(m["ownership_accuracy_pct"]), "≥ 90%", _ge(m["ownership_accuracy_pct"], 90)),
            ("Assignment coverage", _p(m["assignment_coverage_pct"]), "≥ 80%", _ge(m["assignment_coverage_pct"], 80)),
            ("Within SLA", _p(sla), "≥ 85%", _ge(sla, 85)),
            ("Verified closure rate", "100%" if m["verified_closures"] else "—", "100%", True),
            ("Reopen rate", _p(m["reopen_rate_pct"]), "≤ 5%",
             m["reopen_rate_pct"] is not None and m["reopen_rate_pct"] <= 5),
        ]
        buckets = Counter()
        for w in active:
            age = (today - _aware(w.created_at).date()).days
            buckets["0–7 days" if age <= 7 else "8–30 days" if age <= 30 else "31–90 days" if age <= 90
                    else "over 90 days"] += 1
        d["ages"] = [(k, buckets.get(k, 0)) for k in ("0–7 days", "8–30 days", "31–90 days", "over 90 days")]
        d["age_max"] = max([n for _, n in d["ages"]] or [1]) or 1
        d["by_owner"] = summary["work_items"]["by_owner"]
        d["verified"] = Counter(w.owner_slug for w in items if w.state == "verified")
        d["overdue_items"] = sorted((w for w in active if w.due_date and w.due_date < today),
                                    key=lambda w: w.due_date)[:10]
    elif persona == "change_manager":
        keys = {k.lower() for k in policy.production_tag_keys}
        vals = {v.lower() for v in policy.production_values}
        prod = set()
        for f in s.scalars(select(Finding).where(Finding.status == "open")):
            if any(k.lower() in keys and str(v).lower() in vals for k, v in (f.tags or {}).items()):
                prod.add(f.work_item_key)
        d["prod_items"] = sorted((w for w in active if w.key in prod),
                                 key=lambda w: PRIO_RANK.get(w.priority, 9))
        d["urgent"] = sorted((w for w in active if w.priority in ("Critical", "High") and w.ticket_key
                              and w.key not in prod), key=lambda w: PRIO_RANK.get(w.priority, 9))[:10]
        d["prod_keys"] = ", ".join(f"{k}={v}" for k in policy.production_tag_keys for v in policy.production_values)
    return d


def _p(v: float | None) -> str:
    return f"{v}%" if v is not None else "—"


def _ge(v: float | None, target: float) -> bool:
    return v is not None and v >= target


# -- vulnerability explorer ---------------------------------------------------------

SORTS = {"sev": Finding.severity_id, "first": Finding.first_seen, "last": Finding.last_seen,
         "owner": Finding.owner_slug, "package": Finding.package, "conf": Finding.owner_confidence}


@dataclass
class VulnFilter:
    q: str = ""
    sev: list[int] = field(default_factory=list)
    kind: str = ""
    status: str = "open"
    scanner: str = ""
    owner: str = ""
    rule: str = ""
    conf: str = ""
    account: str = ""
    artifact: str = ""
    fix: str = ""
    prod: str = ""
    wi_state: str = ""
    ticket: str = ""
    age: int = 0
    sort: str = "sev"
    dir: str = "desc"
    page: int = 1
    size: int = 50

    def params(self, **override: Any) -> list[tuple[str, Any]]:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        d.update(override)
        out: list[tuple[str, Any]] = []
        for k, v in d.items():
            if isinstance(v, list):
                out.extend((k, x) for x in v)
            elif v not in ("", None, 0) and not (k == "status" and v == "open") \
                    and not (k == "sort" and v == "sev") and not (k == "dir" and v == "desc") \
                    and not (k == "page" and v == 1) and not (k == "size" and v == 50):
                out.append((k, v))
        return out

    def qs(self, **override: Any) -> str:
        return urlencode(self.params(**override))

    def toggle_sev(self, sid: int) -> str:
        new = [x for x in self.sev if x != sid] if sid in self.sev else [*self.sev, sid]
        return self.qs(sev=new, page=1)

    def chips(self) -> list[tuple[str, str]]:
        labels = {"q": "search", "kind": "kind", "scanner": "scanner", "owner": "owner", "rule": "rule",
                  "conf": "confidence", "account": "account", "artifact": "artifact", "fix": "fix available",
                  "prod": "production", "wi_state": "work item", "ticket": "has ticket", "age": "first seen ≤ days"}
        out: list[tuple[str, str]] = []
        if self.sev:
            names = ", ".join(sev_name(x) for x in sorted(self.sev, reverse=True))
            out.append((f"severity: {names}", self.qs(sev=[], page=1)))
        for k, label in labels.items():
            v = getattr(self, k)
            if v:
                out.append((f"{label}: {v}", self.qs(**{k: 0 if k == "age" else "", "page": 1})))
        if self.status != "open":
            out.append((f"status: {self.status or 'any'}", self.qs(status="open", page=1)))
        return out


def _apply(q, f: VulnFilter, policy: PolicyConfig):
    if f.status:
        q = q.where(Finding.status == f.status)
    if f.sev:
        q = q.where(Finding.severity_id.in_(f.sev))
    if f.kind:
        q = q.where(Finding.kind == f.kind)
    if f.owner:
        q = q.where(Finding.owner_slug == f.owner)
    if f.rule:
        if f.rule == "default":
            q = q.where(or_(Finding.owner_rule.like("default%"), Finding.owner_rule == "fallback"))
        else:
            q = q.where(Finding.owner_rule.like(f"{f.rule}%"))
    if f.conf == "review":
        q = q.where(Finding.needs_review.is_(True))
    elif f.conf == "ok":
        q = q.where(Finding.needs_review.is_(False))
    if f.scanner:
        q = q.where(Finding.id.in_(select(FindingSource.finding_id).where(FindingSource.scanner == f.scanner)))
    if f.account:
        q = q.where(Finding.account_uid == f.account)
    if f.artifact:
        q = q.where(Finding.artifact.ilike(f"%{f.artifact}%"))
    if f.fix == "yes":
        q = q.where(Finding.kind == "vuln", Finding.fixed_version != "")
    elif f.fix == "no":
        q = q.where(Finding.kind == "vuln", Finding.fixed_version == "")
    if f.prod == "yes":
        text = cast(Finding.tags, String)
        q = q.where(or_(*[text.ilike(f'%"{k}": "{v}"%') for k in policy.production_tag_keys
                          for v in policy.production_values]))
    if f.wi_state:
        q = q.where(Finding.work_item_key.in_(select(WorkItem.key).where(WorkItem.state == f.wi_state)))
    if f.ticket == "yes":
        q = q.where(Finding.work_item_key.in_(select(WorkItem.key).where(WorkItem.ticket_key != "")))
    elif f.ticket == "no":
        q = q.where(Finding.work_item_key.not_in(select(WorkItem.key).where(WorkItem.ticket_key != "")))
    if f.age:
        q = q.where(Finding.first_seen >= utcnow() - timedelta(days=f.age))
    if f.q:
        like = f"%{f.q.strip()}%"
        q = q.where(or_(Finding.vuln_id.ilike(like), Finding.package.ilike(like), Finding.asset_key.ilike(like),
                        Finding.asset_name.ilike(like), Finding.rule_key.ilike(like), Finding.fingerprint.ilike(like),
                        Finding.title.ilike(like), Finding.owner_slug.ilike(like), Finding.artifact.ilike(like)))
    return q


def explorer(s: Session, f: VulnFilter, policy: PolicyConfig, limit_all: int | None = None) -> dict[str, Any]:
    base = _apply(select(Finding), f, policy)
    ids = _apply(select(Finding.id), f, policy).subquery()
    total = s.scalar(select(func.count()).select_from(ids)) or 0
    col = SORTS.get(f.sort, Finding.severity_id)
    order = [col.desc() if f.dir == "desc" else col.asc(), Finding.severity_id.desc(), Finding.id]
    if limit_all is not None:
        return {"rows": s.scalars(base.order_by(*order).limit(limit_all)).all(), "total": total}
    size = f.size if f.size in (25, 50, 100, 200) else 50
    pages = max(1, -(-total // size))
    page = min(max(1, f.page), pages)
    rows = s.scalars(base.order_by(*order).limit(size).offset((page - 1) * size)).all()

    facet = {}
    for name, column in (("sev", Finding.severity_id), ("owner", Finding.owner_slug), ("kind", Finding.kind),
                         ("account", Finding.account_uid)):
        facet[name] = s.execute(select(column, func.count()).where(Finding.id.in_(select(ids)))
                                .group_by(column).order_by(func.count().desc())).all()
    facet["scanner"] = s.execute(select(FindingSource.scanner, func.count(func.distinct(FindingSource.finding_id)))
                                 .where(FindingSource.finding_id.in_(select(ids)))
                                 .group_by(FindingSource.scanner).order_by(func.count().desc())).all()
    rules = Counter()
    for r, n in s.execute(select(Finding.owner_rule, func.count()).where(Finding.id.in_(select(ids)))
                          .group_by(Finding.owner_rule)):
        rules[rule_family(r) or "none"] += n
    facet["rule"] = sorted(rules.items(), key=lambda x: RULE_FAMILIES.index(x[0]) if x[0] in RULE_FAMILIES else 99)

    keys = {r.work_item_key for r in rows if r.work_item_key}
    items = {w.key: w for w in s.scalars(select(WorkItem).where(WorkItem.key.in_(keys)))} if keys else {}
    srcs: dict[int, list[str]] = defaultdict(list)
    if rows:
        for fid, sc in s.execute(select(FindingSource.finding_id, FindingSource.scanner)
                                 .where(FindingSource.finding_id.in_([r.id for r in rows]))):
            srcs[fid].append(sc)
    return {"rows": rows, "total": total, "page": page, "pages": pages, "size": size, "facet": facet,
            "items": items, "sources": srcs}


def csv_safe(v: Any) -> str:
    """Neutralise spreadsheet formulas (CSV injection)."""
    text = "" if v is None else str(v)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


# -- ownership ------------------------------------------------------------------------


def ownership(s: Session, cfg: OwnershipConfig, policy: PolicyConfig, settings: Settings) -> dict[str, Any]:
    ladder, total, review = rule_ladder(s)
    open_f = s.scalars(select(Finding).where(Finding.status == "open")).all()
    items = s.scalars(select(WorkItem)).all()
    by_owner_f = Counter(f.owner_slug for f in open_f)
    by_owner_r = Counter(f.owner_slug for f in open_f if f.needs_review)
    by_owner_w = Counter(w.owner_slug for w in items if w.state in ACTIVE)
    groups_for: dict[str, list[str]] = defaultdict(list)
    for g, o in cfg.connectors.graph.group_map.items():
        groups_for[o].append(g)
    teams_for: dict[str, list[str]] = defaultdict(list)
    for t, o in cfg.connectors.leanix.team_map.items():
        teams_for[o].append(t)
    owners = [{"o": o, "findings": by_owner_f.get(o.slug, 0), "review": by_owner_r.get(o.slug, 0),
               "active": by_owner_w.get(o.slug, 0), "groups": groups_for.get(o.slug, []),
               "teams": teams_for.get(o.slug, [])} for o in cfg.owners]
    if by_owner_f.get(cfg.fallback_owner):
        owners.append({"o": None, "slug": cfg.fallback_owner, "findings": by_owner_f[cfg.fallback_owner],
                       "review": by_owner_r.get(cfg.fallback_owner, 0), "active": by_owner_w.get(cfg.fallback_owner, 0),
                       "groups": [], "teams": []})

    people = s.scalars(select(DirectoryPerson).order_by(DirectoryPerson.display_name)).all()
    members = Counter(g.lower() for p in people for g in p.groups)
    graph_groups = [{"group": g, "owner": o, "members": members.get(g.lower(), 0)}
                    for g, o in cfg.connectors.graph.group_map.items()]
    apps = s.scalars(select(CatalogApp).order_by(CatalogApp.name)).all()
    app_hits = Counter(str((f.owner_evidence or {}).get("app_id")) for f in open_f if f.owner_rule.startswith("leanix"))
    person_hits = Counter(str((f.owner_evidence or {}).get("person")) for f in open_f
                          if f.owner_rule.startswith("directory"))
    team_map = {k.lower(): v for k, v in cfg.connectors.leanix.team_map.items()}
    known = {o.slug for o in cfg.owners}
    app_rows = []
    for a in apps:
        mapped = next(((t, team_map.get(t.lower()) or (t.lower() if t.lower() in known else None))
                       for t in a.teams if team_map.get(t.lower()) or t.lower() in known), None)
        app_rows.append({"a": a, "mapped": mapped, "findings": app_hits.get(a.id, 0)})
    runs = last_runs(s)
    connectors = {n: {"mode": connector_mode(settings, n), "run": runs[n]} for n in CONNECTORS}
    review_rows = s.scalars(select(Finding).where(Finding.status == "open", Finding.needs_review.is_(True))
                            .order_by(Finding.severity_id.desc()).limit(25)).all()
    overrides = s.scalars(select(OwnerOverride).order_by(OwnerOverride.created_at.desc())).all()
    return {"ladder": ladder, "total": total, "review": review, "owners": owners, "people": people,
            "graph_groups": graph_groups, "apps": app_rows, "connectors": connectors, "review_rows": review_rows,
            "overrides": overrides, "person_hits": person_hits,
            "coverage": pct(sum(1 for f in open_f if not f.needs_review), len(open_f)) if open_f else None}


# -- scanners ---------------------------------------------------------------------------


def scanners(s: Session, policy: PolicyConfig, adapters: list[dict[str, str]]) -> dict[str, Any]:
    sc = scopes(s, policy)
    per = defaultdict(lambda: {"scopes": 0, "open": 0, "last": None, "stale": 0, "scans": 0})
    for r in sc:
        p = per[r["scanner"]]
        p["scopes"] += 1
        p["open"] += r["open"]
        p["stale"] += int(r["stale"])
        if p["last"] is None or _aware(r["scan"].received_at) > _aware(p["last"]):
            p["last"] = r["scan"].received_at
    for name, n in s.execute(select(Scan.scanner, func.count()).group_by(Scan.scanner)):
        per[name]["scans"] = n
    cards = []
    for a in adapters:
        p = per.get(a["name"]) or {"scopes": 0, "open": 0, "last": None, "stale": 0, "scans": 0}
        status = "never" if not p["last"] else ("stale" if p["stale"] else "fresh")
        cards.append({**a, **p, "status": status, "age_h": _hours_since(p["last"])})
    proofs = s.scalars(select(AuditEvent).where(AuditEvent.action.in_(
        ["verify.verified", "verify.pending", "verify.reopened", "verify.superseded"]))
        .order_by(AuditEvent.id.desc()).limit(12)).all()
    pitems = {w.key: w for w in s.scalars(select(WorkItem).where(WorkItem.key.in_({e.target for e in proofs})))} \
        if proofs else {}
    return {"cards": cards, "scopes": sc, "stale": sum(1 for r in sc if r["stale"]),
            "scans": s.scalars(select(Scan).order_by(Scan.id.desc()).limit(30)).all(),
            "scan_total": s.scalar(select(func.count(Scan.id))) or 0,
            "obs_total": s.scalar(select(func.count(Observation.id))) or 0,
            "proofs": proofs, "proof_items": pitems}


# -- settings -------------------------------------------------------------------------------


def settings_page(s: Session, settings: Settings, policy: PolicyConfig, cfg: OwnershipConfig,
                  tokens: dict | None) -> dict[str, Any]:
    from urllib.parse import urlsplit

    overrides = {o.key: o for o in s.scalars(select(SettingOverride))}
    file_policy = (settings.config_dir / "policy.yaml").exists()
    sources = {k: (f"console · {overrides[k].updated_by}" if k in overrides else
                   ("policy.yaml" if file_policy else "default")) for k in EDITABLE_POLICY_KEYS}
    personas = settings.default_personas()
    token_rows = sorted((p.name, p.role, personas.get(p.name, "")) for p in (tokens or {}).values())
    is_set = lambda v: bool(v)  # noqa: E731
    return {
        "policy": policy, "sources": sources, "overrides": overrides,
        "trk": {"kind": settings.tracker, "host": urlsplit(settings.jira_url).netloc,
                    "email": is_set(settings.jira_email), "token": is_set(settings.jira_token),
                    "issue_type": settings.jira_issue_type},
        "graph": {"mode": connector_mode(settings, "graph"), "tenant": is_set(settings.graph_tenant_id),
                  "client": is_set(settings.graph_client_id), "secret": is_set(settings.graph_client_secret),
                  "snapshot": settings.graph_snapshot},
        "leanix": {"mode": connector_mode(settings, "leanix"), "host": settings.leanix_host,
                   "token": is_set(settings.leanix_token), "snapshot": settings.leanix_snapshot,
                   "relation": cfg.connectors.leanix.team_relation},
        "tokens": token_rows, "auth_off": tokens is None,
        "config_dir": str(settings.config_dir), "owners": len(cfg.owners),
        "files": {n: (settings.config_dir / n).exists() for n in ("ownership.yaml", "policy.yaml")},
        "events": s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(60)).all(),
    }
