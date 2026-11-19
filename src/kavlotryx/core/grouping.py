"""Resolve owners for open findings and group them into work items (FR-OW, FR-GR).

A group key joins the findings that one change removes, for one owner:

* vulnerability with a fix:    owner + artifact + source package
  (target version = the highest fixed version in the group)
* vulnerability without a fix: owner + artifact + source package, not dispatched by default
* misconfiguration:            owner + cloud account (or artifact) + rule

Priority (FR-PR-01/02) starts at the highest severity in the group, then:

* production or business-critical asset (tag, or ServiceNow CI): one level up
* EPSS score at or above ``epss_threshold``: one level up
* CVE in the CISA KEV catalog: at least ``kev_min_priority``

Each step that changes the priority is stored in ``priority_reasons``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, PolicyConfig
from kavlotryx.core.fingerprint import short_hash
from kavlotryx.core.intel import CmdbIndex, ThreatIndex, threat_index
from kavlotryx.core.ownership import resolver_for
from kavlotryx.db import Finding, WorkItem, utcnow

PRIORITIES = ["Informational", "Low", "Medium", "High", "Critical"]


def severity_to_priority(severity_id: int) -> str:
    if severity_id >= 5:
        return "Critical"
    return {4: "High", 3: "Medium", 2: "Low"}.get(severity_id, "Informational")


def raise_one(priority: str) -> str:
    i = PRIORITIES.index(priority)
    return PRIORITIES[min(i + 1, len(PRIORITIES) - 1)] if priority != "Informational" else priority


def version_key(v: str) -> tuple:
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.\-+:~_]", v) if p)


def prioritize(members: list[Finding], policy: PolicyConfig, threats: ThreatIndex,
               cmdb: CmdbIndex | None = None) -> tuple[str, list[dict[str, str]]]:
    """The work item priority and the reasons for it."""
    top = max(members, key=lambda m: m.severity_id)
    priority = severity_to_priority(top.severity_id)
    reasons: list[dict[str, Any]] = [{"code": "severity", "text": f"Highest severity is {priority}"
                                      + (f" ({top.vuln_id})" if top.vuln_id else "")}]

    def bump(code: str, text: str) -> None:
        nonlocal priority
        new = raise_one(priority)
        reasons.append({"code": code, "text": text + ("" if new != priority else "; already at the top")})
        priority = new

    prod_keys = {k.lower() for k in policy.production_tag_keys}
    prod_vals = {v.lower() for v in policy.production_values}
    critical = {v.lower() for v in policy.business_critical_values}
    impact = ""
    for m in members:
        hit = next(((k, v) for k, v in (m.tags or {}).items()
                    if k.lower() in prod_keys and str(v).lower() in prod_vals), None)
        if hit:
            impact = f"Production asset: tag {hit[0]}={hit[1]} on {m.asset_name or m.asset_key}"
            break
    if not impact and cmdb:
        for m in members:
            ci = cmdb.match(m).ci
            if ci is None:
                continue
            if ci.environment and ci.environment.lower() in prod_vals:
                impact = f"Production asset: ServiceNow CI {ci.name} is used for {ci.environment}"
            elif ci.criticality and ci.criticality.lower() in critical:
                impact = f"Business-critical asset: ServiceNow CI {ci.name} is {ci.criticality}"
            if impact:
                break
    if impact and priority != "Informational":
        bump("impact", impact)

    vulns = [(m, threats.get(m.vuln_id)) for m in members if m.vuln_id]
    scored = [(m, t) for m, t in vulns if t is not None and t.epss is not None]
    if policy.epss_threshold > 0 and scored:
        m, t = max(scored, key=lambda x: x[1].epss or 0.0)
        if (t.epss or 0.0) >= policy.epss_threshold and priority != "Informational":
            pct = f", percentile {t.epss_percentile * 100:.0f}" if t.epss_percentile is not None else ""
            bump("epss", f"EPSS {t.epss:.3f} for {m.vuln_id}{pct} (threshold {policy.epss_threshold:g})")

    kev = [(m, t) for m, t in vulns if t is not None and t.kev]
    if policy.kev_min_priority and kev:
        m, t = kev[0]
        floor = policy.kev_min_priority
        text = f"{m.vuln_id} is in the CISA KEV catalog" + (f" (added {t.kev_added.isoformat()})"
                                                             if t.kev_added else "")
        if t.kev_ransomware.lower() == "known":
            text += "; known ransomware use"
        if PRIORITIES.index(priority) < PRIORITIES.index(floor):
            priority = floor
            text += f"; at least {floor}"
        reasons.append({"code": "kev", "text": text})
    return priority, reasons


@dataclass
class RebuildReport:
    findings: int
    work_items: int
    needs_review: int
    reopened: int


def group_identity(f: Finding) -> tuple[str, dict[str, str]]:
    if f.kind == "vuln":
        kind = "vuln-fix" if f.fixed_version else "vuln-nofix"
        pkg = f.src_package or f.package
        return kind, {"artifact": f.artifact, "package": pkg}
    scope = f.account_uid or f.artifact
    return "config", {"account_uid": f.account_uid, "artifact": "" if f.account_uid else f.artifact,
                      "rule_key": f.rule_key, "scope": scope}


def _short(artifact: str) -> str:
    return artifact.rsplit("/", 1)[-1] or artifact


def _title(kind: str, ident: dict[str, str], members: list[Finding]) -> tuple[str, str]:
    if kind == "vuln-fix":
        target = max((m.fixed_version for m in members if m.fixed_version), key=version_key)
        n = len({m.vuln_id for m in members})
        return (f"Upgrade {ident['package']} to {target} in {_short(ident['artifact'])} "
                f"({n} {'vulnerability' if n == 1 else 'vulnerabilities'})", target)
    if kind == "vuln-nofix":
        n = len({m.vuln_id for m in members})
        return f"Track {ident['package']} in {_short(ident['artifact'])}: {n} with no fix yet", ""
    first = members[0]
    n = len({m.asset_key for m in members})
    where = f"account {ident['account_uid']}" if ident["account_uid"] else _short(ident["artifact"])
    noun = "resource" if n == 1 else "resources"
    return f"{first.title} ({n} {noun} in {where})", ""


def rebuild(
    session: Session,
    cfg: OwnershipConfig,
    policy: PolicyConfig,
    config_dir: Path,
) -> RebuildReport:
    resolver = resolver_for(session, cfg, policy, config_dir)
    open_findings = list(session.scalars(select(Finding).where(Finding.status == "open")))

    groups: dict[str, tuple[str, str, dict[str, str], list[Finding]]] = {}
    review = 0
    for f in open_findings:
        a = resolver.resolve(f)
        f.owner_slug, f.owner_rule, f.owner_source = a.owner, a.rule, a.source
        f.owner_evidence, f.owner_confidence, f.needs_review = a.evidence, a.confidence, a.needs_review
        review += int(a.needs_review)
        kind, ident = group_identity(f)
        key = "wi_" + short_hash(a.owner, kind, *(ident[k] for k in sorted(ident)))
        groups.setdefault(key, (a.owner, kind, ident, []))[3].append(f)
        f.work_item_key = key

    min_rank = PRIORITIES.index(policy.dispatch_min_priority)
    threats = threat_index(session, {f.vuln_id for f in open_findings if f.vuln_id})
    reopened = 0
    now = utcnow()
    for key, (owner, kind, ident, members) in groups.items():
        title, target = _title(kind, ident, members)
        priority, reasons = prioritize(members, policy, threats, resolver.cmdb)
        dispatchable = (
            priority != "Informational"
            and PRIORITIES.index(priority) >= min_rank
            and (kind != "vuln-nofix" or policy.dispatch_without_fix)
        )
        # Reason codes, not texts: a daily EPSS change must not rewrite every ticket.
        codes = sorted({r["code"] for r in reasons})
        content_hash = short_hash(title, priority, *codes, *sorted(m.fingerprint for m in members), length=32)

        wi = session.get(WorkItem, key)
        if wi is None:
            wi = WorkItem(key=key, owner_slug=owner, kind=kind, created_at=now, state="open")
            session.add(wi)
        elif wi.state in ("verified", "superseded", "triaged"):
            wi.state = "reopened"
            reopened += 1
        wi.artifact = ident.get("artifact", "")
        wi.package = ident.get("package", "")
        wi.account_uid = ident.get("account_uid", "")
        wi.rule_key = ident.get("rule_key", "")
        wi.fixed_version = target
        wi.title = title
        wi.priority = priority
        wi.priority_reasons = reasons
        wi.dispatchable = dispatchable
        wi.needs_review = any(m.needs_review for m in members)
        if wi.content_hash != content_hash:
            wi.content_hash = content_hash
            wi.updated_at = now

    session.commit()
    return RebuildReport(findings=len(open_findings), work_items=len(groups), needs_review=review,
                         reopened=reopened)


def members_by_item(session: Session) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    for f in session.scalars(select(Finding).where(Finding.work_item_key != "")):
        out[f.work_item_key].append(f)
    return out
