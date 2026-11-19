"""Asset and threat context for ownership and priority (FR-EN-08, FR-PR-01/02).

* ``CmdbIndex`` matches a finding's asset to one ServiceNow configuration item.
* ``ThreatIndex`` gives the CISA KEV listing and the EPSS score of a CVE.

Both read only the local caches that a connector sync fills, so a rebuild
never calls an external API. Missing data is never an error (FR-EN-07).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import ServiceNowConnectorConfig
from kavlotryx.db import CmdbCi, Finding, ThreatIntel


@dataclass
class CiMatch:
    ci: CmdbCi | None
    how: str  # what matched, or why nothing did


def _short(v: str) -> str:
    return (v or "").split("@")[0].rsplit("/", 1)[-1].split(":")[0]


class CmdbIndex:
    def __init__(self, cis: list[CmdbCi], cfg: ServiceNowConnectorConfig) -> None:
        self.cfg = cfg
        self.by_key: dict[str, list[CmdbCi]] = defaultdict(list)
        self.by_name: dict[str, list[CmdbCi]] = defaultdict(list)
        for c in cis:
            for k in c.keys or []:
                self.by_key[k].append(c)
            if c.name:
                self.by_name[c.name.strip().lower()].append(c)
        self.size = len(cis)

    def __bool__(self) -> bool:
        return self.size > 0

    def _one(self, hits: list[CmdbCi]) -> CmdbCi | None:
        unique = {c.sys_id: c for c in hits}
        return next(iter(unique.values())) if len(unique) == 1 else None

    def match(self, f: Finding) -> CiMatch:
        if not self.size:
            return CiMatch(None, "ServiceNow not synced")
        tags = {k.lower(): (k, str(v)) for k, v in (f.tags or {}).items()}
        candidates: list[tuple[str, str, dict[str, list[CmdbCi]]]] = []
        for key in self.cfg.ci_tag_keys:
            hit = tags.get(key.lower())
            if hit and hit[1].strip():
                candidates.append((f"tag {hit[0]}={hit[1]}", hit[1], self.by_key))
        if f.asset_key:
            candidates.append(("resource id", f.asset_key, self.by_key))
            if f.asset_key.startswith("arn:") and "/" in f.asset_key:
                candidates.append(("resource id", f.asset_key.rsplit("/", 1)[-1], self.by_key))
        if self.cfg.match_names:
            for label, v in (("resource", f.asset_name), ("artifact", _short(f.artifact))):
                if v:
                    candidates.append((f"{label} name {v}", v, self.by_name))
        ambiguous = ""
        for label, value, index in candidates:
            hits = index.get(value.strip().lower()) or []
            ci = self._one(hits)
            if ci is not None:
                return CiMatch(ci, label)
            if hits and not ambiguous:
                ambiguous = f"{label} matches {len({c.sys_id for c in hits})} CIs; not used"
        return CiMatch(None, ambiguous or "asset matches no ServiceNow CI")


def cmdb_index(session: Session, cfg: ServiceNowConnectorConfig) -> CmdbIndex:
    return CmdbIndex(list(session.scalars(select(CmdbCi))), cfg)


class ThreatIndex:
    def __init__(self, rows: list[ThreatIntel]) -> None:
        self.rows = {r.cve: r for r in rows}

    def get(self, vuln_id: str) -> ThreatIntel | None:
        return self.rows.get((vuln_id or "").strip().upper())

    def __bool__(self) -> bool:
        return bool(self.rows)


def threat_index(session: Session, cves: set[str] | None = None) -> ThreatIndex:
    q = select(ThreatIntel)
    if cves is not None:
        q = q.where(ThreatIntel.cve.in_({c.upper() for c in cves if c}))
    return ThreatIndex(list(session.scalars(q)))


def threat_dict(t: ThreatIntel | None) -> dict[str, Any]:
    if t is None:
        return {"kev": False, "epss": None}
    return {"kev": t.kev, "kev_name": t.kev_name, "kev_added": t.kev_added.isoformat() if t.kev_added else None,
            "kev_due": t.kev_due.isoformat() if t.kev_due else None, "kev_ransomware": t.kev_ransomware,
            "epss": t.epss, "epss_percentile": t.epss_percentile,
            "epss_date": t.epss_date.isoformat() if t.epss_date else None}


def ci_dict(ci: CmdbCi | None) -> dict[str, Any] | None:
    if ci is None:
        return None
    return {"sys_id": ci.sys_id, "name": ci.name, "class": ci.class_name, "support_group": ci.support_group,
            "managed_by_group": ci.managed_by_group, "owned_by": ci.owned_by,
            "business_service": ci.business_service, "criticality": ci.criticality,
            "environment": ci.environment, "url": ci.url}
