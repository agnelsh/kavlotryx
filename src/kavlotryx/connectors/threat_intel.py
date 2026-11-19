"""Threat intelligence feeds (FR-PR-02): CISA KEV and FIRST EPSS.

* ``kev``: the CISA Known Exploited Vulnerabilities catalog, one JSON file.
  The whole catalog is stored (under 2,000 rows), so a CVE that a later scan
  reports is matched without a new sync.
* ``epss``: the FIRST Exploit Prediction Scoring System. Live mode asks the
  EPSS API only for the CVEs that Kavlotryx has findings for, 100 per request.
  A snapshot is an EPSS API response (JSON) or the daily CSV (optionally .gz).

Both feeds are public and need no credentials. Live mode is opt-in
(``KAVLO_THREAT_INTEL_LIVE=1``) because it calls the Internet; snapshots work
air-gapped. A rebuild reads only the local ``threat_intel`` table.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, Settings
from kavlotryx.connectors.base import ConnectorError, HttpClient, record_run
from kavlotryx.db import ConnectorRun, Finding, ThreatIntel, utcnow

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
BATCH = 100


def _https(url: str, name: str) -> str:
    if not url.startswith("https://"):
        raise ConnectorError(f"{name} must be an https:// address")
    return url


def _date(v: Any) -> date | None:
    try:
        return date.fromisoformat(str(v)[:10]) if v else None
    except ValueError:
        return None


def _float(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 1.0 else None


def _read(path: str) -> bytes:
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise ConnectorError(f"cannot read snapshot {path}: {e}") from e
    return gzip.decompress(data) if path.endswith(".gz") else data


def _rows(session: Session) -> dict[str, ThreatIntel]:
    return {t.cve: t for t in session.scalars(select(ThreatIntel))}


def _row(rows: dict[str, ThreatIntel], session: Session, cve: str) -> ThreatIntel:
    t = rows.get(cve)
    if t is None:
        t = ThreatIntel(cve=cve, kev=False, kev_name="", kev_ransomware="", kev_action="")
        session.add(t)
        rows[cve] = t
    return t


def finding_cves(session: Session) -> list[str]:
    ids = {(v or "").strip().upper() for v in session.scalars(select(Finding.vuln_id).distinct())}
    return sorted(i for i in ids if CVE_RE.match(i))


# -- CISA KEV ----------------------------------------------------------------------


def parse_kev(data: bytes) -> tuple[str, list[dict[str, Any]]]:
    try:
        body = json.loads(data)
    except ValueError as e:
        raise ConnectorError(f"KEV feed is not JSON: {e}") from e
    vulns = body.get("vulnerabilities") if isinstance(body, dict) else None
    if not isinstance(vulns, list):
        raise ConnectorError("KEV feed has no 'vulnerabilities' list")
    return str(body.get("catalogVersion") or ""), [v for v in vulns if isinstance(v, dict)]


def sync_kev(session: Session, settings: Settings, cfg: OwnershipConfig, actor: str = "system",
             client: HttpClient | None = None) -> ConnectorRun:
    from kavlotryx.connectors import connector_mode

    mode = "live" if client is not None else connector_mode(settings, "kev")
    if mode == "off":
        raise ConnectorError("CISA KEV is off: set KAVLO_THREAT_INTEL_LIVE=1 or KAVLO_KEV_SNAPSHOT")

    def work() -> dict[str, Any]:
        if mode == "snapshot":
            raw = _read(settings.kev_snapshot)
        else:
            raw = (client or HttpClient()).request("GET", _https(settings.kev_url, "KAVLO_KEV_URL")).content
        version, vulns = parse_kev(raw)
        rows = _rows(session)
        listed: set[str] = set()
        for v in vulns:
            cve = str(v.get("cveID") or "").strip().upper()
            if not CVE_RE.match(cve):
                continue
            listed.add(cve)
            t = _row(rows, session, cve)
            t.kev, t.kev_name = True, str(v.get("vulnerabilityName") or "")[:2000]
            t.kev_added, t.kev_due = _date(v.get("dateAdded")), _date(v.get("dueDate"))
            t.kev_ransomware = str(v.get("knownRansomwareCampaignUse") or "")[:16]
            t.kev_action = str(v.get("requiredAction") or "")[:4000]
            t.updated_at = utcnow()
        removed = 0
        for cve, t in rows.items():
            if t.kev and cve not in listed:  # CISA removes an entry only rarely, but it happens
                t.kev, t.kev_name, t.kev_added, t.kev_due, t.kev_ransomware, t.kev_action = (
                    False, "", None, None, "", "")
                removed += 1
        mine = set(finding_cves(session)) & listed
        return {"catalog": len(listed), "version": version, "removed": removed, "in_findings": len(mine)}

    return record_run(session, "kev", mode, actor, work)


# -- FIRST EPSS --------------------------------------------------------------------


def parse_epss(data: bytes) -> tuple[date | None, list[tuple[str, float | None, float | None]]]:
    """An EPSS API response (JSON) or the EPSS CSV -> (score date, [(cve, epss, percentile)])."""
    text = data.decode("utf-8", errors="replace").lstrip("﻿")
    if text.lstrip().startswith("{"):
        try:
            body = json.loads(text)
        except ValueError as e:
            raise ConnectorError(f"EPSS response is not JSON: {e}") from e
        items = body.get("data") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise ConnectorError("EPSS response has no 'data' list")
        out = [(str(i.get("cve") or "").upper(), _float(i.get("epss")), _float(i.get("percentile")))
               for i in items if isinstance(i, dict)]
        when = next((_date(i.get("date")) for i in items if isinstance(i, dict) and i.get("date")), None)
        return when, out
    when = None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", lines[0])
        when = _date(m.group(1)) if m else None
        lines = lines[1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "cve" not in reader.fieldnames or "epss" not in reader.fieldnames:
        raise ConnectorError("EPSS CSV needs the columns cve, epss, percentile")
    return when, [(str(r.get("cve") or "").upper(), _float(r.get("epss")), _float(r.get("percentile")))
                  for r in reader]


def sync_epss(session: Session, settings: Settings, cfg: OwnershipConfig, actor: str = "system",
              client: HttpClient | None = None, sleep: Callable[[float], None] | None = None) -> ConnectorRun:
    from kavlotryx.connectors import connector_mode

    mode = "live" if client is not None else connector_mode(settings, "epss")
    if mode == "off":
        raise ConnectorError("EPSS is off: set KAVLO_THREAT_INTEL_LIVE=1 or KAVLO_EPSS_SNAPSHOT")

    def work() -> dict[str, Any]:
        wanted = finding_cves(session)
        scores: list[tuple[str, float | None, float | None]] = []
        when: date | None = None
        if mode == "snapshot":
            when, scores = parse_epss(_read(settings.epss_snapshot))
        else:
            http = client or HttpClient()
            url = _https(settings.epss_url, "KAVLO_EPSS_URL")
            for i in range(0, len(wanted), BATCH):
                batch = wanted[i:i + BATCH]
                resp = http.request("GET", url, params={"cve": ",".join(batch), "limit": str(BATCH)})
                day, part = parse_epss(resp.content)
                when = when or day
                scores += part
        keep = set(wanted)
        rows = _rows(session)
        scored = 0
        for cve, epss, pct in scores:
            if cve not in keep or epss is None:
                continue
            t = _row(rows, session, cve)
            t.epss, t.epss_percentile, t.epss_date, t.updated_at = epss, pct, when, utcnow()
            scored += 1
        return {"cves": len(wanted), "scored": scored, "date": when.isoformat() if when else ""}

    return record_run(session, "epss", mode, actor, work)
