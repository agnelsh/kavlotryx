"""Connectors: ownership sources (FR-EN-06/08) and threat intelligence (FR-PR-02).

Ownership: Microsoft Graph, LeanIX and the ServiceNow CMDB. Threat
intelligence: CISA KEV and FIRST EPSS. A sync copies what Kavlotryx needs
into local tables (directory_people, catalog_apps, cmdb_cis, threat_intel).
The resolver and the priority rules read only those tables, so a rebuild
never calls an external API and an outage is just missing data (FR-EN-07).
Each connector runs live (credentials from the environment) or from a
snapshot file (demos, air-gapped installs).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, Settings
from kavlotryx.connectors.base import ConnectorError
from kavlotryx.db import ConnectorRun

CONNECTORS = ("graph", "leanix", "servicenow", "kev", "epss")
LABELS = {"graph": "Microsoft Graph", "leanix": "LeanIX", "servicenow": "ServiceNow CMDB", "kev": "CISA KEV",
          "epss": "FIRST EPSS"}


def connector_mode(settings: Settings, name: str) -> str:
    """'snapshot', 'live' or 'off'."""
    if name == "graph":
        if settings.graph_snapshot:
            return "snapshot"
        if settings.graph_tenant_id and settings.graph_client_id and settings.graph_client_secret:
            return "live"
    elif name == "leanix":
        if settings.leanix_snapshot:
            return "snapshot"
        if settings.leanix_host and settings.leanix_token:
            return "live"
    elif name == "servicenow":
        if settings.servicenow_snapshot:
            return "snapshot"
        if settings.servicenow_instance and (settings.servicenow_token or
                                             (settings.servicenow_user and settings.servicenow_password)):
            return "live"
    elif name in ("kev", "epss"):
        if getattr(settings, f"{name}_snapshot"):
            return "snapshot"
        if settings.threat_intel_live:
            return "live"
    return "off"


def sync(session: Session, settings: Settings, cfg: OwnershipConfig, name: str, actor: str = "system",
         client: Any = None) -> ConnectorRun:
    if name == "graph":
        from kavlotryx.connectors.graph import sync_graph as fn
    elif name == "leanix":
        from kavlotryx.connectors.leanix import sync_leanix as fn
    elif name == "servicenow":
        from kavlotryx.connectors.servicenow import sync_servicenow as fn
    elif name == "kev":
        from kavlotryx.connectors.threat_intel import sync_kev as fn
    elif name == "epss":
        from kavlotryx.connectors.threat_intel import sync_epss as fn
    else:
        raise ConnectorError(f"unknown connector {name!r}; known: {', '.join(CONNECTORS)}")
    return fn(session, settings, cfg, actor=actor, client=client)


def last_runs(session: Session) -> dict[str, ConnectorRun | None]:
    out: dict[str, ConnectorRun | None] = {}
    for name in CONNECTORS:
        out[name] = session.scalars(select(ConnectorRun).where(ConnectorRun.connector == name)
                                    .order_by(ConnectorRun.id.desc()).limit(1)).first()
    return out


__all__ = ["CONNECTORS", "LABELS", "ConnectorError", "connector_mode", "last_runs", "sync"]
