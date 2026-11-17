"""Ownership connectors (FR-EN-06): Microsoft Graph and LeanIX.

A sync copies what ownership needs into local tables (directory_people,
catalog_apps). The resolver reads only those tables, so a rebuild never
calls an external API and an outage is just missing data (FR-EN-07).
Each connector runs live (credentials from the environment) or from a JSON
snapshot file (demos, air-gapped installs).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, Settings
from kavlotryx.connectors.base import ConnectorError
from kavlotryx.db import ConnectorRun

CONNECTORS = ("graph", "leanix")


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
    return "off"


def sync(session: Session, settings: Settings, cfg: OwnershipConfig, name: str, actor: str = "system",
         client: Any = None) -> ConnectorRun:
    if name == "graph":
        from kavlotryx.connectors.graph import sync_graph as fn
    elif name == "leanix":
        from kavlotryx.connectors.leanix import sync_leanix as fn
    else:
        raise ConnectorError(f"unknown connector {name!r}; known: {', '.join(CONNECTORS)}")
    return fn(session, settings, cfg, actor=actor, client=client)


def last_runs(session: Session) -> dict[str, ConnectorRun | None]:
    out: dict[str, ConnectorRun | None] = {}
    for name in CONNECTORS:
        out[name] = session.scalars(select(ConnectorRun).where(ConnectorRun.connector == name)
                                    .order_by(ConnectorRun.id.desc()).limit(1)).first()
    return out


__all__ = ["CONNECTORS", "ConnectorError", "connector_mode", "last_runs", "sync"]
