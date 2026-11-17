"""LeanIX connector (SAP LeanIX Enterprise Architecture).

Live mode exchanges an API token for an access token
(``/services/mtm/v1/oauth2/token``) and reads Application fact sheets through
the GraphQL API (``/services/pathfinder/v1/graphql``): name, alias, external
id, tags, the owning team relation and subscriptions (responsible users).
The team relation differs between workspaces, so its name is configurable.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, Settings
from kavlotryx.connectors.base import ConnectorError, HttpClient, load_snapshot, record_run
from kavlotryx.db import CatalogApp, ConnectorRun, utcnow
from kavlotryx.ocsf.extract import normalize_repo

HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.leanix\.net$")
RELATION_RE = re.compile(r"^rel[A-Za-z]{3,80}$")

QUERY = """
query Apps($after: String) {
  allFactSheets(factSheetType: Application, first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node {
      id displayName
      ... on Application {
        alias
        externalId { externalId }
        tags { name }
        subscriptions { edges { node { user { email } roles { name } } } }
        %(relation)s { edges { node { factSheet { id displayName } } } }
      }
    } }
  }
}
"""


class LeanixClient(HttpClient):
    def __init__(self, host: str, api_token: str, team_relation: str = "relApplicationToOrganization",
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] | None = None) -> None:
        host = (host or "").lower().removeprefix("https://").strip("/")
        if not HOST_RE.match(host):
            raise ConnectorError("KAVLO_LEANIX_HOST must look like <subdomain>.leanix.net")
        if not RELATION_RE.match(team_relation):
            raise ConnectorError("connectors.leanix.team_relation must be a relation name such as "
                                 "relApplicationToOrganization")
        super().__init__(transport=transport, **({"sleep": sleep} if sleep else {}))
        self.host, self.api_token, self.relation = host, api_token, team_relation
        self._token = ""

    def token(self) -> str:
        if not self._token:
            resp = self.request("POST", f"https://{self.host}/services/mtm/v1/oauth2/token",
                                auth=("apitoken", self.api_token), data={"grant_type": "client_credentials"})
            self._token = resp.json().get("access_token", "")
            if not self._token:
                raise ConnectorError("LeanIX returned no access token")
        return self._token

    def applications(self, responsible_roles: list[str]) -> list[dict[str, Any]]:
        apps: list[dict[str, Any]] = []
        after: str | None = None
        query = QUERY % {"relation": self.relation}
        while True:
            resp = self.request("POST", f"https://{self.host}/services/pathfinder/v1/graphql",
                                headers={"Authorization": f"Bearer {self.token()}"},
                                json={"query": query, "variables": {"after": after}})
            body = resp.json()
            if body.get("errors"):
                raise ConnectorError(f"LeanIX GraphQL error: {str(body['errors'])[:300]}")
            page = (body.get("data") or {}).get("allFactSheets") or {}
            for edge in page.get("edges") or []:
                apps.append(_normalize(edge.get("node") or {}, self.relation, responsible_roles, self.host))
            info = page.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                return apps
            after = info.get("endCursor")


def _normalize(node: dict[str, Any], relation: str, roles: list[str], host: str) -> dict[str, Any]:
    ext = (node.get("externalId") or {}).get("externalId") or ""
    teams = [((e.get("node") or {}).get("factSheet") or {}).get("displayName", "")
             for e in ((node.get(relation) or {}).get("edges") or [])]
    wanted = {r.lower() for r in roles}
    responsible = []
    for e in ((node.get("subscriptions") or {}).get("edges") or []):
        n = e.get("node") or {}
        if {(r.get("name") or "").lower() for r in n.get("roles") or []} & wanted:
            email = ((n.get("user") or {}).get("email") or "").lower()
            if email:
                responsible.append(email)
    alias = node.get("alias") or ""
    return {
        "id": node.get("id", ""), "name": node.get("displayName", ""),
        "aliases": [a.strip() for a in alias.split(",") if a.strip()] + [t["name"] for t in node.get("tags") or []
                                                                     if t.get("name")],
        "external_ids": [ext] if ext else [],
        "repos": [normalize_repo(ext)] if ("github" in ext or "gitlab" in ext) else [],
        "teams": [t for t in teams if t], "responsible": responsible,
        "url": f"https://{host}/factsheet/Application/{node.get('id', '')}" if node.get("id") else "",
    }


def sync_leanix(session: Session, settings: Settings, cfg: OwnershipConfig, actor: str = "system",
                client: LeanixClient | None = None) -> ConnectorRun:
    from kavlotryx.connectors import connector_mode

    lcfg = cfg.connectors.leanix
    mode = "live" if client is not None else connector_mode(settings, "leanix")
    if mode == "off":
        raise ConnectorError("LeanIX is not configured: set KAVLO_LEANIX_HOST and KAVLO_LEANIX_TOKEN "
                             "(or KAVLO_LEANIX_SNAPSHOT)")

    def work() -> dict[str, Any]:
        if mode == "snapshot":
            apps = load_snapshot(settings.leanix_snapshot, "applications")
        else:
            c = client or LeanixClient(settings.leanix_host, settings.leanix_token, lcfg.team_relation)
            apps = c.applications(lcfg.responsible_roles)
        now = utcnow()
        session.execute(delete(CatalogApp))
        kept = 0
        for a in apps:
            if not a.get("id") or not a.get("name"):
                continue
            kept += 1
            session.add(CatalogApp(
                id=str(a["id"]), name=str(a["name"]), aliases=[str(x) for x in a.get("aliases") or []],
                external_ids=[str(x) for x in a.get("external_ids") or []],
                repos=[normalize_repo(str(x)) for x in a.get("repos") or []],
                teams=[str(x) for x in a.get("teams") or []],
                responsible=[str(x).lower() for x in a.get("responsible") or []],
                url=str(a.get("url") or ""), synced_at=now))
        return {"applications": kept, "with_team": sum(1 for a in apps if a.get("teams"))}

    return record_run(session, "leanix", mode, actor, work)
