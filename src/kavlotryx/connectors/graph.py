"""Microsoft Graph connector.

Live mode uses the OAuth 2.0 client-credentials flow (application permission
GroupMember.Read.All). It reads only the groups named in
``connectors.graph.group_map`` and their transitive user members, so the
cache holds just the people who can resolve to an owner.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, Settings
from kavlotryx.connectors.base import ConnectorError, HttpClient, load_snapshot, record_run
from kavlotryx.db import ConnectorRun, DirectoryPerson, utcnow

GRAPH = "https://graph.microsoft.com/v1.0"
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
USER_FIELDS = "id,displayName,mail,userPrincipalName,mailNickname,department"


class GraphClient(HttpClient):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] | None = None) -> None:
        if not TENANT_RE.match(tenant_id or ""):
            raise ConnectorError("KAVLO_GRAPH_TENANT_ID must be a tenant GUID or domain")
        super().__init__(transport=transport, **({"sleep": sleep} if sleep else {}))
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self._token = ""

    def token(self) -> str:
        if not self._token:
            resp = self.request("POST", f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                                data={"client_id": self.client_id, "client_secret": self.client_secret,
                                      "scope": "https://graph.microsoft.com/.default",
                                      "grant_type": "client_credentials"})
            self._token = resp.json().get("access_token", "")
            if not self._token:
                raise ConnectorError("Microsoft identity platform returned no access token")
        return self._token

    def get_all(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        while url:
            if not url.startswith(GRAPH + "/"):
                raise ConnectorError("refusing to follow a nextLink outside graph.microsoft.com")
            data = self.request("GET", url, headers={"Authorization": f"Bearer {self.token()}",
                                                     "ConsistencyLevel": "eventual"}).json()
            items.extend(data.get("value") or [])
            url = data.get("@odata.nextLink") or ""
        return items

    def find_group(self, key: str) -> dict[str, Any] | None:
        if GUID_RE.match(key):
            got = self.get_all(f"{GRAPH}/groups?$filter=id eq '{key}'&$select=id,displayName")
        else:
            name = key.replace("'", "''")
            got = self.get_all(f"{GRAPH}/groups?$filter={quote(f'displayName eq {chr(39)}{name}{chr(39)}')}"
                               "&$select=id,displayName")
        return got[0] if got else None

    def members(self, group_id: str) -> list[dict[str, Any]]:
        return self.get_all(f"{GRAPH}/groups/{group_id}/transitiveMembers/microsoft.graph.user"
                            f"?$select={USER_FIELDS}&$top=999")


def _fetch_live(client: GraphClient, cfg: OwnershipConfig) -> tuple[list[dict[str, Any]], int, list[str]]:
    people: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    found = 0
    for key in cfg.connectors.graph.group_map:
        group = client.find_group(key)
        if group is None:
            missing.append(key)
            continue
        found += 1
        labels = {group.get("displayName") or "", group["id"], key}
        for u in client.members(group["id"]):
            p = people.setdefault(u["id"], {**u, "groups": set()})
            p["groups"].update(x for x in labels if x)
    out = [{**p, "groups": sorted(p["groups"])} for p in people.values()]
    return out, found, missing


def sync_graph(session: Session, settings: Settings, cfg: OwnershipConfig, actor: str = "system",
               client: GraphClient | None = None) -> ConnectorRun:
    from kavlotryx.connectors import connector_mode

    mode = "live" if client is not None else connector_mode(settings, "graph")
    if mode == "off":
        raise ConnectorError("Microsoft Graph is not configured: set KAVLO_GRAPH_TENANT_ID, "
                             "KAVLO_GRAPH_CLIENT_ID and KAVLO_GRAPH_CLIENT_SECRET (or KAVLO_GRAPH_SNAPSHOT)")

    def work() -> dict[str, Any]:
        if mode == "snapshot":
            rows, groups, missing = load_snapshot(settings.graph_snapshot, "people"), None, []
        else:
            c = client or GraphClient(settings.graph_tenant_id, settings.graph_client_id,
                                      settings.graph_client_secret)
            rows, groups, missing = _fetch_live(c, cfg)
        now = utcnow()
        session.execute(delete(DirectoryPerson))
        for r in rows:
            pid = str(r.get("id") or r.get("userPrincipalName") or "")
            if not pid:
                continue
            session.add(DirectoryPerson(
                id=pid, upn=str(r.get("userPrincipalName") or "").lower(), mail=str(r.get("mail") or "").lower(),
                nickname=str(r.get("mailNickname") or "").lower(), display_name=str(r.get("displayName") or ""),
                department=str(r.get("department") or ""), groups=[str(g) for g in r.get("groups") or []],
                synced_at=now))
        counts: dict[str, Any] = {"people": len(rows)}
        if groups is not None:
            counts["groups"] = groups
        if missing:
            counts["groups_not_found"] = missing
        return counts

    return record_run(session, "graph", mode, actor, work)
