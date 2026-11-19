"""ServiceNow CMDB connector (FR-EN-08).

Live mode reads configuration items through the Table API
(``GET /api/now/table/<table>``), with basic auth or an OAuth access token.
The read is GET-only, asks for display values and raw values, and dot-walks the reference
fields it needs (``support_group.name``, ``owned_by.email``), so one request
per page returns everything. Snapshot mode reads the same records from a JSON
file: ``{"cis": [ ... ]}``.

A CI gives ownership (support group, managed-by group, owner) and business
context (criticality, environment, business service) to the assets it matches.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, ServiceNowConnectorConfig, Settings
from kavlotryx.connectors.base import ConnectorError, HttpClient, load_snapshot, record_run
from kavlotryx.db import CmdbCi, ConnectorRun, utcnow

HOST_RE = re.compile(r"^[a-z0-9-]+\.(service-now\.com|servicenowservices\.com)$")
NAME_RE = re.compile(r"^[a-z0-9-]+$")
PAGE = 1000
MAX_ROWS = 200_000
KEY_FIELDS = ("object_id", "correlation_id", "serial_number", "fqdn", "ip_address")


def instance_host(value: str) -> str:
    """'acme' or 'acme.service-now.com' (with or without https://) -> the host name."""
    host = (value or "").strip().lower().removeprefix("https://").strip("/")
    if NAME_RE.match(host):
        host = f"{host}.service-now.com"
    if not HOST_RE.match(host):
        raise ConnectorError("KAVLO_SERVICENOW_INSTANCE must be an instance name or <name>.service-now.com")
    return host


def fields_for(cfg: ServiceNowConnectorConfig) -> list[str]:
    out = ["sys_id", "name", "sys_class_name", *KEY_FIELDS, "support_group.name", "managed_by_group.name",
           "owned_by.email", "assigned_to.email", *cfg.criticality_fields, *cfg.environment_fields]
    if cfg.service_field:
        out.append(cfg.service_field)
    return list(dict.fromkeys(out))


class ServiceNowClient(HttpClient):
    def __init__(self, instance: str, user: str = "", password: str = "", token: str = "",
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] | None = None) -> None:
        self.host = instance_host(instance)
        if not token and not (user and password):
            raise ConnectorError("set KAVLO_SERVICENOW_TOKEN, or KAVLO_SERVICENOW_USER and KAVLO_SERVICENOW_PASSWORD")
        super().__init__(transport=transport, **({"sleep": sleep} if sleep else {}))
        self.auth = None if token else (user, password)
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def records(self, cfg: ServiceNowConnectorConfig) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        offset = 0
        while True:
            params = {"sysparm_query": cfg.query, "sysparm_fields": ",".join(fields_for(cfg)),
                      "sysparm_display_value": "all", "sysparm_exclude_reference_link": "true",
                      "sysparm_limit": str(PAGE), "sysparm_offset": str(offset)}
            resp = self.request("GET", f"https://{self.host}/api/now/table/{cfg.table}", params=params,
                                auth=self.auth, headers=self.headers)
            page = (resp.json() or {}).get("result")
            if not isinstance(page, list):
                raise ConnectorError("ServiceNow returned no result list")
            rows += [normalize(r, cfg, self.host) for r in page if isinstance(r, dict)]
            if len(page) < PAGE:
                return rows
            offset += PAGE
            if offset >= MAX_ROWS:
                raise ConnectorError(f"more than {MAX_ROWS} CIs; narrow connectors.servicenow.query")


def _val(v: Any, raw: bool = False) -> str:
    # display_value=all returns {"display_value", "value"}; a snapshot may hold plain strings
    if isinstance(v, dict):
        v = (v.get("value") if raw else v.get("display_value")) or v.get("value")
    return "" if v is None else str(v).strip()


def _first(r: dict[str, Any], names: list[str]) -> str:
    for n in names:
        if _val(r.get(n)):
            return _val(r.get(n))
    return ""


def normalize(r: dict[str, Any], cfg: ServiceNowConnectorConfig, host: str = "") -> dict[str, Any]:
    """One Table API record -> the snapshot shape."""
    sys_id = _val(r.get("sys_id"), raw=True)
    cls = _val(r.get("sys_class_name"), raw=True)  # the table name, not its label
    return {
        "sys_id": sys_id, "name": _val(r.get("name")), "class": cls,
        "keys": [_val(r.get(k)) for k in KEY_FIELDS if _val(r.get(k))],
        "support_group": _val(r.get("support_group.name")),
        "managed_by_group": _val(r.get("managed_by_group.name")),
        "owned_by": (_val(r.get("owned_by.email")) or _val(r.get("assigned_to.email"))).lower(),
        "business_service": _val(r.get(cfg.service_field)) if cfg.service_field else "",
        "criticality": _first(r, cfg.criticality_fields),
        "environment": _first(r, cfg.environment_fields),
        "url": f"https://{host}/{cls or 'cmdb_ci'}.do?sys_id={sys_id}" if host and sys_id else "",
    }


def sync_servicenow(session: Session, settings: Settings, cfg: OwnershipConfig, actor: str = "system",
                    client: ServiceNowClient | None = None) -> ConnectorRun:
    from kavlotryx.connectors import connector_mode

    scfg = cfg.connectors.servicenow
    mode = "live" if client is not None else connector_mode(settings, "servicenow")
    if mode == "off":
        raise ConnectorError("ServiceNow is not configured: set KAVLO_SERVICENOW_INSTANCE and credentials "
                             "(or KAVLO_SERVICENOW_SNAPSHOT)")

    def work() -> dict[str, Any]:
        if mode == "snapshot":
            cis = load_snapshot(settings.servicenow_snapshot, "cis")
        else:
            c = client or ServiceNowClient(settings.servicenow_instance, settings.servicenow_user,
                                           settings.servicenow_password, settings.servicenow_token)
            cis = c.records(scfg)
        now = utcnow()
        session.execute(delete(CmdbCi))
        kept = grouped = 0
        seen: set[str] = set()
        for c in cis:
            sys_id = str(c.get("sys_id") or "")
            if not sys_id or sys_id in seen:
                continue
            seen.add(sys_id)
            name = str(c.get("name") or "")
            keys = {k.strip().lower() for k in [sys_id, name, *[str(x) for x in c.get("keys") or []]] if k.strip()}
            row = CmdbCi(sys_id=sys_id, name=name[:256], class_name=str(c.get("class") or "")[:128],
                         keys=sorted(keys), support_group=str(c.get("support_group") or "")[:256],
                         managed_by_group=str(c.get("managed_by_group") or "")[:256],
                         owned_by=str(c.get("owned_by") or "").lower()[:320],
                         business_service=str(c.get("business_service") or "")[:256],
                         criticality=str(c.get("criticality") or "")[:64],
                         environment=str(c.get("environment") or "")[:64],
                         url=str(c.get("url") or "")[:512], synced_at=now)
            session.add(row)
            kept += 1
            grouped += int(bool(row.support_group or row.managed_by_group))
        return {"cis": kept, "with_group": grouped}

    return record_run(session, "servicenow", mode, actor, work)
