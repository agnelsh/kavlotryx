"""Pull findings from a DefectDojo instance through API v2 (FR-IN-09).

``kavlo pull defectdojo`` reads ``KAVLO_DEFECTDOJO_URL`` and
``KAVLO_DEFECTDOJO_TOKEN`` (an API v2 key, sent as ``Authorization: Token``)
from the environment only (NFR-SEC-02). It ingests one scan per product, with
the scope ``defectdojo:<product>``. A product with no open findings is still
ingested as an empty scan, so its earlier findings count as fixed.

The client only reads. It never changes anything in DefectDojo.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from kavlotryx.connectors.base import ConnectorError, HttpClient

PAGE = 500
MAX_PAGES = 400  # 200,000 findings per product


def check_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    parts = urlsplit(url)
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if not parts.hostname or parts.scheme not in ("https", "http") or (parts.scheme == "http" and not local):
        raise ConnectorError("KAVLO_DEFECTDOJO_URL must be an https:// URL (http only for localhost)")
    if parts.query or parts.fragment or parts.username:
        raise ConnectorError("KAVLO_DEFECTDOJO_URL must be a plain base URL")
    return url


class DefectDojoClient(HttpClient):
    def __init__(self, url: str, token: str, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] | None = None) -> None:
        if not token:
            raise ConnectorError("KAVLO_DEFECTDOJO_TOKEN is not set")
        self.base = check_url(url)
        super().__init__(transport=transport, **({"sleep": sleep} if sleep else {}))
        self.http.headers["Authorization"] = f"Token {token}"
        self.origin = urlsplit(self.base)[:2]

    def pages(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        url: str | None = f"{self.base}{path}"
        out: list[dict[str, Any]] = []
        first = True
        for _ in range(MAX_PAGES):
            if url is None:
                return out
            if urlsplit(url)[:2] != self.origin:
                raise ConnectorError("DefectDojo returned a 'next' link to another host")
            resp = self.request("GET", url, params=params if first else None)
            first = False
            body = resp.json()
            if not isinstance(body, dict) or not isinstance(body.get("results"), list):
                raise ConnectorError(f"GET {path}: not a paginated DefectDojo response")
            out.extend(r for r in body["results"] if isinstance(r, dict))
            url = body.get("next") or None
        raise ConnectorError(f"GET {path}: more than {MAX_PAGES} pages")

    def products(self) -> list[str]:
        return sorted({str(p.get("name")) for p in self.pages("/api/v2/products/", {"limit": PAGE})
                       if p.get("name")})

    def findings(self, product: str) -> bytes:
        rows = self.pages("/api/v2/findings/", {"limit": PAGE, "related_fields": "true",
                                                "duplicate": "false", "product_name": product})
        # product_name matches by name; keep only exact matches in case of a partial match
        rows = [r for r in rows
                if ((((r.get("related_fields") or {}).get("test") or {}).get("engagement") or {})
                    .get("product") or {}).get("name") in (product, None)]
        return json.dumps({"count": len(rows), "next": None, "results": rows}).encode()
