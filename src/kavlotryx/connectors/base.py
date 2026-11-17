"""Shared HTTP and run-recording helpers for connectors."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from kavlotryx.db import ConnectorRun, audit, utcnow

RETRY_STATUS = {429, 500, 502, 503, 504}


class ConnectorError(RuntimeError):
    pass


class HttpClient:
    def __init__(self, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep, max_attempts: int = 5) -> None:
        self.http = httpx.Client(timeout=30.0, transport=transport,
                                 headers={"User-Agent": "kavlotryx/0.1", "Accept": "application/json"})
        self.sleep = sleep
        self.max_attempts = max_attempts

    def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        for attempt in range(1, self.max_attempts + 1):
            try:
                resp = self.http.request(method, url, **kw)
            except httpx.TransportError as e:
                if attempt == self.max_attempts:
                    raise ConnectorError(f"{method} {url}: {e}") from e
                self.sleep(min(2 ** attempt, 30))
                continue
            if resp.status_code in RETRY_STATUS and attempt < self.max_attempts:
                ra = resp.headers.get("Retry-After", "")
                self.sleep(float(ra) if ra.isdigit() else float(min(2 ** attempt, 30)))
                continue
            if resp.status_code >= 400:
                raise ConnectorError(f"{method} {url.split('?')[0]}: HTTP {resp.status_code} {resp.text[:200]}")
            return resp
        raise ConnectorError(f"{method} {url}: retries exhausted")  # pragma: no cover


def load_snapshot(path: str, key: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConnectorError(f"cannot read snapshot {path}: {e}") from e
    items = data.get(key) if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ConnectorError(f"snapshot {path} must be an object with a '{key}' list")
    return [i for i in items if isinstance(i, dict)]


def record_run(session: Session, name: str, mode: str, actor: str, work: Callable[[], dict[str, Any]]) -> ConnectorRun:
    """Run a sync, store its outcome, and audit it. Errors are recorded, then raised."""
    run = ConnectorRun(connector=name, mode=mode, status="running", actor=actor, started_at=utcnow())
    try:
        counts = work()
    except Exception as e:
        session.rollback()
        run.status, run.error, run.finished_at = "error", str(e)[:2000], utcnow()
        session.add(run)
        audit(session, actor, f"connector.{name}.error", name, mode=mode, error=str(e)[:300])
        session.commit()
        raise
    run.status, run.counts, run.finished_at = "ok", counts, utcnow()
    session.add(run)
    audit(session, actor, f"connector.{name}.sync", name, mode=mode, **counts)
    session.commit()
    return run
