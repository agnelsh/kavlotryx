"""Jira Cloud tracker, REST API v3 (FR-DS-01..04).

Auth is email + API token (basic auth). Text goes in Atlassian Document
Format as plain text nodes, so scanner text never becomes Jira markup
(NFR-SEC-04).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import date
from typing import Any

import httpx

from kavlotryx.dispatch.base import Ticket, TrackerError, check_label

RETRY_STATUS = {429, 500, 502, 503, 504}


def adf(text: str) -> dict[str, Any]:
    content = []
    for line in text.splitlines():
        if line.strip():
            content.append({"type": "paragraph", "content": [{"type": "text", "text": line}]})
        else:
            content.append({"type": "paragraph", "content": []})
    return {"type": "doc", "version": 1, "content": content or [{"type": "paragraph", "content": []}]}


class JiraCloudTracker:
    def __init__(
        self,
        base_url: str,
        email: str,
        token: str,
        issue_type: str = "Task",
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 5,
    ) -> None:
        if not base_url.startswith("https://") and transport is None:
            raise TrackerError("KAVLO_JIRA_URL must use https")
        self.base = base_url.rstrip("/")
        self.issue_type = issue_type
        self.sleep = sleep
        self.max_attempts = max_attempts
        self.client = httpx.Client(base_url=self.base, auth=(email, token), timeout=30.0,
                                   transport=transport,
                                   headers={"Accept": "application/json",
                                            "User-Agent": "kavlotryx/0.1"})

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        for attempt in range(1, self.max_attempts + 1):
            try:
                resp = self.client.request(method, path, **kw)
            except httpx.TransportError as e:
                if attempt == self.max_attempts:
                    raise TrackerError(f"Jira {method} {path}: {e}") from e
                self.sleep(min(2 ** attempt, 30))
                continue
            if resp.status_code in RETRY_STATUS and attempt < self.max_attempts:
                retry_after = resp.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.isdigit() else float(min(2 ** attempt, 30))
                self.sleep(delay)
                continue
            return resp
        raise TrackerError(f"Jira {method} {path}: retries exhausted")  # pragma: no cover

    @staticmethod
    def _check(resp: httpx.Response, what: str) -> dict[str, Any]:
        if resp.status_code >= 400:
            raise TrackerError(f"Jira {what} failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json() if resp.content else {}

    def _url(self, key: str) -> str:
        return f"{self.base}/browse/{key}"

    def find_by_label(self, label: str) -> Ticket | None:
        check_label(label)
        body = {"jql": f'labels = "{label}" ORDER BY created ASC', "fields": ["status"],
                "maxResults": 1}
        data = self._check(self._request("POST", "/rest/api/3/search/jql", json=body), "search")
        issues = data.get("issues") or []
        if not issues:
            return None
        issue = issues[0]
        cat = (((issue.get("fields") or {}).get("status") or {}).get("statusCategory") or {}).get("key", "new")
        return Ticket(key=issue["key"], url=self._url(issue["key"]), status=cat)

    def create(self, project: str, summary: str, description: str, priority: str,
               labels: list[str], due: date | None) -> Ticket:
        for label in labels:
            check_label(label)
        fields: dict[str, Any] = {
            "project": {"key": project},
            "issuetype": {"name": self.issue_type},
            "summary": summary[:250],
            "description": adf(description),
            "labels": labels,
        }
        if priority:
            fields["priority"] = {"name": priority}
        if due:
            fields["duedate"] = due.isoformat()
        resp = self._request("POST", "/rest/api/3/issue", json={"fields": fields})
        if resp.status_code == 400 and "priority" in resp.text and "priority" in fields:
            # The project's priority scheme lacks this name: create without it.
            fields.pop("priority")
            resp = self._request("POST", "/rest/api/3/issue", json={"fields": fields})
        data = self._check(resp, "create issue")
        return Ticket(key=data["key"], url=self._url(data["key"]), status="new")

    def update(self, key: str, summary: str, description: str, priority: str) -> None:
        fields: dict[str, Any] = {"summary": summary[:250], "description": adf(description)}
        resp = self._request("PUT", f"/rest/api/3/issue/{key}", json={"fields": fields})
        self._check(resp, f"update {key}")

    def comment(self, key: str, text: str) -> None:
        resp = self._request("POST", f"/rest/api/3/issue/{key}/comment", json={"body": adf(text)})
        self._check(resp, f"comment {key}")

    def status(self, key: str) -> str:
        resp = self._request("GET", f"/rest/api/3/issue/{key}", params={"fields": "status"})
        if resp.status_code == 404:
            return "missing"
        data = self._check(resp, f"get {key}")
        return data["fields"]["status"]["statusCategory"]["key"]

    def transition(self, key: str, category: str) -> None:
        data = self._check(self._request("GET", f"/rest/api/3/issue/{key}/transitions"),
                           f"transitions {key}")
        for t in data.get("transitions") or []:
            if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == category:
                resp = self._request("POST", f"/rest/api/3/issue/{key}/transitions",
                                     json={"transition": {"id": t["id"]}})
                self._check(resp, f"transition {key}")
                return
        raise TrackerError(f"{key}: no transition to a '{category}' status")
