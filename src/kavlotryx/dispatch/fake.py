"""An in-memory tracker, optionally saved to a JSON file. For demos and tests."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from kavlotryx.dispatch.base import Ticket, TrackerError, check_label


class FakeTracker:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.issues: dict[str, dict[str, Any]] = {}
        self.counters: dict[str, int] = {}
        self.calls: list[str] = []
        if path and path.exists():
            data = json.loads(path.read_text())
            self.issues, self.counters = data.get("issues", {}), data.get("counters", {})

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"issues": self.issues, "counters": self.counters},
                                            indent=2, default=str))

    def _ticket(self, issue: dict[str, Any]) -> Ticket:
        return Ticket(key=issue["key"], url=f"fake://{issue['key']}", status=issue["status"])

    def find_by_label(self, label: str) -> Ticket | None:
        self.calls.append(f"search {label}")
        for issue in self.issues.values():
            if label in issue["labels"]:
                return self._ticket(issue)
        return None

    def create(self, project: str, summary: str, description: str, priority: str,
               labels: list[str], due: date | None) -> Ticket:
        for label in labels:
            check_label(label)
        n = self.counters.get(project, 0) + 1
        self.counters[project] = n
        key = f"{project}-{n}"
        self.issues[key] = {"key": key, "project": project, "summary": summary,
                            "description": description, "priority": priority, "labels": labels,
                            "due": due.isoformat() if due else None, "status": "new", "comments": []}
        self.calls.append(f"create {key}")
        self._save()
        return self._ticket(self.issues[key])

    def _get(self, key: str) -> dict[str, Any]:
        if key not in self.issues:
            raise TrackerError(f"issue {key} not found")
        return self.issues[key]

    def update(self, key: str, summary: str, description: str, priority: str) -> None:
        issue = self._get(key)
        issue.update(summary=summary, description=description, priority=priority)
        self.calls.append(f"update {key}")
        self._save()

    def comment(self, key: str, text: str) -> None:
        self._get(key)["comments"].append(text)
        self.calls.append(f"comment {key}")
        self._save()

    def status(self, key: str) -> str:
        return self.issues[key]["status"] if key in self.issues else "missing"

    def transition(self, key: str, category: str) -> None:
        self._get(key)["status"] = category
        self.calls.append(f"transition {key} {category}")
        self._save()
