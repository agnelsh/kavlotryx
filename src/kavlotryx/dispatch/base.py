"""Tracker interface. Status categories follow Jira: new, indeterminate, done."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Protocol

LABEL_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")


class TrackerError(RuntimeError):
    pass


@dataclass
class Ticket:
    key: str
    url: str
    status: str  # "new" | "indeterminate" | "done"


class TicketTracker(Protocol):
    def find_by_label(self, label: str) -> Ticket | None: ...

    def create(self, project: str, summary: str, description: str, priority: str,
               labels: list[str], due: date | None) -> Ticket: ...

    def update(self, key: str, summary: str, description: str, priority: str) -> None: ...

    def comment(self, key: str, text: str) -> None: ...

    def status(self, key: str) -> str: ...  # also "missing"

    def transition(self, key: str, category: str) -> None: ...


def check_label(label: str) -> str:
    if not LABEL_RE.match(label):
        raise TrackerError(f"invalid label {label!r}")
    return label
