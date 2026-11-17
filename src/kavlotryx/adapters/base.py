"""Adapter interface."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar


class AdapterError(ValueError):
    """The input is not valid for this adapter (FR-IN-05)."""


@dataclass
class ParseResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # one reason per skipped row
    default_scope: str = ""


class Adapter:
    name: ClassVar[str] = ""

    def parse(self, data: bytes) -> ParseResult:  # pragma: no cover - interface
        raise NotImplementedError


def load_json_or_lines(data: bytes) -> Any:
    """Load a JSON document, or JSON Lines when the document form fails."""
    text = data.decode("utf-8-sig", errors="strict")
    stripped = text.strip()
    if not stripped:
        raise AdapterError("input is empty")
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as first_error:
        rows = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                raise AdapterError(f"input is not JSON or JSON Lines: {first_error}") from None
            if not isinstance(row, dict):
                raise AdapterError("JSON Lines rows must be objects") from None
            rows.append(row)
        return rows
