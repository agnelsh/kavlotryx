"""Generic OCSF input (FR-IN-03): any Vulnerability, Compliance or Detection Finding."""

from __future__ import annotations

from typing import Any

from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult, load_json_or_lines

ACCEPTED_CLASSES = {2002, 2003, 2004}


def check_ocsf_rows(rows: Any, result: ParseResult) -> None:
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise AdapterError("expected a JSON array of OCSF records")
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            result.skipped.append(f"row {i}: not an object")
            continue
        try:
            class_uid = int(row.get("class_uid") or 0)
        except (TypeError, ValueError):
            class_uid = 0
        if class_uid not in ACCEPTED_CLASSES:
            result.skipped.append(f"row {i}: class_uid {row.get('class_uid')!r} is not 2002/2003/2004")
            continue
        if not row.get("resources"):
            result.skipped.append(f"row {i}: no resources")
            continue
        result.records.append(row)


class OcsfAdapter(Adapter):
    name = "ocsf"

    def parse(self, data: bytes) -> ParseResult:
        result = ParseResult()
        check_ocsf_rows(load_json_or_lines(data), result)
        return result
