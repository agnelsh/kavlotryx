"""Prowler ``json-ocsf`` output (FR-IN-01).

Prowler already writes OCSF Detection Finding (class 2004). This adapter keeps
FAIL rows, checks the fields Kavlotryx needs, and passes the record through.
"""

from __future__ import annotations

from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult, load_json_or_lines
from kavlotryx.adapters.ocsf import check_ocsf_rows


class ProwlerAdapter(Adapter):
    name = "prowler"

    def parse(self, data: bytes) -> ParseResult:
        rows = load_json_or_lines(data)
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise AdapterError("Prowler json-ocsf output must be a JSON array")
        staged = ParseResult()
        check_ocsf_rows(rows, staged)

        result = ParseResult(skipped=staged.skipped)
        accounts: set[str] = set()
        for rec in staged.records:
            status = str(rec.get("status_code") or "").upper()
            if status != "FAIL":
                continue  # PASS, MANUAL and MUTED rows are not work
            account = ((rec.get("cloud") or {}).get("account") or {}).get("uid")
            provider = (rec.get("cloud") or {}).get("provider") or "cloud"
            if account:
                accounts.add(f"{provider}:{account}")
            result.records.append(rec)
        if len(accounts) == 1:
            result.default_scope = f"prowler:{accounts.pop()}"
        elif accounts:
            result.default_scope = "prowler:" + ",".join(sorted(accounts))
        return result
