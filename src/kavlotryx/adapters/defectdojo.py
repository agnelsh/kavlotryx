"""DefectDojo findings export (API v2) as a scanner source (FR-IN-09).

Input: the body of ``GET /api/v2/findings/?related_fields=true`` (one page
``{"count", "next", "results": [...]}``), a list of such pages, or a plain
list of finding objects. ``kavlo pull defectdojo`` fetches every page for
you. Without ``related_fields`` the adapter still works, but it cannot tell
products apart, so pass ``--scope``.

Mapping:

* a finding with a vulnerability id (CVE, GHSA, ...) -> Vulnerability Finding 2002
* any other finding (SAST rule, DAST issue, misconfiguration) -> Detection Finding 2004,
  rule key ``defectdojo:<test type>/<tool rule id or CWE or title>``
* asset: ``defectdojo:<product>[/<service>]``, plus the file path for vulnerabilities;
  artifact (the grouping key): ``<product>[/<service>]``
* tags: the finding's DefectDojo tags (``key:value`` or ``key=value`` split), the product,
  the product type, and ``env`` from the test environment, so ownership rules and the
  production priority bump work on them

Status rule. DefectDojo sets ``active=false`` when a person marks a finding false
positive or risk accepted. Those rows still exist, so they stay present here;
dropping them would let the next export "prove" a fix that never happened. Their
DefectDojo decision travels in ``unmapped.defectdojo.triage`` and shows in the
console as a triage suggestion. It never triages a finding by itself.
Mitigated and other inactive rows are absent, so they count as fixed in that scope.
Duplicates and out-of-scope rows are skipped with a reason.

DefectDojo decides "mitigated" from its own reimports. For scanner-grade proof
of a fix, also send the scanner output to Kavlotryx directly.
"""

from __future__ import annotations

import re
import time
from typing import Any

from kavlotryx import OCSF_VERSION
from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult, load_json_or_lines
from kavlotryx.core.fingerprint import short_hash
from kavlotryx.ocsf.severity import SEVERITY_NAMES, severity_id_from_name

FIX_RE = re.compile(r"(?:upgrade|update|fixed)[^0-9\n]{0,40}?(?:version|to|in)[:\s]+v?([0-9][\w.\-+:~]*)", re.I)
VULN_ID_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA(-[\w]{4}){3}|[A-Z][A-Z0-9]+-[\w.:-]+)$")


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _get(d: Any, *keys: str) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _rows(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict):
        if isinstance(doc.get("results"), list):
            return [r for r in doc["results"] if isinstance(r, dict)]
        if "title" in doc and "severity" in doc:
            return [doc]
        raise AdapterError("JSON is not a DefectDojo findings response (expected a 'results' list)")
    if isinstance(doc, list):
        out: list[dict[str, Any]] = []
        for item in doc:
            if isinstance(item, dict) and isinstance(item.get("results"), list):
                out.extend(r for r in item["results"] if isinstance(r, dict))
            elif isinstance(item, dict):
                out.append(item)
        return out
    raise AdapterError("JSON is not a DefectDojo findings response")


def _vuln_ids(row: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for v in row.get("vulnerability_ids") or []:
        val = _s(v.get("vulnerability_id") if isinstance(v, dict) else v)
        if val and val not in ids:
            ids.append(val)
    for key in ("cve", "vuln_id_from_tool"):
        val = _s(row.get(key))
        if val and VULN_ID_RE.match(val) and val not in ids and (key == "cve" or not ids):
            ids.append(val)
    return ids


def _tags(row: dict[str, Any], product: str, prod_type: str, env: str) -> list[dict[str, str]]:
    tags: dict[str, str] = {}
    for t in row.get("tags") or []:
        t = _s(t)
        if not t:
            continue
        for sep in (":", "="):
            if sep in t:
                k, v = t.split(sep, 1)
                tags.setdefault(k.strip(), v.strip())
                break
        else:
            tags.setdefault(t, "")
    if product:
        tags.setdefault("defectdojo-product", product)
    if prod_type:
        tags.setdefault("defectdojo-product-type", prod_type)
    if env:
        tags.setdefault("env", env.lower())
    return [{"name": k, "value": v} for k, v in sorted(tags.items())]


def _fixed_version(row: dict[str, Any]) -> str:
    v = _s(row.get("fix_version"))
    if v:
        return v
    m = FIX_RE.search(_s(row.get("mitigation"))[:2000])
    return m.group(1).rstrip(".,;") if m else ""


def triage_hint(row: dict[str, Any]) -> str:
    if row.get("false_p"):
        return "false_positive"
    if row.get("risk_accepted"):
        return "risk_accepted"
    return ""


class DefectDojoAdapter(Adapter):
    name = "defectdojo"

    def parse(self, data: bytes) -> ParseResult:
        rows = _rows(load_json_or_lines(data))
        result = ParseResult()
        now = int(time.time())
        products: set[str] = set()
        for n, row in enumerate(rows, start=1):
            fid = _s(row.get("id")) or f"row {n}"
            test = _get(row, "related_fields", "test") or {}
            eng = test.get("engagement") or {} if isinstance(test, dict) else {}
            prod = eng.get("product") or {} if isinstance(eng, dict) else {}
            product = _s(prod.get("name")) if isinstance(prod, dict) else ""
            prod_type = _s(_get(prod, "prod_type", "name"))
            test_type = _s(_get(test, "test_type", "name")) or "DefectDojo"
            env = _s(_get(test, "environment", "name"))
            if product:
                products.add(product)

            hint = triage_hint(row)
            if row.get("duplicate"):
                result.skipped.append(f"finding {fid}: duplicate of DefectDojo finding "
                                      f"{_s(row.get('duplicate_finding')) or '?'}")
                continue
            if row.get("out_of_scope"):
                result.skipped.append(f"finding {fid}: out of scope in DefectDojo")
                continue
            if not hint and (row.get("is_mitigated") or row.get("active") is False):
                continue  # absent: a later export of this scope proves the fix

            title = _s(row.get("title"))
            if not title:
                result.skipped.append(f"finding {fid}: no title")
                continue
            sid = severity_id_from_name(_s(row.get("severity")))
            service = _s(row.get("service"))
            file_path = _s(row.get("file_path"))
            owner_part = product or "unknown-product"
            artifact = f"{owner_part}/{service}" if service else owner_part
            ids = _vuln_ids(row)
            is_vuln = bool(ids)
            asset_key = f"defectdojo:{artifact}" + (f":{file_path}" if is_vuln and file_path else "")
            repo = ""
            tags = _tags(row, product, prod_type, env)
            for t in tags:
                if t["name"].lower() in ("repo", "repository") and t["value"]:
                    repo = t["value"]
            dd = {"id": row.get("id"), "test_type": test_type, "product": product, "product_type": prod_type,
                  "engagement": _s(eng.get("name")) if isinstance(eng, dict) else "",
                  "test": _s(test.get("title")) if isinstance(test, dict) else "",
                  "triage": hint, "verified": bool(row.get("verified")),
                  "under_review": bool(row.get("under_review")), "hash_code": _s(row.get("hash_code")),
                  "unique_id_from_tool": _s(row.get("unique_id_from_tool"))}
            if isinstance(row.get("cwe"), int) and row["cwe"]:
                dd["cwe"] = row["cwe"]
            rec: dict[str, Any] = {
                "category_uid": 2, "category_name": "Findings", "activity_id": 1, "activity_name": "Create",
                "time": now, "severity_id": sid, "severity": SEVERITY_NAMES.get(sid, "Unknown"),
                "status": "Open" if not hint else "Suppressed",
                "metadata": {"version": OCSF_VERSION,
                             "product": {"name": "DefectDojo", "vendor_name": "DefectDojo",
                                         "feature": {"name": test_type}}},
                "finding_info": {"uid": f"defectdojo:{fid}", "title": title,
                                 "desc": _s(row.get("description"))[:8000]},
                "resources": [{"uid": asset_key, "name": artifact, "type": "DefectDojo Product",
                               "tags": tags}],
                "unmapped": {"kavlotryx": {"asset_key": asset_key, "artifact": artifact, "repo": repo,
                                           "path": file_path},
                             "defectdojo": dd},
            }
            mitigation = _s(row.get("mitigation"))
            if mitigation:
                rec["remediation"] = {"desc": mitigation[:4000]}
            if is_vuln:
                pkg = {"name": _s(row.get("component_name")), "version": _s(row.get("component_version"))}
                fix = _fixed_version(row)
                if fix:
                    pkg["fixed_in_version"] = fix
                vuln: dict[str, Any] = {"title": title, "affected_packages": [pkg] if pkg["name"] else []}
                if ids[0].upper().startswith("CVE-"):
                    vuln["cve"] = {"uid": ids[0]}
                else:
                    vuln["advisory"] = {"uid": ids[0]}
                if len(ids) > 1:
                    vuln["related_vulnerabilities"] = ids[1:]
                rec.update({"class_uid": 2002, "class_name": "Vulnerability Finding", "type_uid": 200201,
                            "vulnerabilities": [vuln]})
            else:
                code = (_s(row.get("vuln_id_from_tool")) or (f"CWE-{row['cwe']}" if row.get("cwe") else "")
                        or "t-" + short_hash(title, length=10))
                rec.update({"class_uid": 2004, "class_name": "Detection Finding", "type_uid": 200401})
                rec["metadata"]["event_code"] = f"{test_type}/{code}"
            result.records.append(rec)

        if len(products) == 1:
            result.default_scope = f"defectdojo:{next(iter(products))}"
        elif products:
            names = sorted(products)
            result.default_scope = ("defectdojo:" + "+".join(names) if len(names) <= 3
                                    else f"defectdojo:{len(names)}-products-{short_hash(*names, length=8)}")
        return result
