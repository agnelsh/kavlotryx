"""Wiz exports and wizcli output (FR-IN-08).

One adapter reads four Wiz formats and detects which one it got:

* Issues CSV export          -> OCSF Detection Finding (2004), one per issue
* Vulnerability findings CSV -> OCSF Vulnerability Finding (2002)
* wizcli image / directory scan JSON -> 2002 per package vulnerability
* wizcli IaC scan JSON       -> OCSF Compliance Finding (2003) per rule match

Status rule: only RESOLVED rows are left out. IGNORED and REJECTED issues
are kept as present findings, because the weakness still exists; dropping
them would let a later export "prove" a fix that never happened. Kavlotryx
gets risk-acceptance exceptions in v0.3.

Secrets are counted as skipped: Kavlotryx has no secret finding kind yet.
"""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from kavlotryx import OCSF_VERSION
from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult
from kavlotryx.ocsf.extract import image_repository
from kavlotryx.ocsf.severity import SEVERITY_NAMES, severity_id_from_name

ABSENT_STATUSES = {"RESOLVED"}
ISSUE_COLUMNS = {"Issue ID", "Control ID", "Title", "Severity", "Status"}
VULN_COLUMNS = {"Name", "DetailedName", "Version", "FixedVersion", "AssetName"}

csv.field_size_limit(16 * 1024 * 1024)  # "Resource original JSON" cells can be large


def _base(now: int) -> dict[str, Any]:
    return {
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "time": now,
        "metadata": {"version": OCSF_VERSION, "product": {"name": "Wiz", "vendor_name": "Wiz"}},
    }


def _tags(raw: str) -> list[dict[str, str]]:
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    return [{"name": str(k), "value": "" if v is None else str(v)} for k, v in sorted(data.items())]


def _sev(name: Any) -> tuple[int, str]:
    sid = severity_id_from_name(str(name or ""))
    return sid, SEVERITY_NAMES.get(sid, "Unknown")


def _https(url: str) -> str:
    return url if url.startswith("https://") else ""


class WizAdapter(Adapter):
    name = "wiz"

    def parse(self, data: bytes) -> ParseResult:
        text = data.decode("utf-8-sig")
        stripped = text.lstrip()
        if not stripped:
            raise AdapterError("input is empty")
        if stripped[0] in "{[":
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise AdapterError(f"not valid JSON: {e}") from None
            if isinstance(doc, dict) and "result" in doc and "scanOriginResource" in doc:
                return self._wizcli(doc)
            raise AdapterError("JSON is not wizcli output (expected 'result' and 'scanOriginResource')")
        reader = csv.DictReader(io.StringIO(text))
        cols = set(reader.fieldnames or [])
        if cols >= ISSUE_COLUMNS:
            return self._issues(reader)
        if cols >= VULN_COLUMNS:
            return self._vulns(reader)
        raise AdapterError("CSV is not a Wiz Issues or Vulnerability Findings export "
                           f"(columns: {', '.join(sorted(cols)[:8])}…)")

    # -- Issues CSV -------------------------------------------------------------

    def _issues(self, reader: csv.DictReader) -> ParseResult:
        result = ParseResult(default_scope="wiz:issues")
        now = int(time.time())
        for n, row in enumerate(reader, start=2):
            status = (row.get("Status") or "").strip().upper()
            if status in ABSENT_STATUSES:
                continue
            uid = (row.get("Resource external ID") or row.get("Resource vertex ID") or "").strip()
            if not uid:
                result.skipped.append(f"line {n}: issue {row.get('Issue ID', '')} has no resource id")
                continue
            sid, sev = _sev(row.get("Severity"))
            platform = (row.get("Resource Platform") or "").strip()
            account = (row.get("Subscription ID") or "").strip()
            if not account and row.get("Kubernetes Cluster"):
                account = f"k8s:{row['Kubernetes Cluster'].strip()}"
            if not account and platform:
                # Tenant-level resources (Azure AD users, service principals) have no
                # subscription; group them per platform tenant, not per resource.
                account = f"{platform.lower()}-tenant"
            projects = [p.strip() for p in (row.get("Project Names") or "").split(",") if p.strip()]
            tags = _tags(row.get("Resource Tags", ""))
            if len(projects) == 1:
                tags.append({"name": "wiz-project", "value": projects[0]})
            control = (row.get("Control ID") or "").strip() or (row.get("Title") or "").strip()
            result.records.append({
                **_base(now),
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "type_uid": 200401,
                "severity_id": sid,
                "severity": sev,
                "status": status.title(),
                "metadata": {**_base(now)["metadata"], "event_code": control},
                "finding_info": {
                    "uid": row.get("Issue ID", ""),
                    "title": (row.get("Title") or "").strip(),
                    "desc": row.get("Description") or "",
                    "created_time_dt": row.get("Created At") or "",
                    "src_url": _https(row.get("Wiz URL") or ""),
                },
                "resources": [{
                    "uid": uid,
                    "name": (row.get("Resource Name") or "").strip(),
                    "type": (row.get("Resource Type") or "").strip(),
                    "region": (row.get("Resource Region") or "").strip(),
                    "tags": tags,
                }],
                "cloud": {
                    "provider": platform.lower(),
                    "account": {"uid": account, "name": (row.get("Subscription Name") or "").strip()},
                    "region": (row.get("Resource Region") or "").strip(),
                },
                "remediation": {"desc": row.get("Remediation Recommendation") or ""},
                "unmapped": {"wiz": {"status": status, "projects": projects,
                                     "issue_id": row.get("Issue ID", "")}},
            })
        return result

    # -- Vulnerability findings CSV -------------------------------------------------

    def _vulns(self, reader: csv.DictReader) -> ParseResult:
        result = ParseResult(default_scope="wiz:vulnerabilities")
        now = int(time.time())
        for n, row in enumerate(reader, start=2):
            status = (row.get("FindingStatus") or row.get("Status") or "").strip().upper()
            if status in ABSENT_STATUSES:
                continue
            vid, pkg = (row.get("Name") or "").strip(), (row.get("DetailedName") or "").strip()
            uid = (row.get("ProviderUniqueId") or row.get("AssetID") or "").strip()
            if not vid or not pkg or not uid:
                result.skipped.append(f"line {n}: missing vulnerability, package or asset id")
                continue
            sid, sev = _sev(row.get("VendorSeverity") or row.get("CVSSSeverity"))
            fixed = (row.get("FixedVersion") or "").strip()
            vuln: dict[str, Any] = {
                "title": f"{vid} in {pkg}", "severity": sev, "is_fix_available": bool(fixed),
                "references": [r for r in [_https(row.get("Link") or "")] if r],
                "affected_packages": [{"name": pkg, "version": (row.get("Version") or "").strip(),
                                       "fixed_in_version": fixed}],
            }
            vuln["cve" if vid.upper().startswith("CVE-") else "advisory"] = {"uid": vid}
            result.records.append({
                **_base(now),
                "class_uid": 2002, "class_name": "Vulnerability Finding", "type_uid": 200201,
                "severity_id": sid, "severity": sev,
                "finding_info": {"uid": row.get("ID", ""), "title": f"{vid} in {pkg}",
                                 "src_url": _https(row.get("WizURL") or "")},
                "vulnerabilities": [vuln],
                "resources": [{"uid": uid, "name": (row.get("AssetName") or "").strip(),
                               "region": (row.get("AssetRegion") or "").strip(),
                               "tags": _tags(row.get("Tags", ""))}],
                "cloud": {"provider": (row.get("CloudPlatform") or "").strip().lower(),
                          "account": {"uid": (row.get("SubscriptionExternalId") or "").strip(),
                                      "name": (row.get("SubscriptionName") or "").strip()},
                          "region": (row.get("AssetRegion") or "").strip()},
                "remediation": {"desc": row.get("Remediation") or (f"Upgrade {pkg} to {fixed}" if fixed else "")},
                "unmapped": {
                    "kavlotryx": {"path": (row.get("LocationPath") or "").lstrip("/"),
                                  "artifact": (row.get("AssetName") or "").strip()},
                    "wiz": {"status": status, "has_exploit": row.get("HasExploit", ""),
                            "cisa_kev": row.get("HasCisaKevExploit", "")},
                },
            })
        return result

    # -- wizcli JSON ------------------------------------------------------------

    def _wizcli(self, doc: dict[str, Any]) -> ParseResult:
        origin = doc.get("scanOriginResource") or {}
        kind = str(origin.get("__typename") or "")
        name = str(origin.get("name") or "").strip()
        res = doc.get("result") or {}
        now = int(time.time())

        if kind == "CICDScanOriginContainerImage":
            digest = str(origin.get("digest") or "").strip()
            asset_key = digest or f"image:{name}"
            resource = {"uid": asset_key, "name": name, "type": "Container Image", "tags": []}
            artifact = image_repository(name) if name else asset_key
            scope = f"wizcli:{artifact}" if name else ""
        elif kind == "CICDScanOriginDirectory":
            resource = {"uid": f"fs:{name or '.'}", "name": name, "type": "Filesystem", "tags": []}
            artifact = name
            scope = f"wizcli:{name}" if name.startswith("/") else ""
        else:  # IaC scans are named "IAC scan <timestamp>": not an identity
            resource = {"uid": "fs:.", "name": ".", "type": "Filesystem", "tags": []}
            artifact = ""
            scope = ""

        result = ParseResult(default_scope=scope)
        base = _base(now)
        ext = {"artifact": artifact}

        for group, has_path in (("osPackages", False), ("libraries", True)):
            for pkg in res.get(group) or []:
                pname, pver = str(pkg.get("name") or ""), str(pkg.get("version") or "")
                path = str(pkg.get("path") or "").lstrip("/") if has_path else ""
                for v in pkg.get("vulnerabilities") or []:
                    vid = str(v.get("name") or "")
                    if not vid or not pname:
                        result.skipped.append(f"{group}: vulnerability without id or package")
                        continue
                    sid, sev = _sev(v.get("severity"))
                    fixed = str(v.get("fixedVersion") or "")
                    vuln: dict[str, Any] = {
                        "title": f"{vid} in {pname}", "severity": sev, "is_fix_available": bool(fixed),
                        "references": [r for r in [_https(str(v.get("source") or ""))] if r],
                        "affected_packages": [{"name": pname, "version": pver, "fixed_in_version": fixed,
                                               "path": path}],
                    }
                    vuln["cve" if vid.upper().startswith("CVE-") else "advisory"] = {"uid": vid}
                    result.records.append({
                        **base, "class_uid": 2002, "class_name": "Vulnerability Finding", "type_uid": 200201,
                        "severity_id": sid, "severity": sev,
                        "finding_info": {"uid": f"wizcli:{vid}:{pname}:{resource['uid']}",
                                         "title": f"{vid} in {pname}"},
                        "vulnerabilities": [vuln], "resources": [resource],
                        "remediation": {"desc": f"Upgrade {pname} to {fixed}" if fixed else "No fixed version yet"},
                        "unmapped": {"kavlotryx": {**ext, "path": path},
                                     "wiz": {"has_exploit": v.get("hasExploit"),
                                             "cisa_kev": v.get("hasCisaKevExploit")}},
                    })

        for rm in res.get("ruleMatches") or []:
            rule = rm.get("rule") or {}
            sid, sev = _sev(rm.get("severity"))
            for m in rm.get("matches") or []:
                path = str(m.get("fileName") or "").lstrip("/")
                result.records.append({
                    **base, "class_uid": 2003, "class_name": "Compliance Finding", "type_uid": 200301,
                    "severity_id": sid, "severity": sev,
                    "finding_info": {"uid": f"wizcli:{rule.get('id')}:{path}:{m.get('lineNumber')}",
                                     "title": str(rule.get("name") or rule.get("id") or ""),
                                     "desc": str(m.get("found") or "")},
                    "compliance": {"control": str(rule.get("id") or rule.get("name") or ""), "status": "Fail",
                                   "status_id": 3, "standards": []},
                    "resources": [resource],
                    "remediation": {"desc": str(m.get("expected") or "")},
                    "unmapped": {"kavlotryx": {**ext, "path": path},
                                 "wiz": {"line": m.get("lineNumber"), "resource": m.get("resourceName")}},
                })

        secrets = len(res.get("secrets") or [])
        if secrets:
            result.skipped.append(f"{secrets} secret findings (secret findings are not supported yet)")
        return result
