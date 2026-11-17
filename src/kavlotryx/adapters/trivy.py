"""Trivy JSON output (``trivy ... --format json``), FR-IN-02.

Vulnerabilities become OCSF Vulnerability Finding (2002). Failed
misconfigurations become OCSF Compliance Finding (2003). Facts that OCSF has
no field for (artifact, repository, file path, source package) go under
``unmapped.kavlotryx``.
"""

from __future__ import annotations

import time
from typing import Any

from kavlotryx import OCSF_VERSION
from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult, load_json_or_lines
from kavlotryx.ocsf.extract import image_repository, normalize_repo
from kavlotryx.ocsf.severity import SEVERITY_NAMES, severity_id_from_name

SOURCE_LABEL = "org.opencontainers.image.source"


def _image_digest(meta: dict[str, Any]) -> str:
    for rd in meta.get("RepoDigests") or []:
        if "@" in rd:
            return rd.split("@", 1)[1]
    return ""


class TrivyAdapter(Adapter):
    name = "trivy"

    def parse(self, data: bytes) -> ParseResult:
        doc = load_json_or_lines(data)
        if not isinstance(doc, dict) or "Results" not in doc and "ArtifactName" not in doc:
            raise AdapterError("not Trivy JSON: expected an object with ArtifactName and Results")

        artifact_name = str(doc.get("ArtifactName") or "")
        artifact_type = str(doc.get("ArtifactType") or "")
        meta = doc.get("Metadata") or {}
        labels = ((meta.get("ImageConfig") or {}).get("config") or {}).get("Labels") or {}
        product_version = str(doc.get("Trivy", {}).get("Version", "") if isinstance(doc.get("Trivy"), dict) else "")
        now = int(time.time())

        if artifact_type == "container_image":
            artifact = image_repository(artifact_name)
            digest = _image_digest(meta)
            asset_key = digest or f"image:{artifact_name}"
            asset_type = "Container Image"
            repo = normalize_repo(str(labels.get(SOURCE_LABEL, "")))
        else:
            artifact = normalize_repo(artifact_name) or artifact_name
            asset_key = f"git:{artifact}" if artifact_type == "repository" else f"fs:{artifact_name}"
            asset_type = "Repository" if artifact_type == "repository" else "Filesystem"
            repo = artifact if artifact_type == "repository" else ""

        resource = {
            "uid": asset_key,
            "name": artifact_name,
            "type": asset_type,
            "tags": [{"name": k, "value": str(v)} for k, v in sorted(labels.items())],
        }
        base = {
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "time": now,
            "metadata": {
                "version": OCSF_VERSION,
                "product": {"name": "Trivy", "vendor_name": "Aqua Security", "version": product_version},
            },
        }

        result = ParseResult(default_scope=f"trivy:{artifact or artifact_name}")
        for res in doc.get("Results") or []:
            if not isinstance(res, dict):
                result.skipped.append("result entry is not an object")
                continue
            target = str(res.get("Target") or "")
            path = target if artifact_type != "container_image" or res.get("Class") != "os-pkgs" else ""
            ext_common = {
                "asset_key": asset_key,
                "artifact": artifact,
                "repo": repo,
                "path": path,
                "target": target,
            }
            for v in res.get("Vulnerabilities") or []:
                rec = self._vuln(v, base, resource, ext_common, target)
                if rec is None:
                    result.skipped.append(f"{target}: vulnerability without VulnerabilityID or PkgName")
                else:
                    result.records.append(rec)
            for m in res.get("Misconfigurations") or []:
                if str(m.get("Status", "FAIL")).upper() != "FAIL":
                    continue
                result.records.append(self._misconfig(m, base, resource, ext_common))
        return result

    def _vuln(self, v: dict[str, Any], base: dict, resource: dict, ext: dict, target: str):
        vid = v.get("VulnerabilityID")
        pkg = v.get("PkgName")
        if not vid or not pkg:
            return None
        sev = severity_id_from_name(v.get("Severity"))
        fixed = str(v.get("FixedVersion") or "")
        purl = ((v.get("PkgIdentifier") or {}).get("PURL")) or ""
        title = v.get("Title") or f"{vid} in {pkg}"
        vuln = {
            "title": title,
            "desc": v.get("Description") or "",
            "severity": SEVERITY_NAMES.get(sev, "Unknown"),
            "is_fix_available": bool(fixed),
            "references": [r for r in [v.get("PrimaryURL")] if r],
            "affected_packages": [
                {
                    "name": pkg,
                    "version": v.get("InstalledVersion") or "",
                    "fixed_in_version": fixed,
                    "purl": purl,
                    "path": target,
                }
            ],
        }
        if str(vid).upper().startswith("CVE-"):
            vuln["cve"] = {"uid": vid}
        else:
            vuln["advisory"] = {"uid": vid}
        return {
            **base,
            "class_uid": 2002,
            "class_name": "Vulnerability Finding",
            "type_uid": 200201,
            "severity_id": sev,
            "severity": SEVERITY_NAMES.get(sev, "Unknown"),
            "finding_info": {"uid": f"trivy:{vid}:{pkg}:{resource['uid']}", "title": f"{vid} in {pkg}", "desc": title},
            "vulnerabilities": [vuln],
            "resources": [resource],
            "remediation": {"desc": f"Upgrade {pkg} to {fixed}" if fixed else "No fixed version yet"},
            "unmapped": {"kavlotryx": {**ext, "src_package": v.get("SrcName") or pkg}},
        }

    def _misconfig(self, m: dict[str, Any], base: dict, resource: dict, ext: dict):
        sev = severity_id_from_name(m.get("Severity"))
        control = m.get("AVDID") or m.get("ID") or m.get("Title") or "unknown"
        return {
            **base,
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "type_uid": 200301,
            "severity_id": sev,
            "severity": SEVERITY_NAMES.get(sev, "Unknown"),
            "finding_info": {
                "uid": f"trivy:{control}:{resource['uid']}:{ext['target']}",
                "title": m.get("Title") or str(control),
                "desc": m.get("Message") or m.get("Description") or "",
            },
            "compliance": {"control": control, "status": "Fail", "status_id": 3, "standards": []},
            "resources": [resource],
            "remediation": {"desc": m.get("Resolution") or ""},
            "unmapped": {"kavlotryx": dict(ext)},
        }
