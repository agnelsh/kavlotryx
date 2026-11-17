"""Pull the facts Kavlotryx needs out of one OCSF finding record.

OCSF stays the stored model. This module reads the few fields that the
fingerprint, the ownership resolver and the grouping engine use. It never
fails on missing fields: every connector must work with missing data
(FR-EN-07). Unknown values become empty strings or empty dicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EXT_KEY = "kavlotryx"


@dataclass
class FindingFacts:
    kind: str  # "vuln" | "config"
    scanner: str
    class_uid: int
    asset_key: str
    asset_type: str = ""
    asset_name: str = ""
    artifact: str = ""  # image repository or source repository used for grouping
    vuln_id: str = ""
    package: str = ""
    src_package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    rule_key: str = ""
    title: str = ""
    description: str = ""
    remediation: str = ""
    severity_id: int = 0
    provider: str = ""
    account_uid: str = ""
    region: str = ""
    repo: str = ""  # e.g. github.com/acme/payments-api
    path: str = ""  # file path inside repo, for CODEOWNERS
    tags: dict[str, str] = field(default_factory=dict)


def _get(d: Any, *keys: str, default: Any = None) -> Any:
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _str(v: Any) -> str:
    return "" if v is None else str(v)


def parse_tags(resource: dict[str, Any]) -> dict[str, str]:
    """Collect tags from the places scanners put them.

    Supported shapes: OCSF 1.4+ ``tags`` (list of {name, value}), OCSF
    ``labels`` (list of "k:v" or "k=v" strings), and Prowler's
    ``data.metadata.tags`` (list of {Key, Value} or a plain dict).
    """
    tags: dict[str, str] = {}
    for item in resource.get("tags") or []:
        if isinstance(item, dict) and item.get("name"):
            tags[str(item["name"])] = _str(item.get("value"))
    for label in resource.get("labels") or []:
        if not isinstance(label, str):
            continue
        for sep in ("=", ":"):
            if sep in label:
                k, v = label.split(sep, 1)
                tags.setdefault(k.strip(), v.strip())
                break
    meta_tags = _get(resource, "data", "metadata", "tags")
    if isinstance(meta_tags, dict):
        for k, v in meta_tags.items():
            tags.setdefault(str(k), _str(v))
    elif isinstance(meta_tags, list):
        for item in meta_tags:
            if isinstance(item, dict):
                k = item.get("Key") or item.get("key") or item.get("name")
                if k:
                    tags.setdefault(str(k), _str(item.get("Value", item.get("value"))))
    return tags


def extract_facts(record: dict[str, Any]) -> FindingFacts:
    class_uid = int(record.get("class_uid") or 0)
    ext = _get(record, "unmapped", EXT_KEY, default={}) or {}
    scanner = _str(_get(record, "metadata", "product", "name")).strip().lower() or "unknown"
    resources = record.get("resources") or []
    res = resources[0] if resources and isinstance(resources[0], dict) else {}

    tags = parse_tags(res)
    asset_key = _str(ext.get("asset_key") or res.get("uid") or res.get("name"))
    finding_info = record.get("finding_info") or {}

    facts = FindingFacts(
        kind="vuln" if class_uid == 2002 else "config",
        scanner=scanner,
        class_uid=class_uid,
        asset_key=asset_key,
        asset_type=_str(res.get("type")),
        asset_name=_str(res.get("name")),
        artifact=_str(ext.get("artifact")),
        title=_str(finding_info.get("title") or record.get("message")),
        description=_str(finding_info.get("desc")),
        remediation=_str(_get(record, "remediation", "desc")),
        severity_id=int(record.get("severity_id") or 0),
        provider=_str(_get(record, "cloud", "provider") or res.get("cloud_partition")),
        account_uid=_str(_get(record, "cloud", "account", "uid") or ext.get("account_uid")),
        region=_str(_get(record, "cloud", "region") or res.get("region")),
        repo=_str(ext.get("repo") or tags.get("org.opencontainers.image.source")),
        path=_str(ext.get("path")),
        tags=tags,
    )

    if class_uid == 2002:
        vulns = record.get("vulnerabilities") or [{}]
        v = vulns[0] if isinstance(vulns[0], dict) else {}
        facts.vuln_id = _str(
            _get(v, "cve", "uid") or _get(v, "advisory", "uid") or v.get("uid")
            or finding_info.get("uid")
        )
        pkgs = v.get("affected_packages") or []
        pkg = pkgs[0] if pkgs and isinstance(pkgs[0], dict) else {}
        facts.package = _str(pkg.get("name"))
        facts.installed_version = _str(pkg.get("version"))
        facts.fixed_version = _str(pkg.get("fixed_in_version"))
        facts.src_package = _str(ext.get("src_package"))
        if not facts.title:
            facts.title = _str(v.get("title"))
    elif class_uid == 2003:
        control = _get(record, "compliance", "control") or finding_info.get("uid") or facts.title
        facts.rule_key = f"{scanner}:{_str(control)}"
    else:  # 2004 Detection Finding (Prowler) and anything else
        code = _get(record, "metadata", "event_code") or finding_info.get("uid") or facts.title
        facts.rule_key = f"{scanner}:{_str(code)}"

    if not facts.artifact:
        if facts.asset_type == "Container Image" and facts.asset_name:
            facts.artifact = image_repository(facts.asset_name)
        else:
            facts.artifact = facts.asset_name or facts.asset_key
    facts.repo = normalize_repo(facts.repo)
    return facts


def image_repository(name: str) -> str:
    """``ghcr.io/acme/api:1.2@sha256:..`` -> ``ghcr.io/acme/api``."""
    base = name.split("@", 1)[0]
    if ":" in base.rsplit("/", 1)[-1]:
        base = base.rsplit(":", 1)[0]
    return base


def normalize_repo(url: str) -> str:
    """Return ``host/org/repo`` for a repository URL, or an empty string."""
    if not url:
        return ""
    u = url.strip()
    for prefix in ("git+", "https://", "http://", "ssh://", "git@"):
        if u.startswith(prefix):
            u = u[len(prefix):]
    u = u.replace(":", "/", 1) if u.count(":") == 1 and "/" in u else u
    if u.endswith(".git"):
        u = u[:-4]
    return u.strip("/").lower()
