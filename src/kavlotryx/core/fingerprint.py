"""Stable fingerprints (FR-DD-01).

One fingerprint = one weakness on one asset, the same across scanners and
scan runs. A vulnerability is asset + id + package + version; a misconfiguration
is asset + file + rule.
"""

from __future__ import annotations

import hashlib

from kavlotryx.ocsf.extract import FindingFacts


def _norm(v: str) -> str:
    return (v or "").strip().lower()


def fingerprint(f: FindingFacts) -> str:
    if f.kind == "vuln":
        parts = ["vuln", f.asset_key, f.vuln_id, f.package, f.installed_version]
    else:
        # A misconfiguration is one rule on one asset. When the scanner names a
        # file (Dockerfile, Terraform module), the file is part of the asset.
        parts = ["config", f.asset_key, f.path, f.rule_key]
    digest = hashlib.sha256("\x1f".join(_norm(p) for p in parts).encode()).hexdigest()
    return f"sha256:{digest}"


def short_hash(*parts: str, length: int = 16) -> str:
    return hashlib.sha256("\x1f".join(_norm(p) for p in parts).encode()).hexdigest()[:length]
