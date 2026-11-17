"""Ownership resolver (FR-OW-01..05). The primary differentiator.

Rules run in a fixed order; the first match wins. Every result keeps the
rule, the source, the evidence and a confidence value. A result below the
confidence limit is marked ``needs_review``. The resolver also returns a
trace of every rule it tried, so ``kavlo owner explain`` can show why.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from kavlotryx.config import OwnershipConfig, PolicyConfig
from kavlotryx.core import codeowners
from kavlotryx.db import Finding, OwnerOverride

CONF_OVERRIDE = 1.0
CONF_TAG = 0.9
CONF_CODEOWNERS = 0.85
CONF_PATTERN = 0.75
CONF_DEFAULT = 0.5
CONF_FALLBACK = 0.0


@dataclass
class RuleTrace:
    rule: str
    matched: bool
    reason: str


@dataclass
class Assignment:
    owner: str
    rule: str
    source: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    needs_review: bool = False
    trace: list[RuleTrace] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "rule": self.rule,
            "source": self.source,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "needs_review": self.needs_review,
            "trace": [t.__dict__ for t in self.trace],
        }


class OwnershipResolver:
    def __init__(
        self,
        cfg: OwnershipConfig,
        policy: PolicyConfig,
        config_dir: Path,
        overrides: list[OwnerOverride] | None = None,
    ) -> None:
        self.cfg = cfg
        self.policy = policy
        self.known = {o.slug for o in cfg.owners} | {cfg.fallback_owner}
        self.alias: dict[str, str] = {}
        for o in cfg.owners:
            self.alias[o.slug] = o.slug
            for a in o.aliases:
                self.alias[a.strip().lower()] = o.slug
        self.overrides = {(o.match_type, o.match_value): o for o in overrides or []}
        self.codeowners: dict[str, tuple[Path, list[codeowners.CodeownersLine], dict[str, str]]] = {}
        for src in cfg.codeowners:
            path = (config_dir / src.file).resolve()
            try:
                lines = codeowners.load_file(path)
            except OSError:
                lines = []  # FR-EN-07: a missing file is missing data, not an error
            self.codeowners[src.repo.lower()] = (path, lines, src.team_map)

    # -- helpers --------------------------------------------------------------

    def _owner_from_value(self, value: str) -> str | None:
        v = value.strip().lower()
        if v in self.alias:
            return self.alias[v]
        return None

    def _owner_from_handle(self, handle: str, team_map: dict[str, str]) -> str | None:
        if handle in team_map:
            return team_map[handle] if team_map[handle] in self.known else None
        # "@acme/payments" -> "payments" when that is a known owner.
        name = handle.lstrip("@").split("/")[-1]
        return self._owner_from_value(name)

    def _repo_for(self, f: Finding) -> tuple[str, str]:
        if f.repo:
            return f.repo, "finding"
        for m in self.cfg.image_repos:
            if f.artifact and fnmatchcase(f.artifact, m.image):
                return m.repo.lower(), f"image_repos:{m.image}"
        return "", ""

    # -- main -----------------------------------------------------------------

    def resolve(self, f: Finding) -> Assignment:
        trace: list[RuleTrace] = []
        a = (
            self._override(f, trace)
            or self._tags(f, trace)
            or self._codeowners(f, trace)
            or self._patterns(f, trace)
            or self._defaults(f, trace)
        )
        if a is None:
            trace.append(RuleTrace("fallback", True, f"no rule matched; using {self.cfg.fallback_owner}"))
            a = Assignment(self.cfg.fallback_owner, "fallback", "none", CONF_FALLBACK)
        a.trace = trace
        a.needs_review = a.confidence < self.policy.confidence_limit
        return a

    def _override(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        for mtype, value in (("finding", f.fingerprint), ("asset", f.asset_key)):
            o = self.overrides.get((mtype, value))
            if o is not None:
                trace.append(RuleTrace(f"override:{mtype}", True, f"set by {o.actor}"))
                return Assignment(o.owner_slug, f"override:{mtype}", "manual", CONF_OVERRIDE,
                                  {"actor": o.actor, "reason": o.reason,
                                   "created_at": o.created_at.isoformat() if o.created_at else ""})
        trace.append(RuleTrace("override", False, "no manual override for this finding or asset"))
        return None

    def _tags(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        lower = {k.lower(): (k, v) for k, v in (f.tags or {}).items()}
        if not lower:
            trace.append(RuleTrace("tag", False, "asset has no tags"))
            return None
        for key in self.cfg.tag_keys:
            hit = lower.get(key.lower())
            if hit is None:
                continue
            tag_key, value = hit
            owner = self._owner_from_value(value)
            if owner:
                trace.append(RuleTrace(f"tag:{key}", True, f"tag {tag_key}={value}"))
                return Assignment(owner, f"tag:{key}", "cloud_tag", CONF_TAG,
                                  {"asset": f.asset_key, "tag_key": tag_key, "tag_value": value})
            trace.append(RuleTrace(f"tag:{key}", False, f"tag {tag_key}={value} is not a known owner"))
        if not any(t.rule.startswith("tag:") for t in trace):
            trace.append(RuleTrace("tag", False, f"none of the tag keys {self.cfg.tag_keys} present"))
        return None

    def _codeowners(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        repo, how = self._repo_for(f)
        if not repo:
            trace.append(RuleTrace("codeowners", False, "no repository known for this asset"))
            return None
        entry = self.codeowners.get(repo)
        if entry is None or not entry[1]:
            trace.append(RuleTrace("codeowners", False, f"no CODEOWNERS loaded for {repo}"))
            return None
        file_path, lines, team_map = entry
        path = f.path or (self.cfg.image_default_path if f.asset_type == "Container Image" else "")
        if not path:
            trace.append(RuleTrace("codeowners", False, "finding has no file path"))
            return None
        m = codeowners.match(lines, path)
        if m is None:
            trace.append(RuleTrace("codeowners", False, f"no CODEOWNERS line matches {path}"))
            return None
        for handle in m.line.owners:
            owner = self._owner_from_handle(handle, team_map)
            if owner:
                trace.append(RuleTrace("codeowners", True,
                                       f"{repo} CODEOWNERS line {m.line.lineno}: {m.line.pattern} {handle}"))
                return Assignment(owner, "codeowners", "github_codeowners", CONF_CODEOWNERS, {
                    "repo": repo, "repo_from": how, "path": path, "file": str(file_path.name),
                    "line": m.line.lineno, "pattern": m.line.pattern, "handle": handle,
                })
        trace.append(RuleTrace("codeowners", False,
                               f"line {m.line.lineno} owners {list(m.line.owners)} map to no known owner"))
        return None

    def _patterns(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        for p in self.cfg.patterns:
            checks = []
            if p.asset:
                checks.append(fnmatchcase(f.asset_key, p.asset))
            if p.name:
                checks.append(fnmatchcase(f.asset_name, p.name) or fnmatchcase(f.artifact, p.name))
            if p.rule:
                checks.append(fnmatchcase(f.rule_key, p.rule))
            if checks and all(checks) and p.owner in self.known:
                trace.append(RuleTrace(f"pattern:{p.id}", True, "pattern matched"))
                return Assignment(p.owner, f"pattern:{p.id}", "config", CONF_PATTERN,
                                  {"pattern": p.id, "asset": p.asset, "name": p.name, "rule": p.rule})
        trace.append(RuleTrace("pattern", False, f"{len(self.cfg.patterns)} pattern rules, none matched"))
        return None

    def _defaults(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        if f.account_uid and f.account_uid in self.cfg.account_defaults:
            owner = self.cfg.account_defaults[f.account_uid]
            trace.append(RuleTrace("default:account", True, f"default owner of account {f.account_uid}"))
            return Assignment(owner, "default:account", "config", CONF_DEFAULT,
                              {"account": f.account_uid})
        for glob, owner in self.cfg.registry_defaults.items():
            if f.artifact and fnmatchcase(f.artifact, glob):
                trace.append(RuleTrace("default:registry", True, f"default owner of {glob}"))
                return Assignment(owner, "default:registry", "config", CONF_DEFAULT, {"registry": glob})
        trace.append(RuleTrace("default", False, "no account or registry default"))
        return None
