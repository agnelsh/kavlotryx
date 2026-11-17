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

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.config import OwnershipConfig, PolicyConfig
from kavlotryx.core import codeowners
from kavlotryx.db import CatalogApp, DirectoryPerson, Finding, OwnerOverride

CONF_OVERRIDE = 1.0
CONF_TAG = 0.9
CONF_DIRECTORY = 0.8
CONF_CODEOWNERS = 0.85
CONF_CATALOG = 0.8
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
        people: list[DirectoryPerson] | None = None,
        apps: list[CatalogApp] | None = None,
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
        # Directory (Microsoft Graph) and catalog (LeanIX) caches, filled by a connector sync.
        self.people: dict[str, DirectoryPerson] = {}
        for p in people or []:
            for k in (p.upn, p.mail, p.nickname):
                if k:
                    self.people.setdefault(k.lower(), p)
        self.group_map = {k.lower(): v for k, v in cfg.connectors.graph.group_map.items()}
        self.apps: dict[str, CatalogApp] = {}
        for a in apps or []:
            for k in [a.id, a.name, *a.aliases, *a.external_ids]:
                if k:
                    self.apps.setdefault(k.strip().lower(), a)
        self.app_repos = {r: a for a in apps or [] for r in a.repos if r}
        self.team_map = {k.lower(): v for k, v in cfg.connectors.leanix.team_map.items()}
        self.has_people, self.has_apps = bool(people), bool(apps)

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
            or self._directory(f, trace)
            or self._codeowners(f, trace)
            or self._catalog(f, trace)
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

    def _person_team(self, person: DirectoryPerson) -> tuple[str, str] | None:
        for g in person.groups:
            owner = self.group_map.get(g.lower())
            if owner in self.known:
                return owner, g
        return None

    def _directory(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        if not self.has_people:
            trace.append(RuleTrace("directory", False, "Microsoft Graph not synced"))
            return None
        lower = {k.lower(): (k, v) for k, v in (f.tags or {}).items()}
        for key in self.cfg.connectors.graph.person_tag_keys:
            hit = lower.get(key.lower())
            if hit is None or not str(hit[1]).strip():
                continue
            tag_key, value = hit
            person = self.people.get(str(value).strip().lower())
            if person is None:
                trace.append(RuleTrace("directory", False, f"tag {tag_key}={value} is not a person in Entra ID"))
                continue
            team = self._person_team(person)
            if team is None:
                trace.append(RuleTrace("directory", False,
                                       f"{person.upn or person.display_name} is in no mapped Entra group"))
                continue
            owner, group = team
            trace.append(RuleTrace("directory", True,
                                   f"tag {tag_key}={value} → {person.upn or person.mail} → group {group}"))
            return Assignment(owner, "directory:graph", "microsoft_graph", CONF_DIRECTORY, {
                "tag_key": tag_key, "tag_value": value, "person": person.upn or person.mail,
                "name": person.display_name, "group": group})
        if not any(t.rule == "directory" for t in trace):
            trace.append(RuleTrace("directory", False, "no person tag on the asset"))
        return None

    def _catalog(self, f: Finding, trace: list[RuleTrace]) -> Assignment | None:
        if not self.has_apps:
            trace.append(RuleTrace("leanix", False, "LeanIX not synced"))
            return None
        lcfg = self.cfg.connectors.leanix
        candidates: list[tuple[str, str]] = []
        lower = {k.lower(): (k, v) for k, v in (f.tags or {}).items()}
        for key in lcfg.app_tag_keys:
            hit = lower.get(key.lower())
            if hit and str(hit[1]).strip():
                candidates.append((f"tag {hit[0]}={hit[1]}", str(hit[1])))
        if lcfg.match_artifact_names:
            for label, v in (("artifact", f.artifact), ("resource", f.asset_name)):
                short = (v or "").split("@")[0].rsplit("/", 1)[-1].split(":")[0]
                if short:
                    candidates.append((f"{label} {short}", short))
        app = None
        how = ""
        repo, _ = self._repo_for(f)
        if repo and repo in self.app_repos:
            app, how = self.app_repos[repo], f"repository {repo}"
        for label, value in candidates:
            if app is None and value.strip().lower() in self.apps:
                app, how = self.apps[value.strip().lower()], label
        if app is None:
            trace.append(RuleTrace("leanix", False, "asset matches no LeanIX application"))
            return None
        ev: dict[str, Any] = {"application": app.name, "app_id": app.id, "matched_by": how}
        for t in app.teams:
            owner = self.team_map.get(t.lower()) or self._owner_from_value(t)
            if owner:
                trace.append(RuleTrace("leanix", True, f"{how} → application {app.name} → team {t}"))
                return Assignment(owner, "leanix:team", "leanix", CONF_CATALOG, {**ev, "team": t})
        for email in app.responsible:
            person = self.people.get(email)
            team = self._person_team(person) if person else None
            if team:
                trace.append(RuleTrace("leanix", True, f"{how} → application {app.name} → responsible "
                                                       f"{email} → group {team[1]}"))
                return Assignment(team[0], "leanix:responsible", "leanix+graph", CONF_CATALOG,
                                  {**ev, "responsible": email, "group": team[1]})
        trace.append(RuleTrace("leanix", False, f"application {app.name} ({how}) has no mapped team or "
                                                "responsible person"))
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
            if p.type:
                checks.append(fnmatchcase(f.asset_type, p.type))
            if checks and all(checks) and p.owner in self.known:
                trace.append(RuleTrace(f"pattern:{p.id}", True, "pattern matched"))
                return Assignment(p.owner, f"pattern:{p.id}", "config", CONF_PATTERN,
                                  {k: v for k, v in {"pattern": p.id, "asset": p.asset, "name": p.name,
                                                     "rule": p.rule, "type": p.type}.items() if v})
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


def resolver_for(session: Session, cfg: OwnershipConfig, policy: PolicyConfig, config_dir: Path) -> OwnershipResolver:
    """A resolver with the overrides and connector caches from the database."""
    return OwnershipResolver(cfg, policy, config_dir,
                             overrides=list(session.scalars(select(OwnerOverride))),
                             people=list(session.scalars(select(DirectoryPerson))),
                             apps=list(session.scalars(select(CatalogApp))))
