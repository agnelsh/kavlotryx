"""Configuration: process settings (env) plus ownership.yaml and policy.yaml.

Credentials come only from the environment (NFR-SEC-02). They are never
written to the database or to logs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

# --- ownership.yaml ---------------------------------------------------------


class OwnerDef(BaseModel):
    slug: str
    name: str = ""
    jira_project: str = ""
    aliases: list[str] = Field(default_factory=list)

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError("owner slug must be letters, digits, '-' or '_'")
        return v


class CodeownersSource(BaseModel):
    repo: str  # host/org/repo
    file: str  # path to a local CODEOWNERS file (relative to the config dir)
    team_map: dict[str, str] = Field(default_factory=dict)  # "@acme/payments" -> "payments"


class ImageRepoMap(BaseModel):
    image: str  # glob over the image repository, e.g. "ghcr.io/acme/payments-*"
    repo: str


class PatternRule(BaseModel):
    id: str
    owner: str
    asset: str = ""  # glob over asset_key
    name: str = ""  # glob over asset or image name
    rule: str = ""  # glob over rule_key


class OwnershipConfig(BaseModel):
    owners: list[OwnerDef] = Field(default_factory=list)
    tag_keys: list[str] = Field(default_factory=lambda: ["owner", "team"])
    codeowners: list[CodeownersSource] = Field(default_factory=list)
    image_default_path: str = "Dockerfile"
    image_repos: list[ImageRepoMap] = Field(default_factory=list)
    patterns: list[PatternRule] = Field(default_factory=list)
    account_defaults: dict[str, str] = Field(default_factory=dict)
    registry_defaults: dict[str, str] = Field(default_factory=dict)  # glob -> owner
    fallback_owner: str = "unassigned"

    @field_validator("account_defaults", mode="before")
    @classmethod
    def _account_keys_as_str(cls, v):
        # YAML reads an unquoted AWS account id as an int.
        return {str(k): val for k, val in (v or {}).items()}


# --- policy.yaml -------------------------------------------------------------


class PolicyConfig(BaseModel):
    confidence_limit: float = 0.7
    due_days: dict[str, int] = Field(
        default_factory=lambda: {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}
    )
    jira_priority: dict[str, str] = Field(
        default_factory=lambda: {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
        }
    )
    dispatch_min_priority: str = "Low"
    dispatch_without_fix: bool = False
    production_tag_keys: list[str] = Field(default_factory=lambda: ["env", "environment"])
    production_values: list[str] = Field(default_factory=lambda: ["prod", "production"])


# --- process settings --------------------------------------------------------


@dataclass
class Settings:
    database_url: str = "sqlite:///./kavlotryx.db"
    config_dir: Path = Path(".")
    tracker: str = "fake"  # "jira" | "fake"
    fake_tracker_file: Path = Path(".kavlotryx/fake-tracker.json")
    jira_url: str = ""
    jira_email: str = ""
    jira_token: str = field(default="", repr=False)
    jira_issue_type: str = "Task"
    api_tokens: str = field(default="", repr=False)  # "name:role:token,name:role:token"
    max_upload_mb: int = 200

    @classmethod
    def from_env(cls) -> Settings:
        e = os.environ.get
        return cls(
            database_url=e("KAVLO_DATABASE_URL", cls.database_url),
            config_dir=Path(e("KAVLO_CONFIG_DIR", ".")),
            tracker=e("KAVLO_TRACKER", "jira" if e("KAVLO_JIRA_URL") else "fake"),
            fake_tracker_file=Path(e("KAVLO_FAKE_TRACKER_FILE", str(cls.fake_tracker_file))),
            jira_url=e("KAVLO_JIRA_URL", ""),
            jira_email=e("KAVLO_JIRA_EMAIL", ""),
            jira_token=e("KAVLO_JIRA_TOKEN", ""),
            jira_issue_type=e("KAVLO_JIRA_ISSUE_TYPE", "Task"),
            api_tokens=e("KAVLO_API_TOKENS", ""),
            max_upload_mb=int(e("KAVLO_MAX_UPLOAD_MB", "200")),
        )


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return data


def load_ownership(config_dir: Path) -> OwnershipConfig:
    return OwnershipConfig.model_validate(_load_yaml(config_dir / "ownership.yaml"))


def load_policy(config_dir: Path) -> PolicyConfig:
    return PolicyConfig.model_validate(_load_yaml(config_dir / "policy.yaml"))
