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
    type: str = ""  # glob over the resource type, e.g. "Microsoft.Compute/*" or "ServiceAccount"


class GraphConnectorConfig(BaseModel):
    """Microsoft Graph: a person named in a tag resolves to a team through Entra groups."""

    group_map: dict[str, str] = Field(default_factory=dict)  # group display name or id -> owner slug
    person_tag_keys: list[str] = Field(default_factory=lambda: ["owner", "contact", "created-by"])
    # People view: walk the Entra "manager" chain this many levels above group
    # members (needs User.Read.All). 0 turns it off.
    manager_levels: int = Field(default=3, ge=0, le=6)
    read_group_owners: bool = True  # Entra group owners are the team's leads


class LeanixConnectorConfig(BaseModel):
    """LeanIX: an asset matched to an Application fact sheet gets that application's team."""

    app_tag_keys: list[str] = Field(default_factory=lambda: ["app", "application", "leanix-app"])
    match_artifact_names: bool = True  # image repository or resource name equals an app alias
    team_map: dict[str, str] = Field(default_factory=dict)  # LeanIX team (Organization) name -> owner
    team_relation: str = "relApplicationToOrganization"  # older workspaces: relApplicationToUserGroup
    responsible_roles: list[str] = Field(default_factory=lambda: ["Responsible", "Application Owner"])


class ConnectorsConfig(BaseModel):
    graph: GraphConnectorConfig = Field(default_factory=GraphConnectorConfig)
    leanix: LeanixConnectorConfig = Field(default_factory=LeanixConnectorConfig)


class OwnershipConfig(BaseModel):
    owners: list[OwnerDef] = Field(default_factory=list)
    connectors: ConnectorsConfig = Field(default_factory=ConnectorsConfig)
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
    scan_stale_hours: int = 48  # a scope with no scan for longer is shown as stale
    # Triage (FR-IF-06/07). A risk acceptance must expire within these days, by the
    # highest severity it covers. Four eyes: the approver must not be the requester.
    acceptance_max_days: dict[str, int] = Field(
        default_factory=lambda: {"Critical": 30, "High": 90, "Medium": 180, "Low": 365}
    )
    triage_four_eyes: bool = True


# Policy keys that admins may change in the console (Settings page).
EDITABLE_POLICY_KEYS = ("confidence_limit", "due_days", "dispatch_min_priority", "dispatch_without_fix",
                        "production_tag_keys", "production_values", "scan_stale_hours",
                        "acceptance_max_days", "triage_four_eyes")


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
    personas: str = ""  # default console persona per token name: "alice=team_lead,bob=security_manager"
    graph_tenant_id: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = field(default="", repr=False)
    graph_snapshot: str = ""  # path to a JSON snapshot, used instead of the live API (demos, air-gapped)
    leanix_host: str = ""  # e.g. acme.leanix.net
    leanix_token: str = field(default="", repr=False)
    leanix_snapshot: str = ""
    defectdojo_url: str = ""  # e.g. https://defectdojo.example.com
    defectdojo_token: str = field(default="", repr=False)
    defectdojo_products: str = ""  # comma-separated product names; empty = every product
    auto_migrate: bool = True  # KAVLO_AUTO_MIGRATE=0: never change the schema at start
    # OIDC single sign-on for the console (FR-IF-10)
    oidc_issuer: str = ""  # e.g. https://login.microsoftonline.com/<tenant>/v2.0
    oidc_client_id: str = ""
    oidc_client_secret: str = field(default="", repr=False)
    oidc_redirect_url: str = ""  # e.g. https://kavlotryx.example.com/ui/sso/callback
    oidc_scopes: str = "openid email profile"
    oidc_groups_claim: str = "groups"
    oidc_role_map: str = ""  # "admin=<group>,analyst=<group>,viewer=*"
    oidc_label: str = "single sign-on"  # button text, e.g. "Microsoft Entra ID"
    token_login: bool = True  # KAVLO_TOKEN_LOGIN=0 hides the API-token sign-in on the console

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
            personas=e("KAVLO_PERSONAS", ""),
            graph_tenant_id=e("KAVLO_GRAPH_TENANT_ID", ""),
            graph_client_id=e("KAVLO_GRAPH_CLIENT_ID", ""),
            graph_client_secret=e("KAVLO_GRAPH_CLIENT_SECRET", ""),
            graph_snapshot=e("KAVLO_GRAPH_SNAPSHOT", ""),
            leanix_host=e("KAVLO_LEANIX_HOST", ""),
            leanix_token=e("KAVLO_LEANIX_TOKEN", ""),
            leanix_snapshot=e("KAVLO_LEANIX_SNAPSHOT", ""),
            defectdojo_url=e("KAVLO_DEFECTDOJO_URL", ""),
            defectdojo_token=e("KAVLO_DEFECTDOJO_TOKEN", ""),
            defectdojo_products=e("KAVLO_DEFECTDOJO_PRODUCTS", ""),
            auto_migrate=e("KAVLO_AUTO_MIGRATE", "1") != "0",
            oidc_issuer=e("KAVLO_OIDC_ISSUER", ""),
            oidc_client_id=e("KAVLO_OIDC_CLIENT_ID", ""),
            oidc_client_secret=e("KAVLO_OIDC_CLIENT_SECRET", ""),
            oidc_redirect_url=e("KAVLO_OIDC_REDIRECT_URL", ""),
            oidc_scopes=e("KAVLO_OIDC_SCOPES", cls.oidc_scopes),
            oidc_groups_claim=e("KAVLO_OIDC_GROUPS_CLAIM", cls.oidc_groups_claim),
            oidc_role_map=e("KAVLO_OIDC_ROLE_MAP", ""),
            oidc_label=e("KAVLO_OIDC_LABEL", cls.oidc_label),
            token_login=e("KAVLO_TOKEN_LOGIN", "1") != "0",
        )

    def default_personas(self) -> dict[str, str]:
        out = {}
        for item in filter(None, (p.strip() for p in self.personas.split(","))):
            name, _, persona = item.partition("=")
            if name and persona:
                out[name.strip()] = persona.strip()
        return out


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


def load_policy(config_dir: Path, overrides: dict | None = None) -> PolicyConfig:
    data = _load_yaml(config_dir / "policy.yaml")
    data.update({k: v for k, v in (overrides or {}).items() if k in EDITABLE_POLICY_KEYS})
    return PolicyConfig.model_validate(data)
