"""SQLAlchemy models. PostgreSQL in production (JSONB), SQLite for demos and tests.

v0.1 creates tables with ``create_all``. Alembic migrations replace this
before the first public release (NFR-OPS-02).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

JsonType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scanner: Mapped[str] = mapped_column(String(64), index=True)
    scope: Mapped[str] = mapped_column(String(512), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(80), index=True)
    class_uid: Mapped[int] = mapped_column(Integer)
    raw: Mapped[dict[str, Any]] = mapped_column(JsonType)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    class_uid: Mapped[int] = mapped_column(Integer)
    asset_key: Mapped[str] = mapped_column(String(1024), index=True)
    asset_type: Mapped[str] = mapped_column(String(128), default="")
    asset_name: Mapped[str] = mapped_column(String(1024), default="")
    artifact: Mapped[str] = mapped_column(String(1024), default="")
    vuln_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    package: Mapped[str] = mapped_column(String(256), default="")
    src_package: Mapped[str] = mapped_column(String(256), default="")
    installed_version: Mapped[str] = mapped_column(String(128), default="")
    fixed_version: Mapped[str] = mapped_column(String(128), default="")
    rule_key: Mapped[str] = mapped_column(String(512), default="")
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    severity_id: Mapped[int] = mapped_column(Integer, default=0, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="")
    account_uid: Mapped[str] = mapped_column(String(128), default="")
    region: Mapped[str] = mapped_column(String(64), default="")
    repo: Mapped[str] = mapped_column(String(512), default="")
    path: Mapped[str] = mapped_column(String(1024), default="")
    tags: Mapped[dict[str, str]] = mapped_column(JsonType, default=dict)

    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fixed_by_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)

    owner_slug: Mapped[str] = mapped_column(String(64), default="", index=True)
    owner_rule: Mapped[str] = mapped_column(String(128), default="")
    owner_source: Mapped[str] = mapped_column(String(64), default="")
    owner_evidence: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    owner_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)

    work_item_key: Mapped[str] = mapped_column(String(64), default="", index=True)


class FindingSource(Base):
    """One scanner and scope that reports a finding. Verification is per source."""

    __tablename__ = "finding_sources"
    __table_args__ = (UniqueConstraint("finding_id", "scanner", "scope"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(64))
    scope: Mapped[str] = mapped_column(String(512))
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_id: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OwnerOverride(Base):
    """A manual owner choice. It is the highest-order ownership rule (FR-OW-05)."""

    __tablename__ = "owner_overrides"
    __table_args__ = (UniqueConstraint("match_type", "match_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    match_type: Mapped[str] = mapped_column(String(16))  # "finding" | "asset"
    match_value: Mapped[str] = mapped_column(String(1024))
    owner_slug: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkItem(Base):
    __tablename__ = "work_items"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_slug: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    artifact: Mapped[str] = mapped_column(String(1024), default="")
    package: Mapped[str] = mapped_column(String(256), default="")
    fixed_version: Mapped[str] = mapped_column(String(128), default="")
    account_uid: Mapped[str] = mapped_column(String(128), default="")
    rule_key: Mapped[str] = mapped_column(String(512), default="")
    title: Mapped[str] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(16), default="Low")
    dispatchable: Mapped[bool] = mapped_column(Boolean, default=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(32), default="open", index=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    ticket_key: Mapped[str] = mapped_column(String(64), default="")
    ticket_url: Mapped[str] = mapped_column(String(512), default="")
    content_hash: Mapped[str] = mapped_column(String(64), default="")
    dispatched_hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AuditEvent(Base):
    """Append-only record of every write (NFR-SEC-05)."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)


class UserPref(Base):
    """Console preferences per signed-in principal (persona dashboard, team)."""

    __tablename__ = "user_prefs"
    principal: Mapped[str] = mapped_column(String(128), primary_key=True)
    persona: Mapped[str] = mapped_column(String(32), default="")
    team: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SettingOverride(Base):
    """A policy value changed in the console. It wins over policy.yaml."""

    __tablename__ = "setting_overrides"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JsonType)
    updated_by: Mapped[str] = mapped_column(String(128), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DirectoryPerson(Base):
    """A person from the identity provider (Microsoft Graph), with group names."""

    __tablename__ = "directory_people"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    upn: Mapped[str] = mapped_column(String(320), default="", index=True)
    mail: Mapped[str] = mapped_column(String(320), default="", index=True)
    nickname: Mapped[str] = mapped_column(String(128), default="", index=True)
    display_name: Mapped[str] = mapped_column(String(256), default="")
    department: Mapped[str] = mapped_column(String(256), default="")
    groups: Mapped[list[str]] = mapped_column(JsonType, default=list)  # group display names
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CatalogApp(Base):
    """An application from the enterprise catalog (LeanIX fact sheet)."""

    __tablename__ = "catalog_apps"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    aliases: Mapped[list[str]] = mapped_column(JsonType, default=list)
    external_ids: Mapped[list[str]] = mapped_column(JsonType, default=list)
    repos: Mapped[list[str]] = mapped_column(JsonType, default=list)
    teams: Mapped[list[str]] = mapped_column(JsonType, default=list)
    responsible: Mapped[list[str]] = mapped_column(JsonType, default=list)  # e-mail addresses
    url: Mapped[str] = mapped_column(String(512), default="")
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConnectorRun(Base):
    __tablename__ = "connector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connector: Mapped[str] = mapped_column(String(32), index=True)
    mode: Mapped[str] = mapped_column(String(16))  # live | snapshot
    status: Mapped[str] = mapped_column(String(16))  # ok | error
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    counts: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(128), default="")


def make_engine(url: str) -> Engine:
    kwargs: dict[str, Any] = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _):  # pragma: no cover - driver hook
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


def audit(session: Session, actor: str, action: str, target: str = "", **detail: Any) -> None:
    session.add(AuditEvent(actor=actor, action=action, target=target, detail=detail))
