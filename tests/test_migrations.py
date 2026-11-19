"""Alembic migrations (NFR-OPS-02)."""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from kavlotryx import migrate
from kavlotryx.db import Base, init_db


def test_migrations_build_exactly_the_models(svc):
    """The schema from 'upgrade head' matches the SQLAlchemy models, on SQLite and PostgreSQL."""
    assert migrate.current(svc.engine) == migrate.head() == "0003"
    with svc.engine.connect() as c:
        diff = compare_metadata(MigrationContext.configure(c, opts={"compare_type": True}), Base.metadata)
    assert diff == []


def test_downgrade_and_upgrade_again(svc):
    migrate.downgrade(svc.engine, "0001")
    assert not inspect(svc.engine).has_table("users") and migrate.current(svc.engine) == "0001"
    migrate.upgrade(svc.engine)
    assert inspect(svc.engine).has_table("users")


def legacy_db(tmp_path):
    """A database that create_all made before migrations and before triage existed."""
    eng = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    old = [Base.metadata.tables[n] for n in migrate.BASELINE_TABLES
           if n not in ("triage_decisions", "triage_items", "notes", "directory_people")]
    Base.metadata.create_all(eng, tables=old)
    with eng.begin() as c:
        c.execute(text("CREATE TABLE directory_people (id VARCHAR(128) PRIMARY KEY, upn VARCHAR(320))"))
        c.execute(text("INSERT INTO audit_events (at, actor, action, target, detail) "
                       "VALUES ('2026-11-01 00:00:00', 'me', 'scan.ingest', 'scan:1', '{}')"))
    return eng


def test_legacy_database_is_adopted_and_keeps_its_data(tmp_path):
    eng = legacy_db(tmp_path)
    init_db(eng)
    insp = inspect(eng)
    assert migrate.current(eng) == migrate.head()
    assert {"triage_decisions", "notes", "users"} <= set(insp.get_table_names())
    assert "manager_id" in {c["name"] for c in insp.get_columns("directory_people")}
    with eng.connect() as c:
        assert c.execute(text("SELECT count(*) FROM audit_events")).scalar() == 1


def test_no_auto_migrate_refuses_an_old_schema(tmp_path):
    with pytest.raises(migrate.SchemaOutdated, match="kavlo db upgrade"):
        init_db(legacy_db(tmp_path), auto_migrate=False)
    eng = create_engine(f"sqlite:///{tmp_path / 'behind.db'}")
    migrate.upgrade(eng, "0001")
    with pytest.raises(migrate.SchemaOutdated, match="0001"):
        init_db(eng, auto_migrate=False)
    init_db(eng)
    init_db(eng, auto_migrate=False)  # current now: no error


def test_history_lists_revisions():
    assert [r for r, _ in migrate.history()] == ["0001", "0002", "0003"]
