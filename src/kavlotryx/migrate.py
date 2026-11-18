"""Schema migrations with Alembic (NFR-OPS-02).

``ensure`` runs when Kavlotryx starts:

* an empty database is upgraded to the latest revision;
* a database that ``create_all`` made before Alembic arrived is brought to the
  baseline schema (missing baseline tables are created, cache tables with old
  columns are rebuilt), stamped as ``0001`` and then upgraded;
* any other database is upgraded when it is behind.

With ``KAVLO_AUTO_MIGRATE=0`` Kavlotryx does not change the schema at start.
It refuses to run on an old schema and asks for ``kavlo db upgrade``. Use that
when several replicas share one database, so only one process migrates.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine

BASELINE = "0001"
# The tables in revision 0001, the schema of the last release made by create_all.
BASELINE_TABLES = (
    "scans", "observations", "findings", "finding_sources", "owner_overrides", "work_items",
    "triage_decisions", "triage_items", "notes", "audit_events", "user_prefs", "setting_overrides",
    "directory_people", "catalog_apps", "connector_runs",
)
# Tables that only cache connector data: rebuilt (empty) when a legacy copy lacks columns.
CACHE_TABLES = ("directory_people", "catalog_apps")


class SchemaOutdated(RuntimeError):
    pass


def config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def head() -> str:
    return ScriptDirectory.from_config(config()).get_current_head() or ""


def current(engine: Engine) -> str | None:
    with engine.connect() as c:
        return MigrationContext.configure(c).get_current_revision()


def upgrade(engine: Engine, revision: str = "head") -> None:
    with engine.begin() as c:
        command.upgrade(config(c), revision)


def downgrade(engine: Engine, revision: str) -> None:
    with engine.begin() as c:
        command.downgrade(config(c), revision)


def stamp(engine: Engine, revision: str) -> None:
    with engine.begin() as c:
        command.stamp(config(c), revision)


def history() -> list[tuple[str, str]]:
    script = ScriptDirectory.from_config(config())
    return [(r.revision, (r.doc or "").strip().splitlines()[0]) for r in reversed(list(script.walk_revisions()))]


def _adopt_legacy(engine: Engine) -> None:
    """Bring a pre-Alembic database to the baseline schema and stamp it."""
    from kavlotryx.db import Base

    insp = inspect(engine)
    for name in CACHE_TABLES:
        if insp.has_table(name):
            have = {c["name"] for c in insp.get_columns(name)}
            table = Base.metadata.tables[name]
            if not {c.name for c in table.columns} <= have:
                table.drop(engine)
    tables = [Base.metadata.tables[n] for n in BASELINE_TABLES]
    Base.metadata.create_all(engine, tables=tables)  # creates only the missing ones
    stamp(engine, BASELINE)


def ensure(engine: Engine, auto: bool = True) -> str:
    """Make the schema current. Returns the revision the database is at."""
    tables = set(inspect(engine).get_table_names())
    if "alembic_version" not in tables and tables & set(BASELINE_TABLES):
        if not auto:
            raise SchemaOutdated("the database predates migrations: run 'kavlo db upgrade'")
        _adopt_legacy(engine)
    target = head()
    cur = current(engine)
    if cur != target:
        if not auto:
            raise SchemaOutdated(f"the database is at revision {cur or 'none'}, the code needs {target}: "
                                 "run 'kavlo db upgrade'")
        upgrade(engine)
    return target
