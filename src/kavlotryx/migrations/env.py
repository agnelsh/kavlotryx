"""Alembic environment. Kavlotryx passes the connection in ``config.attributes``."""

from __future__ import annotations

from alembic import context

from kavlotryx.db import Base

config = context.config
connection = config.attributes.get("connection")
if connection is None:  # pragma: no cover - only `alembic` CLI use without kavlo
    raise RuntimeError("run migrations with 'kavlo db upgrade'")

context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=True,  # SQLite needs batch mode for ALTER TABLE
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
