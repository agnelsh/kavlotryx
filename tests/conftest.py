from __future__ import annotations

import os
from pathlib import Path

import pytest

from kavlotryx.config import Settings
from kavlotryx.dispatch.fake import FakeTracker
from kavlotryx.service import Kavlotryx

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SCANS = EXAMPLES / "scans"
CONFIG = EXAMPLES / "config"


def scan(name: str) -> bytes:
    return (SCANS / name).read_bytes()


# Set KAVLO_TEST_DATABASE_URL=postgresql+psycopg://... to run the suite on PostgreSQL.
PG_URL = os.environ.get("KAVLO_TEST_DATABASE_URL", "")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    url = PG_URL or f"sqlite:///{tmp_path / 'k.db'}"
    if PG_URL:
        from sqlalchemy import text

        from kavlotryx.db import Base, make_engine

        engine = make_engine(PG_URL)
        Base.metadata.drop_all(engine)
        with engine.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS alembic_version"))
        engine.dispose()
    return Settings(database_url=url, config_dir=CONFIG,
                    tracker="fake", fake_tracker_file=tmp_path / "tracker.json")


@pytest.fixture
def tracker() -> FakeTracker:
    return FakeTracker()


@pytest.fixture
def svc(settings: Settings, tracker: FakeTracker):
    k = Kavlotryx(settings, tracker=tracker)
    yield k
    k.engine.dispose()  # PostgreSQL has a connection limit


@pytest.fixture
def day1(svc: Kavlotryx) -> Kavlotryx:
    svc.ingest("prowler", scan("prowler-aws-day1.ocsf.json"))
    svc.ingest("trivy", scan("trivy-payments-api-1.4.0.json"))
    svc.ingest("trivy", scan("trivy-repo-payments-api.json"))
    svc.ingest("ocsf", scan("grype-payments-api-1.4.0.ocsf.json"), scope="grype:ghcr.io/acme/payments-api")
    return svc
