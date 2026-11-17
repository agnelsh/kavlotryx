"""Dispatch idempotency (FR-DS-02) and scan-verified closure (FR-VF)."""

from __future__ import annotations

from sqlalchemy import select

from kavlotryx.config import Settings
from kavlotryx.db import WorkItem
from kavlotryx.service import Kavlotryx
from tests.conftest import scan


def _items(svc) -> dict[str, WorkItem]:
    with svc.session() as s:
        return {w.title.split(" (")[0]: w for w in s.scalars(select(WorkItem))}


def test_dispatch_creates_one_ticket_per_item_and_is_idempotent(day1, tracker):
    out = day1.run()
    assert out["dispatch"]["create"] == 6  # 7 items minus zlib (no fix yet)
    creates = [c for c in tracker.calls if c.startswith("create")]
    assert len(creates) == 6
    projects = sorted(i["project"] for i in tracker.issues.values())
    assert projects == ["DATA", "PAY", "PAY", "PLAT", "PLAT", "PLAT"]
    again = day1.run()
    assert again["dispatch"]["create"] == 0
    assert len(tracker.issues) == 6


def test_fresh_database_adopts_existing_tickets(day1, tracker, tmp_path):
    day1.run()
    other = Kavlotryx(Settings(database_url=f"sqlite:///{tmp_path / 'other.db'}",
                               config_dir=day1.settings.config_dir), tracker=tracker)
    other.ingest("prowler", scan("prowler-aws-day1.ocsf.json"))
    other.ingest("trivy", scan("trivy-payments-api-1.4.0.json"))
    other.ingest("trivy", scan("trivy-repo-payments-api.json"))
    out = other.run()
    assert out["dispatch"]["create"] == 0
    assert out["dispatch"]["adopt"] == 6
    assert len(tracker.issues) == 6


def test_ticket_body_has_evidence_and_due_date(day1, tracker):
    day1.run()
    issue = next(i for i in tracker.issues.values() if i["project"] == "DATA")
    assert issue["priority"] == "Highest" and issue["due"]
    assert "tag" in issue["description"] and "data-eng" in issue["description"]
    assert any(label.startswith("kavlo-") for label in issue["labels"])


def test_dry_run_changes_nothing(day1, tracker):
    out = day1.run(dry_run=True)
    assert out["dispatch"]["create"] == 6
    assert tracker.issues == {}


def test_verified_closure_lifecycle(day1, tracker):
    day1.run()
    items = _items(day1)
    bucket_key = items["Ensure S3 buckets have Block Public Access enabled"].ticket_key
    openssl_key = items["Upgrade openssl to 3.0.14-1~deb12u2 in payments-api"].ticket_key

    # A person closes the openssl ticket before any scan confirms it.
    tracker.transition(openssl_key, "done")
    out = day1.run()
    assert out["verify"]["pending"] == 1
    assert "still report" in tracker.issues[openssl_key]["comments"][-1]

    # Day 2: bucket fixed, one SSH group fixed, new image without openssl CVEs.
    day1.ingest("prowler", scan("prowler-aws-day2.ocsf.json"))
    day1.ingest("trivy", scan("trivy-payments-api-1.4.1.json"))
    out = day1.run()
    assert tracker.status(bucket_key) == "done"
    assert "verified the fix" in tracker.issues[bucket_key]["comments"][-1]
    # Grype still reports CVE-2024-6119 on the old image: the openssl item stays open.
    assert _items(day1)["Upgrade openssl to 3.0.14-1~deb12u2 in payments-api"].state == "pending_verification"

    # Grype re-scans and no longer reports it: now the item is verified.
    day1.ingest("ocsf", b"[]", scope="grype:ghcr.io/acme/payments-api")
    day1.run()
    assert _items(day1)["Upgrade openssl to 3.0.14-1~deb12u2 in payments-api"].state == "verified"

    # The old image comes back (rollback): the finding returns and the ticket reopens.
    day1.ingest("trivy", scan("trivy-payments-api-1.4.0.json"))
    out = day1.run()
    assert out["verify"]["reopened"] >= 1
    w = _items(day1)["Upgrade openssl to 3.0.14-1~deb12u2 in payments-api"]
    assert w.state == "dispatched" and w.ticket_key == openssl_key
    assert tracker.status(openssl_key) == "new"
    assert len([c for c in tracker.calls if c.startswith("create")]) == 6


def test_partial_fix_keeps_item_open(day1, tracker):
    day1.run()
    day1.ingest("prowler", scan("prowler-aws-day2.ocsf.json"))
    day1.run()
    ssh = next(w for t, w in _items(day1).items() if "port 22" in t)
    assert ssh.state == "dispatched"
    assert "1 resource" in ssh.title
    assert any(c == f"update {ssh.ticket_key}" for c in tracker.calls)


def test_scope_isolation(day1):
    # A Prowler scan of another account must not mark this account's findings fixed.
    other = scan("prowler-aws-day1.ocsf.json").replace(b"123456789012", b"999999999999")
    r = day1.ingest("prowler", other)
    assert r.scope == "prowler:aws:999999999999"
    assert r.fixed == 0
