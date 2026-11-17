"""Ownership rules with evidence (FR-OW) and root-cause grouping (FR-GR)."""

from __future__ import annotations

from sqlalchemy import select

from kavlotryx.db import Finding, FindingSource, WorkItem


def _find(svc, **where) -> Finding:
    with svc.session() as s:
        q = select(Finding)
        for k, v in where.items():
            q = q.where(getattr(Finding, k) == v)
        return s.scalars(q).one()


def test_dedupe_across_scanners(day1):
    f = _find(day1, vuln_id="CVE-2024-6119")
    with day1.session() as s:
        srcs = s.scalars(select(FindingSource).where(FindingSource.finding_id == f.id)).all()
    assert sorted(x.scanner for x in srcs) == ["ocsf", "trivy"]
    assert f.src_package == "openssl"  # the later scanner did not overwrite it


def test_tag_alias_owner(day1):
    f = _find(day1, asset_key="arn:aws:s3:::acme-analytics-exports")
    a = day1.explain(f.id)
    assert (a.owner, a.rule, a.confidence, a.needs_review) == ("data", "tag:team", 0.9, False)
    assert a.evidence["tag_value"] == "data-eng"


def test_account_default_needs_review(day1):
    f = _find(day1, asset_key="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f60001")
    a = day1.explain(f.id)
    assert (a.owner, a.rule, a.needs_review) == ("platform", "default:account", True)
    assert [t.rule for t in a.trace][:3] == ["override", "tag", "codeowners"]


def test_pattern_rule(day1):
    f = _find(day1, asset_key="arn:aws:rds:us-east-1:123456789012:db:payments-db")
    assert day1.explain(f.id).rule == "pattern:payments-databases"


def test_codeowners_splits_image_findings(day1):
    os_pkg = _find(day1, vuln_id="CVE-2023-45853")
    a = day1.explain(os_pkg.id)
    assert (a.owner, a.rule) == ("platform", "codeowners")
    assert a.evidence["path"] == "Dockerfile" and a.evidence["line"] == 3
    npm = _find(day1, vuln_id="CVE-2024-21538")
    b = day1.explain(npm.id)
    assert (b.owner, b.evidence["line"], b.evidence["pattern"]) == ("payments", 5, "/app/")


def test_override_wins_and_is_audited(day1):
    f = _find(day1, asset_key="arn:aws:s3:::acme-analytics-exports")
    day1.set_owner(f.id, "payments", actor="test", reason="bucket moved team")
    a = day1.explain(f.id)
    assert (a.owner, a.rule, a.confidence) == ("payments", "override:asset", 1.0)
    day1.rebuild()
    assert _find(day1, id=f.id).owner_slug == "payments"


def test_override_unknown_owner(day1):
    f = _find(day1, asset_key="arn:aws:s3:::acme-analytics-exports")
    try:
        day1.set_owner(f.id, "nobody", actor="t")
    except ValueError as e:
        assert "unknown owner" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_grouping(day1):
    r = day1.rebuild()
    assert r.findings == 10
    with day1.session() as s:
        items = {w.title: w for w in s.scalars(select(WorkItem))}
    openssl = items["Upgrade openssl to 3.0.14-1~deb12u2 in payments-api (2 vulnerabilities)"]
    assert openssl.owner_slug == "platform" and openssl.priority == "High" and openssl.dispatchable
    zlib = next(w for t, w in items.items() if t.startswith("Track zlib"))
    assert not zlib.dispatchable  # no fix: tracked, not dispatched
    ssh = next(w for t, w in items.items() if "port 22" in t)
    assert "(2 resources in account 123456789012)" in ssh.title
    bucket = next(w for t, w in items.items() if "S3" in t)
    assert bucket.priority == "Critical"  # High raised one level for env=prod
    assert len(items) == 7


def test_rebuild_is_stable(day1):
    day1.rebuild()
    with day1.session() as s:
        first = {w.key: w.content_hash for w in s.scalars(select(WorkItem))}
    day1.rebuild()
    with day1.session() as s:
        assert {w.key: w.content_hash for w in s.scalars(select(WorkItem))} == first
