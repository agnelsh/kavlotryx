"""Wiz adapter (FR-IN-08): Issues CSV, Vulnerability CSV, wizcli image/directory/IaC JSON."""

from __future__ import annotations

import csv
import io
import json

import pytest
from sqlalchemy import select

from kavlotryx.adapters import AdapterError, get_adapter
from kavlotryx.db import Finding, WorkItem
from kavlotryx.ocsf import extract_facts
from tests.test_samples import SAMPLES, needs_samples, sample_svc  # noqa: F401  (fixture)

ISSUE_COLS = ["Created At", "Title", "Severity", "Status", "Description", "Resource Type",
              "Resource external ID", "Subscription ID", "Project Names", "Control ID", "Resource Name",
              "Resource Region", "Resource Platform", "Issue ID", "Resource vertex ID",
              "Remediation Recommendation", "Subscription Name", "Wiz URL", "Resource Tags",
              "Kubernetes Cluster"]


def issues_csv(*rows: dict) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ISSUE_COLS)
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in ISSUE_COLS})
    return buf.getvalue().encode()


def issue(n: int, status: str = "OPEN", **kw) -> dict:
    base = {"Title": "Publicly exposed VM on port 22", "Severity": "HIGH", "Status": status,
            "Resource Type": "Microsoft.Compute/virtualMachines",
            "Resource external ID": f"/subscriptions/sub-1/vm/vm-{n}", "Subscription ID": "sub-1",
            "Control ID": "ctl-ssh", "Resource Name": f"vm-{n}", "Resource Platform": "Azure",
            "Issue ID": f"issue-{n}", "Resource Tags": json.dumps({"Owner": "JD", "env": "prod"}),
            "Wiz URL": "https://app.wiz.io/issues#x", "Project Names": "Payments"}
    base.update(kw)
    return base


def test_issues_csv_maps_to_detection_findings():
    r = get_adapter("wiz").parse(issues_csv(issue(1), issue(2, "IGNORED"), issue(3, "RESOLVED")))
    assert r.default_scope == "wiz:issues"
    assert len(r.records) == 2  # RESOLVED rows are absent; IGNORED still exists
    f = extract_facts(r.records[0])
    assert (f.kind, f.scanner, f.rule_key) == ("config", "wiz", "wiz:ctl-ssh")
    assert f.asset_key == "/subscriptions/sub-1/vm/vm-1"
    assert (f.account_uid, f.provider, f.severity_id) == ("sub-1", "azure", 4)
    assert f.tags == {"Owner": "JD", "env": "prod", "wiz-project": "Payments"}


def test_tenant_level_issues_group_by_platform_tenant():
    rows = [issue(n, **{"Subscription ID": "", "Resource Type": "Microsoft.AzureActiveDirectory/User"})
            for n in range(3)]
    recs = get_adapter("wiz").parse(issues_csv(*rows)).records
    assert {extract_facts(r).account_uid for r in recs} == {"azure-tenant"}


def test_resolved_issue_is_verified_but_ignored_is_not(svc):
    svc.ingest("wiz", issues_csv(issue(1), issue(2)))
    r = svc.ingest("wiz", issues_csv(issue(1, "RESOLVED"), issue(2, "IGNORED")))
    assert r.fixed == 1
    with svc.session() as s:
        status = {f.asset_key[-4:]: f.status for f in s.scalars(select(Finding))}
    assert status == {"vm-1": "fixed", "vm-2": "open"}


def test_issues_group_by_control_and_route_by_owner_tag(svc):
    svc.ingest("wiz", issues_csv(issue(1), issue(2), issue(3)))
    svc.rebuild()
    with svc.session() as s:
        items = s.scalars(select(WorkItem)).all()
    assert len(items) == 1 and "(3 resources in account sub-1)" in items[0].title
    assert items[0].priority == "Critical"  # High raised for env=prod


def test_vulnerability_csv():
    cols = ["ID", "Name", "VendorSeverity", "DetailedName", "Version", "FixedVersion", "LocationPath",
            "AssetName", "ProviderUniqueId", "CloudPlatform", "SubscriptionExternalId", "FindingStatus", "Tags"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    w.writerow({"ID": "1", "Name": "CVE-2024-36891", "VendorSeverity": "Medium", "DetailedName": "kernel",
                "Version": "1.0", "FixedVersion": "1.1", "LocationPath": "/usr/bin/x", "AssetName": "node-a",
                "ProviderUniqueId": "gcp://node-a", "CloudPlatform": "GCP", "SubscriptionExternalId": "big-corp",
                "FindingStatus": "Open", "Tags": "{}"})
    w.writerow({"ID": "2", "Name": "CVE-1", "DetailedName": "x", "AssetName": "n", "ProviderUniqueId": "p",
                "FindingStatus": "Resolved"})
    r = get_adapter("wiz").parse(buf.getvalue().encode())
    assert r.default_scope == "wiz:vulnerabilities" and len(r.records) == 1
    f = extract_facts(r.records[0])
    assert (f.kind, f.vuln_id, f.package, f.fixed_version, f.path) == ("vuln", "CVE-2024-36891", "kernel", "1.1",
                                                                      "usr/bin/x")


def wizcli(origin: dict, result: dict) -> bytes:
    return json.dumps({"id": "x", "scanOriginResource": origin, "result": result}).encode()


IMG = {"__typename": "CICDScanOriginContainerImage", "name": "ghcr.io/acme/api:1.2", "digest": "sha256:abc"}


def test_wizcli_image_vulns_and_secrets_skipped():
    data = wizcli(IMG, {
        "osPackages": [{"name": "libcrypto3", "version": "3.3.1-r0", "vulnerabilities": [
            {"name": "CVE-2024-5535", "severity": "LOW", "fixedVersion": "3.3.1-r1"}]}],
        "libraries": [{"name": "golang.org/x/net", "version": "0.14.0", "path": "/app/go.mod", "vulnerabilities": [
            {"name": "GHSA-qppj-fm5r-hxr3", "severity": "HIGH", "fixedVersion": "0.17.0"}]}],
        "secrets": [{"path": "/app/x.go"}, {"path": "/app/y.go"}],
    })
    r = get_adapter("wiz").parse(data)
    assert r.default_scope == "wizcli:ghcr.io/acme/api"
    assert len(r.records) == 2 and "2 secret findings" in r.skipped[0]
    os_f, lib_f = (extract_facts(x) for x in r.records)
    assert (os_f.asset_key, os_f.artifact, os_f.path) == ("sha256:abc", "ghcr.io/acme/api", "")
    assert (lib_f.vuln_id, lib_f.path) == ("GHSA-qppj-fm5r-hxr3", "app/go.mod")


def test_wizcli_iac_needs_scope(svc):
    data = wizcli({"__typename": "CICDScanOriginIAC", "name": "IAC scan 2024-07-16T12:17:28Z"}, {
        "ruleMatches": [{"rule": {"id": "r-user", "name": "Missing User Instruction"}, "severity": "HIGH",
                         "matches": [{"fileName": "Dockerfile", "lineNumber": 58, "expected": "add USER"}]}]})
    assert get_adapter("wiz").parse(data).default_scope == ""
    r = svc.ingest("wiz", data, scope="wizcli:checkout")
    assert r.new == 1
    with svc.session() as s:
        f = s.scalars(select(Finding)).one()
    assert (f.asset_key, f.rule_key, f.path, f.artifact) == ("fs:wizcli:checkout", "wiz:r-user", "Dockerfile",
                                                            "checkout")


@pytest.mark.parametrize("data", [b"a,b,c\n1,2,3\n", b'{"foo": 1}', b""])
def test_rejects_other_input(data):
    with pytest.raises(AdapterError):
        get_adapter("wiz").parse(data)


def test_pattern_rule_matches_resource_type(svc):
    svc.ingest("wiz", issues_csv(issue(1, **{"Resource Tags": "{}", "Resource Type": "ServiceAccount"})))
    with svc.session() as s:
        fid = s.scalars(select(Finding.id)).one()
    from kavlotryx.config import PatternRule

    cfg = svc.ownership
    cfg.patterns.append(PatternRule(id="sa", owner="platform", type="ServiceAccount"))
    from kavlotryx.core.ownership import OwnershipResolver

    with svc.session() as s:
        a = OwnershipResolver(cfg, svc.policy, svc.settings.config_dir).resolve(s.get(Finding, fid))
    assert (a.owner, a.rule, a.evidence["type"]) == ("platform", "pattern:sa", "ServiceAccount")


# -- DefectDojo samples (after hack/fetch-samples.sh) -------------------------------


@needs_samples
def test_wiz_issue_export_sample(sample_svc):  # noqa: F811
    r = sample_svc.ingest("wiz", (SAMPLES / "wiz" / "multiple_findings.csv").read_bytes())
    assert (r.records, r.new) == (97, 97)  # 98 rows, 1 RESOLVED
    before = sample_svc.rebuild()
    cfg_dir = sample_svc.settings.config_dir
    sample_svc.settings.graph_snapshot = str(cfg_dir / "graph-snapshot.json")
    sample_svc.settings.leanix_snapshot = str(cfg_dir / "leanix-snapshot.json")
    sample_svc.sync_connector("graph", rebuild=False)
    sample_svc.sync_connector("leanix", rebuild=False)
    rb = sample_svc.rebuild()
    assert (before.work_items, before.needs_review) == (38, 8)
    assert (rb.work_items, rb.needs_review) == (39, 5)  # Graph and LeanIX resolve 3 more owners
    with sample_svc.session() as s:
        guests = s.scalars(select(WorkItem).where(WorkItem.title.like("Azure guest user%"))).one()
    assert guests.owner_slug == "identity" and "26 resources" in guests.title


@needs_samples
def test_wizcli_image_sample_fix_is_verified(sample_svc):  # noqa: F811
    d = SAMPLES / "wizcli_img"
    assert sample_svc.ingest("wiz", (d / "wizcli_img_many_vul.json").read_bytes()).new == 8
    sample_svc.run()
    assert sample_svc.ingest("wiz", (d / "wizcli_img_zero_vul.json").read_bytes()).fixed == 8
    out = sample_svc.run()
    assert out["verify"]["verified"] >= 1
    with sample_svc.session() as s:
        assert {w.state for w in s.scalars(select(WorkItem))} == {"verified"}
