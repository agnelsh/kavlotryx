"""ServiceNow CMDB ownership (FR-EN-08) and priority from business context and exploit signals (FR-PR-01/02)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kavlotryx.api import create_app
from kavlotryx.config import OwnershipConfig, ServiceNowConnectorConfig
from kavlotryx.connectors import connector_mode
from kavlotryx.connectors.base import ConnectorError, HttpClient
from kavlotryx.connectors.servicenow import ServiceNowClient, instance_host
from kavlotryx.connectors.threat_intel import parse_epss, parse_kev
from kavlotryx.db import CmdbCi, Finding, ThreatIntel, WorkItem
from tests.test_web import ADMIN, VIEW, csrf, login

SG1 = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f60001"
SG2 = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f60002"


def ci(sys_id: str, name: str, keys=(), **kw) -> dict:
    return {"sys_id": sys_id, "name": name, "class": kw.pop("cls", "cmdb_ci_server"), "keys": list(keys), **kw}


def write(tmp: Path, name: str, data) -> str:
    p = tmp / name
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return str(p)


@pytest.fixture
def intel(day1, tmp_path):
    """day1 plus a CMDB snapshot and made-up KEV and EPSS data for its CVEs."""
    day1.settings.servicenow_snapshot = write(tmp_path, "sn.json", {"cis": [
        ci("a1", "bastion-sg", [SG1], support_group="Payments Engineering", environment="Production"),
        ci("a2", "legacy-jump-sg", support_group="Cloud Operations"),
        ci("a3", "legacy-jump-sg", support_group="Cloud Operations"),  # same name twice: not used
        ci("a4", "payments-db", support_group="Data Platform", criticality="1 - most critical", cls="cmdb_ci_db"),
    ]})
    day1.settings.kev_snapshot = write(tmp_path, "kev.json", {"catalogVersion": "test", "vulnerabilities": [
        {"cveID": "CVE-2024-6119", "vulnerabilityName": "OpenSSL test entry", "dateAdded": "2026-01-02",
         "dueDate": "2026-01-23", "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch it."},
        {"cveID": "CVE-1999-0001", "vulnerabilityName": "not in any finding"}]})
    day1.settings.epss_snapshot = write(tmp_path, "epss.json", {"status": "OK", "data": [
        {"cve": "CVE-2024-21538", "epss": "0.50000", "percentile": "0.97", "date": "2026-11-19"},
        {"cve": "CVE-2024-5535", "epss": "0.01000", "percentile": "0.40", "date": "2026-11-19"}]})
    for n in ("servicenow", "kev", "epss"):
        day1.sync_connector(n, rebuild=False)
    day1.rebuild()
    return day1


def find(k, **where) -> Finding:
    with k.session() as s:
        q = select(Finding)
        for key, v in where.items():
            q = q.where(getattr(Finding, key) == v)
        return s.scalars(q).first()


def item(k, key: str) -> WorkItem:
    with k.session() as s:
        return s.get(WorkItem, key)


# -- ServiceNow connector -----------------------------------------------------------


@pytest.mark.parametrize("value,host", [("acme", "acme.service-now.com"),
                                        ("https://acme.service-now.com/", "acme.service-now.com"),
                                        ("gov1.servicenowservices.com", "gov1.servicenowservices.com")])
def test_instance_host(value, host):
    assert instance_host(value) == host


@pytest.mark.parametrize("value", ["evil.example.com", "acme.service-now.com.evil.io", "", "a/b"])
def test_instance_host_refuses_other_hosts(value):
    with pytest.raises(ConnectorError):
        instance_host(value)


def test_servicenow_client_pages_and_reads_display_values(monkeypatch):
    monkeypatch.setattr("kavlotryx.connectors.servicenow.PAGE", 2)
    seen: list[httpx.Request] = []

    def rec(i: int) -> dict:
        return {"sys_id": {"value": f"s{i}", "display_value": f"s{i}"},
                "name": {"value": f"vm-{i}", "display_value": f"vm-{i}"},
                "sys_class_name": {"value": "cmdb_ci_vm_instance", "display_value": "Virtual Machine Instance"},
                "object_id": {"value": f"/subscriptions/x/vm-{i}", "display_value": f"/subscriptions/x/vm-{i}"},
                "support_group.name": {"value": "Cloud Operations", "display_value": "Cloud Operations"},
                "owned_by.email": {"value": "Ann@Example.com", "display_value": "Ann@Example.com"},
                "used_for": {"value": "Production", "display_value": "Production"},
                "busines_criticality": {"value": "1", "display_value": "1 - most critical"}}

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        off = int(req.url.params["sysparm_offset"])
        return httpx.Response(200, json={"result": [rec(i) for i in range(off, min(off + 2, 3))]})

    c = ServiceNowClient("acme", "svc", "pw", transport=httpx.MockTransport(h), sleep=lambda _: None)
    rows = c.records(ServiceNowConnectorConfig())
    assert [r["sys_id"] for r in rows] == ["s0", "s1", "s2"] and len(seen) == 2
    assert all(r.method == "GET" and r.url.host == "acme.service-now.com" for r in seen)
    assert seen[0].url.path == "/api/now/table/cmdb_ci" and seen[0].headers["authorization"].startswith("Basic ")
    fields = seen[0].url.params["sysparm_fields"].split(",")
    assert {"support_group.name", "owned_by.email", "object_id"} <= set(fields)
    r = rows[0]
    assert r["class"] == "cmdb_ci_vm_instance"  # the table name, not the label
    assert r["criticality"] == "1 - most critical" and r["environment"] == "Production"
    assert r["owned_by"] == "ann@example.com" and r["keys"] == ["/subscriptions/x/vm-0"]
    assert r["url"] == "https://acme.service-now.com/cmdb_ci_vm_instance.do?sys_id=s0"


def test_servicenow_token_auth_and_errors():
    def h(req):
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(401, text="no")
    with pytest.raises(ConnectorError, match="HTTP 401"):
        ServiceNowClient("acme", token="tok", transport=httpx.MockTransport(h)).records(ServiceNowConnectorConfig())
    with pytest.raises(ConnectorError, match="KAVLO_SERVICENOW_TOKEN"):
        ServiceNowClient("acme")


def test_servicenow_config_refuses_bad_table():
    with pytest.raises(ValueError):
        ServiceNowConnectorConfig(table="cmdb_ci?x=1")


def test_modes(settings):
    for n in ("servicenow", "kev", "epss"):
        assert connector_mode(settings, n) == "off"
    settings.servicenow_instance, settings.servicenow_token = "acme", "t"
    settings.threat_intel_live = True
    assert {connector_mode(settings, n) for n in ("servicenow", "kev", "epss")} == {"live"}
    settings.kev_snapshot = "x.json"
    assert connector_mode(settings, "kev") == "snapshot"


# -- ownership from the CMDB --------------------------------------------------------


def test_cmdb_ci_assigns_owner_by_resource_id(intel):
    f = find(intel, asset_key=SG1)
    assert (f.owner_slug, f.owner_rule, f.owner_source) == ("payments", "servicenow:support_group", "servicenow")
    assert f.owner_confidence == 0.8 and not f.needs_review
    assert f.owner_evidence["matched_by"] == "resource id" and f.owner_evidence["ci"] == "bastion-sg"


def test_ambiguous_ci_name_is_not_used(intel):
    f = find(intel, asset_key=SG2)
    assert f.owner_rule == "default:account"
    trace = intel.explain(f.id).trace
    assert any(t.rule == "servicenow" and "matches 2 CIs" in t.reason for t in trace)


def test_unmapped_support_group_falls_through(intel):
    f = find(intel, asset_name="payments-db")
    assert f.owner_rule == "pattern:payments-databases"
    trace = intel.explain(f.id).trace
    assert any(t.rule == "servicenow" and "Data Platform" in t.reason and not t.matched for t in trace)


def test_stronger_rules_still_win(intel):
    assert find(intel, asset_name="acme-analytics-exports").owner_rule == "tag:team"


def test_ci_owner_through_entra_group():
    from kavlotryx.config import PolicyConfig
    from kavlotryx.core.ownership import OwnershipResolver
    from kavlotryx.db import DirectoryPerson

    cfg = OwnershipConfig(owners=[{"slug": "app"}], connectors={"graph": {"group_map": {"sg-app": "app"}}})
    person = DirectoryPerson(id="p1", upn="ann@example.com", mail="", nickname="", display_name="Ann",
                             groups=["sg-app"])
    vm = CmdbCi(sys_id="c1", name="vm-1", class_name="", keys=["i-0abc"], owned_by="ann@example.com",
                support_group="", managed_by_group="", business_service="", criticality="", environment="", url="")
    res = OwnershipResolver(cfg, PolicyConfig(), Path("."), people=[person], cis=[vm])
    f = Finding(fingerprint="x", kind="config", class_uid=2003, asset_key="arn:aws:ec2:us-east-1:1:instance/i-0abc",
                asset_name="", artifact="", tags={}, repo="", path="", account_uid="", rule_key="r", asset_type="")
    a = res.resolve(f)
    assert (a.owner, a.rule, a.source) == ("app", "servicenow:owned_by", "servicenow+graph")
    assert a.evidence["matched_by"] == "resource id"


# -- threat intelligence feeds -------------------------------------------------------


def test_kev_and_epss_parsers(tmp_path):
    version, rows = parse_kev(json.dumps({"catalogVersion": "v1", "vulnerabilities": [{"cveID": "CVE-1-2"}]}).encode())
    assert version == "v1" and rows[0]["cveID"] == "CVE-1-2"
    with pytest.raises(ConnectorError):
        parse_kev(b'{"nope": 1}')
    csv_text = "#model_version:v2025.03.14,score_date:2026-11-19T00:00:00+0000\ncve,epss,percentile\n" \
               "CVE-2024-0001,0.25,0.9\nCVE-2024-0002,bad,0.1\n"
    when, scores = parse_epss(csv_text.encode())
    assert when.isoformat() == "2026-11-19" and scores[0] == ("CVE-2024-0001", 0.25, 0.9) and scores[1][1] is None
    with pytest.raises(ConnectorError):
        parse_epss(b"a,b\n1,2\n")


def test_epss_gzip_csv_snapshot_keeps_only_finding_cves(day1, tmp_path):
    p = tmp_path / "epss.csv.gz"
    p.write_bytes(gzip.compress(b"cve,epss,percentile\nCVE-2024-6119,0.3,0.95\nCVE-2000-0001,0.9,1\n"))
    day1.settings.epss_snapshot = str(p)
    run = day1.sync_connector("epss", rebuild=False)
    assert run.counts["scored"] == 1
    with day1.session() as s:
        assert [t.cve for t in s.scalars(select(ThreatIntel))] == ["CVE-2024-6119"]


def test_live_feeds_batch_and_stay_on_https(day1, monkeypatch):
    monkeypatch.setattr("kavlotryx.connectors.threat_intel.BATCH", 2)
    asked: list[list[str]] = []

    def h(req: httpx.Request) -> httpx.Response:
        if "cisa.gov" in req.url.host:
            return httpx.Response(200, json={"catalogVersion": "x", "vulnerabilities": [{"cveID": "CVE-2024-5535"}]})
        cves = req.url.params["cve"].split(",")
        asked.append(cves)
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.2", "percentile": "0.9", "date": "2026-11-19"}
                                                  for c in cves]})

    client = HttpClient(transport=httpx.MockTransport(h), sleep=lambda _: None)
    assert day1.sync_connector("kev", client=client, rebuild=False).counts["in_findings"] == 1
    run = day1.sync_connector("epss", client=client, rebuild=False)
    assert run.counts == {"cves": 4, "scored": 4, "date": "2026-11-19"}
    assert [len(b) for b in asked] == [2, 2]
    day1.settings.kev_url = "http://plain.example/kev.json"
    with pytest.raises(ConnectorError, match="https"):
        day1.sync_connector("kev", client=client, rebuild=False)


def test_kev_removal_clears_the_flag(intel, tmp_path):
    intel.settings.kev_snapshot = write(tmp_path, "kev2.json", {"vulnerabilities": []})
    assert intel.sync_connector("kev", rebuild=False).counts["removed"] == 2
    with intel.session() as s:
        assert not s.get(ThreatIntel, "CVE-2024-6119").kev


# -- priority -------------------------------------------------------------------------


def codes(w: WorkItem) -> list[str]:
    return [r["code"] for r in w.priority_reasons]


def test_kev_sets_the_floor_and_explains_it(intel):
    w = item(intel, find(intel, vuln_id="CVE-2024-6119").work_item_key)
    assert w.priority == "Critical" and codes(w) == ["severity", "kev"]
    assert "known ransomware use" in w.priority_reasons[-1]["text"]


def test_epss_raises_one_level(intel):
    w = item(intel, find(intel, vuln_id="CVE-2024-21538").work_item_key)
    assert w.priority == "Critical" and codes(w) == ["severity", "epss"]  # High + 1
    assert "EPSS 0.500" in w.priority_reasons[1]["text"]


def test_cmdb_context_raises_priority(intel):
    assert item(intel, find(intel, asset_name="payments-db").work_item_key).priority == "High"  # Medium + critical CI
    w = item(intel, find(intel, asset_key=SG1).work_item_key)
    assert "impact" in codes(w) and "used for Production" in w.priority_reasons[1]["text"]


def test_signals_can_be_turned_off(intel):
    intel.set_policy({"kev_min_priority": "", "epss_threshold": 0.0, "business_critical_values": []}, "t")
    intel.rebuild()
    assert item(intel, find(intel, vuln_id="CVE-2024-6119").work_item_key).priority == "High"
    assert item(intel, find(intel, vuln_id="CVE-2024-21538").work_item_key).priority == "High"
    assert item(intel, find(intel, asset_name="payments-db").work_item_key).priority == "Medium"


def test_daily_epss_change_does_not_rewrite_tickets(intel):
    key = find(intel, vuln_id="CVE-2024-21538").work_item_key
    before = item(intel, key).content_hash
    with intel.session() as s:
        s.get(ThreatIntel, "CVE-2024-21538").epss = 0.61
        s.commit()
    intel.rebuild()
    after = item(intel, key)
    assert after.content_hash == before and "EPSS 0.610" in after.priority_reasons[1]["text"]


def test_ticket_text_lists_the_reasons(intel):
    intel.dispatch()
    key = find(intel, vuln_id="CVE-2024-6119").work_item_key
    w = item(intel, key)
    issue = intel.tracker.issues[w.ticket_key]
    assert issue["priority"] == "Highest"  # Critical
    assert "- CVE-2024-6119 is in the CISA KEV catalog (added 2026-01-02); known ransomware use; at least Critical" \
        in issue["description"]


# -- console and API ---------------------------------------------------------------------


@pytest.fixture
def client(intel):
    intel.settings.api_tokens = f"me:admin:{ADMIN},v:viewer:{VIEW}"
    return TestClient(create_app(intel))


def test_console_shows_signals(client, intel):
    login(client, ADMIN)
    page = client.get("/ui/vulnerabilities?intel=kev").text
    assert "CVE-2024-6119" in page and "CVE-2024-21538" not in page and ">KEV<" in page
    assert "CVE-2024-21538" in client.get("/ui/vulnerabilities?intel=epss").text
    f = find(intel, vuln_id="CVE-2024-6119")
    detail = client.get(f"/ui/vulnerabilities/{f.id}").text
    assert "Risk Context" in detail and "OpenSSL test entry" in detail and "federal due date" in detail
    sg = client.get(f"/ui/vulnerabilities/{find(intel, asset_key=SG1).id}").text
    assert "ServiceNow CI" in sg and "Payments Engineering" in sg
    wi = client.get(f"/ui/workitems/{f.work_item_key}").text
    assert "Why Critical" in wi and "CISA KEV catalog" in wi
    own = client.get("/ui/ownership").text
    assert "ServiceNow CMDB" in own and "bastion-sg" in own and "Open on KEV" in own
    assert "ServiceNow CI" in own  # rule ladder
    assert "Exploited or Likely to Be Exploited" in client.get("/ui?persona=analyst").text
    csv_text = client.get("/ui/vulnerabilities.csv?intel=kev").text
    assert csv_text.splitlines()[0].endswith(",kev,epss") and ",True," in csv_text


def test_policy_form_saves_signal_settings(client, intel):
    login(client, ADMIN)
    page = client.get("/ui/settings/policy").text
    assert 'name="kev_min_priority"' in page and 'name="epss_threshold"' in page
    p = intel.policy
    data = {"csrf": csrf(page), "confidence_limit": p.confidence_limit, "due_critical": 7, "due_high": 30,
            "due_medium": 90, "due_low": 180, "dispatch_min_priority": "Low", "production_tag_keys": "env",
            "production_values": "prod, production", "scan_stale_hours": 48, "acc_critical": 30, "acc_high": 90,
            "acc_medium": 180, "acc_low": 365, "triage_four_eyes": "on", "kev_min_priority": "High",
            "epss_threshold": "0.3", "business_critical_values": "1 - most critical, 2 - somewhat critical"}
    r = client.post("/ui/settings/policy", data=data, follow_redirects=True)
    assert "Saved" in r.text
    p = intel.policy
    assert p.kev_min_priority == "High" and p.epss_threshold == 0.3
    assert p.business_critical_values == ["1 - most critical", "2 - somewhat critical"]
    bad = client.post("/ui/settings/policy", data={**data, "kev_min_priority": "Urgent"}, follow_redirects=True)
    assert "Not saved" in bad.text
    connectors = client.get("/ui/settings/connectors").text
    assert "KAVLO_SERVICENOW_INSTANCE" in connectors and "KAVLO_THREAT_INTEL_LIVE" in connectors


def test_api_exposes_signals(client, intel):
    h = {"Authorization": f"Bearer {VIEW}"}
    rows = client.get("/api/v1/findings?kev=true", headers=h).json()
    assert [r["vuln_id"] for r in rows] == ["CVE-2024-6119"] and rows[0]["threat"]["kev_ransomware"] == "Known"
    assert {r["vuln_id"] for r in client.get("/api/v1/findings?min_epss=0.4", headers=h).json()} == {"CVE-2024-21538"}
    fid = find(intel, asset_key=SG1).id
    assert client.get(f"/api/v1/findings/{fid}", headers=h).json()["cmdb_ci"]["support_group"] == "Payments Engineering"
    items = client.get("/api/v1/workitems", headers=h).json()
    rows = items["items"] if isinstance(items, dict) else items
    assert any(r["priority_reasons"] and r["priority_reasons"][-1]["code"] == "kev" for r in rows)
    assert {r["name"] for r in client.get("/api/v1/connectors", headers=h).json()} >= {"servicenow", "kev", "epss"}
