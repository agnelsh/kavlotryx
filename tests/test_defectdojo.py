"""DefectDojo adapter and API pull (FR-IN-09)."""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from kavlotryx.adapters import AdapterError, get_adapter
from kavlotryx.adapters.defectdojo_api import check_url
from kavlotryx.connectors.base import ConnectorError
from kavlotryx.db import Finding, WorkItem
from kavlotryx.ocsf import extract_facts
from tests.conftest import scan

DAY1 = "defectdojo-payments-checkout.json"
DAY2 = "defectdojo-payments-checkout-day2.json"


def parse(data: bytes):
    return get_adapter("defectdojo").parse(data)


def test_export_maps_to_ocsf():
    r = parse(scan(DAY1))
    assert r.default_scope == "defectdojo:payments-checkout"
    assert r.skipped == ["finding 108: duplicate of DefectDojo finding 101"]
    facts = {rec["unmapped"]["defectdojo"]["id"]: (rec, extract_facts(rec)) for rec in r.records}
    assert sorted(facts) == [101, 102, 103, 104, 105, 106]  # 107 is mitigated: absent
    rec, f = facts[101]
    assert (rec["class_uid"], f.kind, f.vuln_id, f.package, f.installed_version) == \
        (2002, "vuln", "CVE-2024-6345", "setuptools", "65.5.0")
    assert f.fixed_version == "70.0.0"  # parsed from "Upgrade to version 70.0.0"
    assert facts[102][1].fixed_version == "1.26.18"  # fix_version field
    assert facts[103][1].fixed_version == "1.26.17"  # "Upgrade to version: 1.26.17"
    assert f.asset_key == "defectdojo:payments-checkout:requirements.txt" and f.artifact == "payments-checkout"
    assert f.tags["env"] == "production" and f.tags["defectdojo-product-type"] == "Payments"
    sast = facts[104][1]
    assert (sast.kind, sast.rule_key, sast.path, sast.tags["team"]) == (
        "config", "defectdojo:Semgrep JSON Report/python.lang.security.audit.formatted-sql-query",
        "src/checkout/db.py", "data")
    assert facts[105][1].rule_key == "defectdojo:ZAP Scan/CWE-693"  # CWE when the tool has no rule id
    # false positive and risk accepted rows stay present, with the hint only
    assert facts[105][0]["unmapped"]["defectdojo"]["triage"] == "false_positive"
    assert facts[106][0]["unmapped"]["defectdojo"]["triage"] == "risk_accepted"


@pytest.mark.parametrize("doc", [
    {"results": []},
    [{"results": []}, {"results": []}],
    [],
])
def test_empty_and_paged_shapes(doc):
    r = parse(json.dumps(doc).encode())
    assert r.records == [] and r.default_scope == ""


def test_pages_and_plain_lists_are_read():
    rows = json.loads(scan(DAY1))["results"]
    paged = [{"results": rows[:3]}, {"results": rows[3:]}]
    assert len(parse(json.dumps(paged).encode()).records) == 6
    assert len(parse(json.dumps(rows).encode()).records) == 6


def test_without_related_fields_scope_is_left_to_the_caller():
    rows = json.loads(scan(DAY1))["results"]
    for r in rows:
        r.pop("related_fields")
    res = parse(json.dumps({"results": rows}).encode())
    assert res.default_scope == "" and extract_facts(res.records[0]).asset_key.startswith("defectdojo:unknown-product")


def test_rejects_other_json():
    with pytest.raises(AdapterError):
        parse(b'{"Results": []}')


def test_ingest_owners_grouping_and_closure(svc):
    r1 = svc.ingest("defectdojo", scan(DAY1))
    assert (r1.scope, r1.new, len(r1.skipped)) == ("defectdojo:payments-checkout", 6, 1)
    svc.rebuild()
    with svc.session() as s:
        by_id = {f.vuln_id or f.rule_key: f for f in s.scalars(select(Finding))}
        assert by_id["CVE-2024-6345"].owner_slug == "payments"  # pattern payments-* on the product
        assert by_id["defectdojo:Semgrep JSON Report/python.lang.security.audit.formatted-sql-query"].owner_slug \
            == "data"  # DefectDojo tag team:data
        urllib3 = s.get(WorkItem, by_id["CVE-2023-45803"].work_item_key)
        assert urllib3.title.startswith("Upgrade urllib3 to 1.26.18") and urllib3.priority == "Critical"  # prod bump

    r2 = svc.ingest("defectdojo", scan(DAY2))
    assert (r2.fixed, r2.new) == (2, 0)  # DefectDojo mitigated the two urllib3 findings
    with svc.session() as s:
        assert {f.vuln_id for f in s.scalars(select(Finding).where(Finding.status == "fixed"))} == \
            {"CVE-2023-45803", "CVE-2023-43804"}


# -- live pull ------------------------------------------------------------------


def dd_handler(seen: list[httpx.Request]):
    rows = json.loads(scan(DAY1))["results"]

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        assert req.headers["Authorization"] == "Token dd-test-token"
        if req.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"name": "payments-checkout"}, {"name": "legacy"}],
                                             "next": None})
        if req.url.path == "/api/v2/findings/":
            if req.url.params.get("product_name") == "legacy":
                return httpx.Response(200, json={"results": [], "next": None})
            if req.url.params.get("offset") == "3":
                return httpx.Response(200, json={"results": rows[3:], "next": None})
            assert req.url.params["related_fields"] == "true"
            return httpx.Response(200, json={"results": rows[:3],
                                             "next": "https://dojo.example.com/api/v2/findings/?offset=3"})
        return httpx.Response(404)

    return handler


def test_pull_ingests_each_product(svc):
    seen: list[httpx.Request] = []
    svc.settings.defectdojo_url, svc.settings.defectdojo_token = "https://dojo.example.com/", "dd-test-token"
    reports = svc.pull_defectdojo(transport=httpx.MockTransport(dd_handler(seen)))
    assert [(r.scope, r.findings_seen) for r in reports] == [("defectdojo:legacy", 0),
                                                             ("defectdojo:payments-checkout", 6)]
    assert all(req.method == "GET" for req in seen)  # read-only


def test_pull_refuses_foreign_next_link_and_plain_http(svc):
    def handler(req):
        return httpx.Response(200, json={"results": [], "next": "https://evil.example/api/v2/products/"})

    svc.settings.defectdojo_url, svc.settings.defectdojo_token = "https://dojo.example.com", "dd-test-token"
    with pytest.raises(ConnectorError, match="another host"):
        svc.pull_defectdojo(transport=httpx.MockTransport(handler))
    with pytest.raises(ConnectorError, match="https"):
        check_url("http://dojo.example.com")
    assert check_url("http://localhost:8080/") == "http://localhost:8080"
    svc.settings.defectdojo_token = ""
    with pytest.raises(ConnectorError, match="TOKEN"):
        svc.pull_defectdojo(["x"])
