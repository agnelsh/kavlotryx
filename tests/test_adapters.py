"""Golden-file tests for adapters (FR-IN-01..06)."""

from __future__ import annotations

import json

import pytest

from kavlotryx.adapters import AdapterError, get_adapter
from kavlotryx.core.fingerprint import fingerprint
from kavlotryx.ocsf import extract_facts
from kavlotryx.ocsf.extract import image_repository, normalize_repo, parse_tags
from tests.conftest import scan


def test_prowler_keeps_fail_rows_only():
    r = get_adapter("prowler").parse(scan("prowler-aws-day1.ocsf.json"))
    assert len(r.records) == 4  # the PASS row is not work
    assert r.default_scope == "prowler:aws:123456789012"
    assert {rec["class_uid"] for rec in r.records} == {2004}


def test_prowler_facts():
    rec = get_adapter("prowler").parse(scan("prowler-aws-day1.ocsf.json")).records[0]
    f = extract_facts(rec)
    assert f.kind == "config"
    assert f.scanner == "prowler"
    assert f.asset_key == "arn:aws:s3:::acme-analytics-exports"
    assert f.rule_key == "prowler:s3_bucket_level_public_access_block"
    assert f.account_uid == "123456789012"
    assert f.tags == {"team": "data-eng", "env": "prod"}
    assert f.severity_id == 4


def test_trivy_image_maps_to_ocsf():
    r = get_adapter("trivy").parse(scan("trivy-payments-api-1.4.0.json"))
    assert len(r.records) == 5
    assert r.default_scope == "trivy:ghcr.io/acme/payments-api"
    rec = r.records[0]
    assert rec["class_uid"] == 2002
    assert rec["metadata"]["version"] == "1.9.0"
    assert rec["vulnerabilities"][0]["cve"]["uid"] == "CVE-2024-5535"
    f = extract_facts(rec)
    assert f.asset_key == "sha256:" + "1" * 64
    assert f.artifact == "ghcr.io/acme/payments-api"
    assert f.repo == "github.com/acme/payments-api"
    assert f.src_package == "openssl"
    assert f.path == ""  # OS packages have no repo path
    npm = extract_facts(r.records[-1])
    assert npm.path == "app/package-lock.json"
    assert npm.fixed_version == "7.0.5"


def test_trivy_repo_misconfig_fail_only():
    r = get_adapter("trivy").parse(scan("trivy-repo-payments-api.json"))
    assert len(r.records) == 1
    f = extract_facts(r.records[0])
    assert f.class_uid == 2003
    assert f.rule_key == "trivy:AVD-DS-0002"
    assert f.asset_key == "git:github.com/acme/payments-api"
    assert f.path == "Dockerfile"


def test_cross_scanner_same_fingerprint():
    trivy = [extract_facts(r) for r in get_adapter("trivy").parse(scan("trivy-payments-api-1.4.0.json")).records]
    grype = extract_facts(get_adapter("ocsf").parse(scan("grype-payments-api-1.4.0.ocsf.json")).records[0])
    assert grype.artifact == "ghcr.io/acme/payments-api"
    assert fingerprint(grype) in {fingerprint(t) for t in trivy}


def test_ocsf_skips_unsupported_rows():
    rows = [{"class_uid": 3002, "resources": [{"uid": "x"}]}, {"class_uid": 2002}, "nope"]
    r = get_adapter("ocsf").parse(json.dumps(rows).encode())
    assert r.records == [] and len(r.skipped) == 3


def test_json_lines_accepted():
    rows = json.loads(scan("grype-payments-api-1.4.0.ocsf.json"))
    data = "\n".join(json.dumps(x) for x in rows * 2).encode()
    assert len(get_adapter("ocsf").parse(data).records) == 2


@pytest.mark.parametrize("data", [b"", b"{not json", b"[1, 2"])
def test_malformed_input_is_rejected(data):
    with pytest.raises(AdapterError):
        get_adapter("ocsf").parse(data)


def test_trivy_rejects_other_json():
    with pytest.raises(AdapterError):
        get_adapter("trivy").parse(b'{"foo": 1}')


def test_unknown_scanner():
    with pytest.raises(AdapterError, match="unknown scanner"):
        get_adapter("nessus")


def test_tag_shapes():
    assert parse_tags({"tags": [{"name": "team", "value": "a"}]}) == {"team": "a"}
    assert parse_tags({"labels": ["team:b", "env=prod"]}) == {"team": "b", "env": "prod"}
    assert parse_tags({"data": {"metadata": {"tags": {"owner": "c"}}}}) == {"owner": "c"}


def test_helpers():
    assert image_repository("ghcr.io/acme/api:1.2") == "ghcr.io/acme/api"
    assert image_repository("localhost:5000/api@sha256:ab") == "localhost:5000/api"
    assert normalize_repo("git@github.com:Acme/API.git") == "github.com/acme/api"
    assert normalize_repo("https://github.com/acme/api/") == "github.com/acme/api"
