"""Third-party sample data (DefectDojo test files) and relative filesystem scans.

The DefectDojo tests run only after ``hack/fetch-samples.sh`` has downloaded
the files; they are skipped otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from kavlotryx.config import Settings
from kavlotryx.db import Finding, WorkItem
from kavlotryx.dispatch.fake import FakeTracker
from kavlotryx.service import Kavlotryx
from tests.conftest import ROOT

SAMPLES = ROOT / "examples" / "samples" / "defectdojo"
ACCOUNT = "prowler:aws:123456789012"

needs_samples = pytest.mark.skipif(not (SAMPLES / "aws_prowler_v3plus").exists(),
                                   reason="run hack/fetch-samples.sh first")


def _fs_scan(path: str) -> bytes:
    return json.dumps({
        "ArtifactName": path, "ArtifactType": "filesystem",
        "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-33503", "PkgName": "urllib3", "InstalledVersion": "1.26.4",
             "FixedVersion": "1.26.5", "Severity": "HIGH"}]}],
    }).encode()


def test_relative_filesystem_scans_do_not_merge(svc):
    a = svc.ingest("trivy", _fs_scan("."), scope="trivy:checkout")
    b = svc.ingest("trivy", _fs_scan("."), scope="trivy:billing")
    assert (a.new, b.new) == (1, 1)
    with svc.session() as s:
        keys = sorted(f.asset_key for f in s.scalars(select(Finding)))
    assert keys == ["fs:trivy:billing", "fs:trivy:checkout"]


def test_relative_filesystem_scan_has_no_guessed_scope(svc):
    r = svc.ingest("trivy", _fs_scan("."))
    assert r.scope == "trivy"  # the CLI warns and asks for --scope


def test_absolute_filesystem_path_keeps_its_identity(svc):
    r = svc.ingest("trivy", _fs_scan("/srv/checkout"))
    assert r.scope == "trivy:/srv/checkout"
    with svc.session() as s:
        assert s.scalars(select(Finding.asset_key)).one() == "fs:/srv/checkout"


@pytest.fixture
def sample_svc(tmp_path: Path) -> Kavlotryx:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 's.db'}",
                        config_dir=ROOT / "examples" / "samples" / "config", tracker="fake")
    return Kavlotryx(settings, tracker=FakeTracker())


def _states(svc: Kavlotryx) -> dict[str, str]:
    with svc.session() as s:
        return {w.title.split(" (")[0]: w.state for w in s.scalars(select(WorkItem))}


@needs_samples
def test_defectdojo_prowler_story(sample_svc):
    svc = sample_svc
    p = SAMPLES / "aws_prowler_v3plus"
    assert svc.ingest("prowler", (p / "many_vuln.ocsf.json").read_bytes(), scope=ACCOUNT).new == 3
    # Prowler 4.5 output format: same findings, no duplicates.
    assert svc.ingest("prowler", (p / "many_vuln_after_4_5_0.ocsf.json").read_bytes(), scope=ACCOUNT).new == 0
    out = svc.run()
    assert out["dispatch"]["create"] == 3
    assert {svc.explain(i).rule for i in (1, 2, 3)} == {"pattern:iam-roles"}

    day2 = svc.ingest("prowler", (p / "one_vuln.ocsf.json").read_bytes(), scope=ACCOUNT)
    assert day2.fixed == 2
    assert svc.run()["verify"]["verified"] == 2

    day3 = svc.ingest("prowler", (p / "no_vuln.ocsf.json").read_bytes(), scope=ACCOUNT)
    assert day3.fixed == 1
    svc.run()
    assert set(_states(svc).values()) == {"verified"}


@needs_samples
def test_defectdojo_trivy_samples_route_by_codeowners(sample_svc):
    svc = sample_svc
    svc.ingest("trivy", (SAMPLES / "trivy" / "scheme_2_many_vulns.json").read_bytes())
    svc.rebuild()
    with svc.session() as s:
        owners = {f.package: (f.owner_slug, f.owner_rule) for f in s.scalars(select(Finding))}
    assert owners["libbz2"] == ("platform", "codeowners")  # OS package -> /Dockerfile line
    assert owners["org.apache.commons:commons-compress"] == ("app", "codeowners")  # app/libs/ -> /app/
