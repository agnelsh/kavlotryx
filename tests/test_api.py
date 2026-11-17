"""REST API and token roles (FR-IF-01, NFR-SEC-01)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kavlotryx.api import create_app
from kavlotryx.api.auth import parse_tokens
from tests.conftest import scan

ADMIN = "admin-token-0123456789abcdef"
CI = "ci-token-0123456789abcdef00"
VIEW = "view-token-0123456789abcdef"


@pytest.fixture
def client(svc):
    svc.settings.api_tokens = f"me:admin:{ADMIN},ci:ingest:{CI},boss:viewer:{VIEW}"
    return TestClient(create_app(svc))


def h(token):
    return {"Authorization": f"Bearer {token}"}


def test_no_tokens_refuses_to_start(svc):
    with pytest.raises(RuntimeError, match="no API tokens"):
        create_app(svc)


def test_bad_token_spec():
    with pytest.raises(ValueError):
        parse_tokens("me:root:0123456789abcdef")
    with pytest.raises(ValueError):
        parse_tokens("me:admin:short")


def test_health_is_open(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_auth_required(client):
    assert client.get("/api/v1/findings").status_code == 401
    assert client.get("/api/v1/findings", headers=h("wrong-token-xxxxxxxxxxxx")).status_code == 401


def test_full_flow(client, tracker):
    files = {"file": ("t.json", scan("trivy-payments-api-1.4.0.json"), "application/json")}
    r = client.post("/api/v1/scans", data={"scanner": "trivy"}, files=files, headers=h(CI))
    assert r.status_code == 201, r.text
    assert r.json()["new"] == 5

    # ingest role cannot trigger dispatch; viewer cannot either
    assert client.post("/api/v1/run", headers=h(CI)).status_code == 403
    assert client.post("/api/v1/run", headers=h(VIEW)).status_code == 403

    run = client.post("/api/v1/run", headers=h(ADMIN)).json()
    assert run["dispatch"]["create"] == 2

    rows = client.get("/api/v1/findings", headers=h(VIEW)).json()
    assert len(rows) == 5 and rows[0]["owner"]["slug"] in {"platform", "payments"}
    fid = rows[0]["id"]
    detail = client.get(f"/api/v1/findings/{fid}", headers=h(VIEW)).json()
    assert detail["sources"][0]["scanner"] == "trivy"
    exp = client.get(f"/api/v1/findings/{fid}/owner/explain", headers=h(VIEW)).json()
    assert exp["trace"][0]["rule"] == "override"

    bad = client.put(f"/api/v1/findings/{fid}/owner", json={"owner": "ghost"}, headers=h(ADMIN))
    assert bad.status_code == 422
    ok = client.put(f"/api/v1/findings/{fid}/owner", json={"owner": "data", "reason": "test"},
                    headers=h(ADMIN))
    assert ok.status_code == 200

    items = client.get("/api/v1/workitems", headers=h(VIEW)).json()
    assert any(i["ticket"] for i in items)
    summary = client.get("/api/v1/reports/summary", headers=h(VIEW)).json()
    assert summary["findings"]["open"] == 5
    assert summary["metrics"]["noise_reduction"] == 2.5


def test_bad_upload(client):
    files = {"file": ("x.json", b"{oops", "application/json")}
    r = client.post("/api/v1/scans", data={"scanner": "trivy"}, files=files, headers=h(CI))
    assert r.status_code == 422


def test_upload_limit(client, svc):
    svc.settings.max_upload_mb = 0
    app = create_app(svc)
    c = TestClient(app)
    files = {"file": ("t.json", b"[]", "application/json")}
    r = c.post("/api/v1/scans", data={"scanner": "ocsf"}, files=files, headers=h(CI))
    assert r.status_code == 413


def test_openapi(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/v1/findings/{finding_id}/owner/explain" in paths
