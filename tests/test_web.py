"""Web console (FR-IF-04): sign-in, CSRF, roles, pages and actions."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from kavlotryx.api import create_app
from tests.conftest import scan

ADMIN = "admin-token-0123456789abcdef"
VIEW = "view-token-0123456789abcdef"
CI = "ci-token-0123456789abcdef00"


def login(client: TestClient, token: str):
    return client.post("/ui/login", data={"token": token, "next": "/ui"}, follow_redirects=False)


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


@pytest.fixture
def app(day1):
    day1.settings.api_tokens = f"me:admin:{ADMIN},boss:viewer:{VIEW},ci:ingest:{CI}"
    day1.run()
    return create_app(day1)


@pytest.fixture
def admin(app):
    c = TestClient(app, base_url="https://testserver")
    assert login(c, ADMIN).status_code == 303
    return c


def test_redirects_to_login(app):
    c = TestClient(app)
    r = c.get("/ui/vulnerabilities", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/ui/login")
    assert c.get("/", follow_redirects=False).headers["location"] == "/ui"


def test_bad_token_and_ingest_role(app):
    c = TestClient(app)
    assert "error=invalid" in login(c, "nope-nope-nope-nope").headers["location"]
    assert "error=role" in login(c, CI).headers["location"]


def test_cookie_is_hardened_and_holds_no_token(app):
    c = TestClient(app, base_url="https://testserver")
    r = login(c, ADMIN)
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie
    assert ADMIN not in cookie


PAGES = ["/ui", "/ui?persona=analyst", "/ui?persona=team_lead", "/ui?persona=platform",
         "/ui?persona=security_manager", "/ui?persona=change_manager", "/ui/vulnerabilities",
         "/ui/vulnerabilities?conf=review", "/ui/vulnerabilities?q=openssl&kind=vuln&sev=4&sev=5",
         "/ui/vulnerabilities?scanner=prowler&rule=tag&fix=no&ticket=yes&age=30&sort=first&dir=asc&size=25",
         "/ui/vulnerabilities?prod=yes&status=&wi_state=dispatched&account=123456789012&artifact=pay",
         "/ui/vulnerabilities/1", "/ui/vulnerabilities/1?tab=ocsf", "/ui/workitems",
         "/ui/workitems?state=dispatched", "/ui/ownership", "/ui/scanners", "/ui/settings"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_render(admin, path):
    r = admin.get(path)
    assert r.status_code == 200, r.text[:500]
    assert "KAVLO" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_workitem_detail_and_404(admin):
    page = admin.get("/ui/workitems").text
    key = re.search(r'href="/ui/workitems/(wi_[0-9a-f]+)"', page).group(1)
    r = admin.get(f"/ui/workitems/{key}")
    assert r.status_code == 200 and "Proof-of-Closure Timeline" in r.text and "kavlo-" in r.text
    assert admin.get("/ui/workitems/wi_missing").status_code == 404


def test_scanner_text_is_escaped(admin, day1):
    evil = scan("trivy-repo-payments-api.json").replace(b"Image user should not be 'root'",
                                                       b"<script>alert(1)</script>")
    day1.ingest("trivy", evil, scope="trivy:evil")
    day1.rebuild()
    r = admin.get("/ui/vulnerabilities?kind=config")
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_post_without_csrf_is_rejected(admin):
    assert admin.post("/ui/actions/rebuild", data={}).status_code == 403
    assert admin.post("/ui/actions/rebuild", data={"csrf": "0" * 40}).status_code == 403


def test_cross_origin_post_is_rejected(admin):
    token = csrf(admin.get("/ui").text)
    r = admin.post("/ui/actions/rebuild", data={"csrf": token}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_actions_flash_and_dry_run(admin, tracker):
    token = csrf(admin.get("/ui/workitems").text)
    r = admin.post("/ui/actions/rebuild", data={"csrf": token}, follow_redirects=True)
    assert "Rebuilt:" in r.text
    before = len(tracker.issues)
    r = admin.post("/ui/actions/dry-run", data={"csrf": token})
    assert "Dry Run: What Dispatch Would Do" in r.text
    assert len(tracker.issues) == before
    r = admin.post("/ui/actions/verify", data={"csrf": token}, follow_redirects=True)
    assert "Verify:" in r.text


def test_override_from_console(admin, day1):
    listing = admin.get("/ui/vulnerabilities?conf=review").text
    fid = int(re.search(r'href="/ui/vulnerabilities/(\d+)"', listing).group(1))
    page = admin.get(f"/ui/vulnerabilities/{fid}").text
    r = admin.post(f"/ui/vulnerabilities/{fid}/owner", data={"csrf": csrf(page), "owner": "platform",
                                                     "match": "asset", "reason": "confirmed"},
                   follow_redirects=True)
    assert "Owner set to platform" in r.text
    a = day1.explain(fid)
    assert (a.rule, a.confidence) == ("override:asset", 1.0)


def test_viewer_cannot_write(app):
    c = TestClient(app, base_url="https://testserver")
    login(c, VIEW)
    page = c.get("/ui/workitems")
    assert page.status_code == 200 and "Dry-run dispatch" not in page.text
    r = c.post("/ui/actions/dispatch", data={"csrf": csrf(page.text)}, follow_redirects=True)
    assert "viewer role cannot do this" in r.text


def test_upload_from_console(admin):
    token = csrf(admin.get("/ui/scanners").text)
    files = {"file": ("t.json", scan("trivy-payments-api-1.4.1.json"), "application/json")}
    r = admin.post("/ui/scans", data={"csrf": token, "scanner": "trivy"}, files=files, follow_redirects=True)
    assert "Scan 5 (trivy" in r.text
    bad = {"file": ("x.json", b"{oops", "application/json")}
    r = admin.post("/ui/scans", data={"csrf": token, "scanner": "trivy"}, files=bad, follow_redirects=True)
    assert "Rejected x.json" in r.text


def test_revoked_token_signs_out(app, admin):
    app.state.tokens = {h: p for h, p in app.state.tokens.items() if p.role != "admin"}
    assert admin.get("/ui", follow_redirects=False).status_code == 303


def test_logout(admin):
    token = csrf(admin.get("/ui").text)
    r = admin.post("/ui/logout", data={"csrf": token}, follow_redirects=False)
    assert r.headers["location"] == "/ui/login"
    assert admin.get("/ui", follow_redirects=False).status_code == 303


def test_insecure_mode_has_no_login(day1):
    c = TestClient(create_app(day1, insecure_no_auth=True))
    r = c.get("/ui")
    assert r.status_code == 200 and "auth off" in r.text
