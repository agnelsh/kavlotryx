"""Public demo mode: anonymous visitors read everything and change nothing."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from kavlotryx.api import create_app
from kavlotryx.db import AuditEvent, Finding, UserPref
from tests.conftest import scan
from tests.test_web import ADMIN, csrf, login

PUBLIC = "https://demo.example.com"
PAGES = ["/ui", "/ui?persona=platform", "/ui/vulnerabilities", "/ui/workitems", "/ui/triage", "/ui/triage/report",
         "/ui/ownership", "/ui/ownership/people", "/ui/scanners", "/ui/settings/iam", "/ui/settings/policy",
         "/ui/settings/configuration"]


@pytest.fixture
def demo(day1):
    day1.settings.demo_mode = True
    day1.settings.public_url = PUBLIC
    day1.settings.api_tokens = f"me:admin:{ADMIN}"
    day1.run()
    return day1, create_app(day1)


def visitor(app) -> TestClient:
    # The proxy talks plain HTTP to the container; the browser's origin is the public URL.
    return TestClient(app, base_url="http://container", headers={"origin": PUBLIC})


def state(k) -> tuple[int, list[tuple[int, str]]]:
    with k.session() as s:
        events = s.scalar(select(func.count(AuditEvent.id)))
        statuses = [(f.id, f.status, f.owner_slug) for f in s.scalars(select(Finding).order_by(Finding.id))]
    return events, statuses


def test_visitor_sees_every_page_with_the_banner(demo):
    _, app = demo
    c = visitor(app)
    for path in PAGES:
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 200, path
        assert "Public demo." in r.text and 'href="/ui/login?next=' in r.text
        assert 'action="/ui/logout"' not in r.text
    assert "visitor" in c.get("/ui").text
    assert f"{PUBLIC}/api/v1/scans" in c.get("/ui/scanners").text  # snippets use the public address


def test_visitor_cannot_change_anything(demo):
    k, app = demo
    c = visitor(app)
    fid = state(k)[1][0][0]
    page = c.get(f"/ui/vulnerabilities/{fid}").text
    assert "Propose decision" not in page and "Apply override" not in page and 'name="csrf"' not in page
    token = csrf(c.get("/ui").text)  # the persona form is the only one a visitor sees
    before = state(k)
    posts = [
        ("/ui/actions/run", {}), ("/ui/actions/rebuild", {}), ("/ui/actions/dispatch", {}),
        (f"/ui/vulnerabilities/{fid}/owner", {"owner": "platform"}),
        ("/ui/triage", {"kind": "false_positive", "finding_ids": str(fid), "reason": "visitor tries this"}),
        (f"/ui/notes/finding/{fid}", {"body": "hello"}),
        ("/ui/settings/policy", {"confidence_limit": "0.1", "due_critical": "1", "due_high": "1", "due_medium": "1",
                                 "due_low": "1", "dispatch_min_priority": "Low", "scan_stale_hours": "1"}),
        ("/ui/settings/policy/reset", {}), ("/ui/connectors/graph/sync", {}), ("/ui/settings/users/1",
                                                                              {"action": "deactivate"}),
        ("/ui/triage/1/approve", {}),
    ]
    for url, data in posts:
        r = c.post(url, data={"csrf": token, **data}, follow_redirects=True)
        assert "viewer role cannot do this" in r.text, url
    up = c.post("/ui/scans", data={"csrf": token, "scanner": "trivy"},
                files={"file": ("t.json", scan("trivy-payments-api-1.4.1.json"))}, follow_redirects=True)
    assert "viewer role cannot do this" in up.text
    assert state(k) == before


def test_visitor_persona_choice_is_not_stored(demo):
    k, app = demo
    c = visitor(app)
    r = c.post("/ui/prefs", data={"csrf": csrf(c.get("/ui").text), "persona": "platform"}, follow_redirects=False)
    assert r.headers["location"] == "/ui?persona=platform"
    with k.session() as s:
        assert s.scalars(select(UserPref)).all() == []


def test_api_stays_closed_and_admin_can_still_sign_in(demo):
    k, app = demo
    assert TestClient(app).get("/api/v1/findings").status_code == 401
    r = login(visitor(app), ADMIN)
    cookie = r.headers["set-cookie"]
    assert r.status_code == 303 and "Secure" in cookie  # https public URL, even behind an http proxy
    session_cookie = cookie.split(";", 1)[0]

    def admin(origin: str) -> TestClient:
        return TestClient(app, base_url="http://container", headers={"origin": origin, "cookie": session_cookie})

    page = admin(PUBLIC).get("/ui").text
    assert "Public demo." in page and 'action="/ui/logout"' in page
    r = admin(PUBLIC).post("/ui/actions/rebuild", data={"csrf": csrf(page)}, follow_redirects=True)
    assert "Rebuilt" in r.text  # Origin is the public URL, Host is the container: accepted
    assert admin("https://evil.example").post("/ui/actions/rebuild", data={"csrf": csrf(page)}).status_code == 403


def test_demo_needs_no_tokens_and_refuses_insecure_mode(day1):
    day1.settings.demo_mode = True
    day1.settings.api_tokens = ""
    app = create_app(day1)
    assert TestClient(app).get("/ui").status_code == 200
    assert TestClient(app).get("/api/v1/findings").status_code == 401
    with pytest.raises(RuntimeError, match="every demo visitor an admin"):
        create_app(day1, insecure_no_auth=True)


def test_demo_off_still_requires_sign_in(day1):
    day1.settings.api_tokens = f"me:admin:{ADMIN}"
    r = TestClient(create_app(day1)).get("/ui", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/ui/login")
