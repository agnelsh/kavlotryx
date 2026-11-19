"""Console menus: persona dashboards, vulnerability explorer, CSV export, settings, redirects."""

from __future__ import annotations

import csv
import io
import re

import pytest
from fastapi.testclient import TestClient

from kavlotryx.api import create_app
from kavlotryx.web.pages import VulnFilter, csv_safe
from tests.conftest import scan
from tests.test_web import ADMIN, VIEW, csrf, login


@pytest.fixture
def app(day1):
    day1.settings.api_tokens = f"me:admin:{ADMIN},boss:viewer:{VIEW}"
    day1.settings.personas = "boss=security_manager"
    day1.run()
    return create_app(day1)


@pytest.fixture
def admin(app):
    c = TestClient(app, base_url="https://testserver")
    login(c, ADMIN)
    return c


@pytest.fixture
def viewer(app):
    c = TestClient(app, base_url="https://testserver")
    login(c, VIEW)
    return c


def test_nav_has_five_menus(admin):
    html = admin.get("/ui").text
    nav = re.search(r'<nav class="nav">(.*?)</nav>', html, re.S).group(1)
    assert re.findall(r'href="(/ui[^"]*)"', nav) == ["/ui", "/ui/vulnerabilities", "/ui/ownership",
                                                     "/ui/scanners", "/ui/settings"]


def test_default_persona_and_switch(admin, viewer):
    assert "Proof of progress against due dates" in viewer.get("/ui").text  # KAVLO_PERSONAS default
    assert "One prioritized queue across all scanners" in admin.get("/ui").text  # no default: analyst
    page = admin.get("/ui?persona=platform").text
    assert "Root-cause fixes, not single findings" in page and "Make this my default" in page
    r = admin.post("/ui/prefs", data={"csrf": csrf(page), "persona": "team_lead", "team": "payments"},
                   follow_redirects=True)
    assert "Only the work that belongs to my team" in r.text and "@payments" in r.text
    bad = admin.post("/ui/prefs", data={"csrf": csrf(page), "persona": "ceo"}, follow_redirects=True)
    assert "Unknown persona" in bad.text


def test_pipeline_status_on_every_persona(admin):
    for p in ("analyst", "team_lead", "platform", "security_manager", "change_manager"):
        html = admin.get(f"/ui?persona={p}").text
        assert "Pipeline Status" in html and "Microsoft Graph" in html and "LeanIX" in html


def test_change_manager_lists_production_items(admin):
    html = admin.get("/ui?persona=change_manager").text
    assert "Fixes that touch production" in html
    assert "Ensure S3 buckets have Block Public Access enabled" in html  # env=prod tag


def test_explorer_filters_and_facets(admin):
    all_open = admin.get("/ui/vulnerabilities").text
    assert "Matching</span><b class=\"mono\">10</b>" in all_open.replace("\n", "")
    crit_high = admin.get("/ui/vulnerabilities?sev=5&sev=4").text
    assert "severity: Critical, High" in crit_high
    prod = admin.get("/ui/vulnerabilities?prod=yes").text
    assert "acme-analytics-exports" in prod and "sg-0a1b2c3d4e5f60002" not in prod
    by_scanner = admin.get("/ui/vulnerabilities?scanner=prowler").text
    assert "prowler:ec2_securitygroup" in by_scanner and "CVE-2024-6119" not in by_scanner
    merged = admin.get("/ui/vulnerabilities?scanner=ocsf").text
    assert "CVE-2024-6119" in merged and "merged" in merged
    nofix = admin.get("/ui/vulnerabilities?fix=no").text
    assert "CVE-2023-45853" in nofix and "CVE-2024-6119" not in nofix
    rule = admin.get("/ui/vulnerabilities?rule=codeowners").text
    assert "CVE-2024-21538" in rule and "acme-analytics-exports" not in rule


def test_filter_query_round_trip():
    f = VulnFilter(sev=[5, 4], owner="payments", page=3)
    assert f.qs() == "sev=5&sev=4&owner=payments&page=3"
    assert "sev=4" in f.toggle_sev(5) and "sev=5" not in f.toggle_sev(5)
    assert [c[0] for c in f.chips()] == ["severity: Critical, High", "owner: payments"]


def test_csv_export_neutralises_formulas(admin, day1):
    evil = scan("trivy-repo-payments-api.json").replace(b"Image user should not be 'root'", b"=HYPERLINK(1)")
    day1.ingest("trivy", evil, scope="trivy:evil")
    day1.rebuild()
    r = admin.get("/ui/vulnerabilities.csv?kind=config")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "id" and len(rows) > 2
    assert csv_safe("=1+1") == "'=1+1" and csv_safe("-2") == "'-2" and csv_safe("ok") == "ok"
    assert not any(cell.startswith("=") for row in rows for cell in row)


def test_settings_policy_edit_is_admin_only_and_audited(admin, viewer, day1):
    page = admin.get("/ui/settings/policy").text
    form = {"csrf": csrf(page), "confidence_limit": "0.6", "due_critical": "3", "due_high": "14",
            "due_medium": "60", "due_low": "120", "dispatch_min_priority": "Medium", "production_tag_keys": "env",
            "production_values": "prod", "scan_stale_hours": "24"}
    r = admin.post("/ui/settings/policy", data=form, follow_redirects=True)
    assert "Saved" in r.text and "console · ui:me" in r.text
    p = day1.policy
    got = (p.confidence_limit, p.due_days["High"], p.dispatch_min_priority, p.scan_stale_hours)
    assert got == (0.6, 14, "Medium", 24)

    vpage = viewer.get("/ui/settings/policy").text
    assert "Only admins can change the policy" in vpage
    denied = viewer.post("/ui/settings/policy", data={**form, "csrf": csrf(vpage)}, follow_redirects=True)
    assert "viewer role cannot do this" in denied.text

    bad = admin.post("/ui/settings/policy", data={**form, "confidence_limit": "1.5"}, follow_redirects=True)
    assert "Not saved" in bad.text and day1.policy.confidence_limit == 0.6

    r = admin.post("/ui/settings/policy/reset", data={"csrf": csrf(page)}, follow_redirects=True)
    assert "Policy reset" in r.text and day1.policy.confidence_limit == 0.7


def test_settings_never_shows_secrets(admin, day1):
    day1.settings.jira_token = "jira-secret-value-123"
    day1.settings.graph_client_secret = "graph-secret-value-456"
    day1.settings.defectdojo_token = "dojo-secret-value-789"
    for tab in ("iam", "users", "policy", "connectors", "configuration"):
        html = admin.get(f"/ui/settings/{tab}").text
        for secret in ("jira-secret-value-123", "graph-secret-value-456", "dojo-secret-value-789", ADMIN):
            assert secret not in html, (tab, secret)
    assert "KAVLO_GRAPH_CLIENT_SECRET" in admin.get("/ui/settings/connectors").text


def test_settings_tabs(admin):
    r = admin.get("/ui/settings", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/ui/settings/iam"
    tabs = {"iam": ("Single Sign-On (OIDC)", "API Tokens"), "users": ("Users",),
            "policy": ("Remediation Policy",), "connectors": ("Ticket Tracker", "DefectDojo", "Ownership Connectors"),
            "configuration": ("Database", "audit_events", "0002")}
    for tab, words in tabs.items():
        html = admin.get(f"/ui/settings/{tab}").text
        nav = re.search(r'<nav class="tabs tabs-lg page-tabs" aria-label="Settings">(.*?)</nav>', html, re.S).group(1)
        assert re.findall(r">([A-Za-z ]+)</a>", nav) == ["IAM", "User Management", "Policy", "Connectors",
                                                         "Configuration"]
        assert f'href="/ui/settings/{tab}" aria-current="page"' in html
        for w in words:
            assert w in html, (tab, w)
    assert "Remediation policy" not in admin.get("/ui/settings/iam").text
    assert admin.get("/ui/settings/nope").status_code == 404


def test_old_urls_redirect(admin):
    r = admin.get("/ui/findings?f=1", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/ui/vulnerabilities/1"
    assert admin.get("/ui/findings?q=x", follow_redirects=False).headers["location"] == "/ui/vulnerabilities?q=x"
    assert admin.get("/ui/verify", follow_redirects=False).headers["location"] == "/ui/scanners"


def test_work_items_live_under_vulnerabilities(admin):
    html = admin.get("/ui/workitems").text
    assert "Work Items &amp; Tickets" in html
    assert re.search(r'href="/ui/vulnerabilities" class="active"|class="active"[^>]*href="/ui/vulnerabilities"', html)
