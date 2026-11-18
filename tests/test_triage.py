"""Triage: risk acceptance (FR-IF-06), false positives (FR-IF-07), notes (FR-IF-08), audit report (FR-IF-09)."""

from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kavlotryx.api import create_app
from kavlotryx.core import triage
from kavlotryx.db import AuditEvent, Finding, TriageDecision, WorkItem, utcnow
from tests.conftest import scan
from tests.test_web import ADMIN, VIEW, csrf, login

TODAY = utcnow().date()  # the code works in UTC
OTHER = "other-admin-token-0123456789ab"
ANALYST = "analyst-token-0123456789abcdef"


def open_ids(svc, **where) -> list[int]:
    with svc.session() as s:
        q = select(Finding).where(Finding.status == "open")
        for k, v in where.items():
            q = q.where(getattr(Finding, k) == v)
        return [f.id for f in s.scalars(q.order_by(Finding.id))]


def status(svc, fid: int) -> str:
    with svc.session() as s:
        return s.get(Finding, fid).status


@pytest.fixture
def ran(day1):
    day1.run()
    return day1


def item_of(svc, fid: int) -> WorkItem:
    with svc.session() as s:
        return s.get(WorkItem, s.get(Finding, fid).work_item_key)


# -- lifecycle -----------------------------------------------------------------


def test_risk_acceptance_needs_expiry_controls_and_a_second_person(ran):
    fid = open_ids(ran, kind="vuln")[0]
    with pytest.raises(triage.TriageError, match="expiry"):
        ran.triage_propose("risk_acceptance", [fid], "Legacy box, replaced in Q1", "alice")
    with pytest.raises(triage.TriageError, match="at most"):
        ran.triage_propose("risk_acceptance", [fid], "Legacy box, replaced in Q1", "alice", controls="WAF",
                           expires_on=TODAY + timedelta(days=400))
    with pytest.raises(triage.TriageError, match="controls"):
        ran.triage_propose("risk_acceptance", [fid], "Legacy box, replaced in Q1", "alice",
                           expires_on=TODAY + timedelta(days=10))
    with pytest.raises(triage.TriageError, match="10 characters"):
        ran.triage_propose("false_positive", [fid], "nope", "alice")

    d = ran.triage_propose("risk_acceptance", [fid], "Legacy box, replaced in Q1", "alice", controls="WAF rule 12",
                           expires_on=TODAY + timedelta(days=10), can_approve=True)
    assert d["state"] == "proposed" and status(ran, fid) == "open"  # four eyes: admin proposal waits
    with pytest.raises(triage.TriageError, match="four eyes"):
        ran.triage_decide(d["id"], "approve", "alice")
    with pytest.raises(triage.TriageError, match="live decision"):
        ran.triage_propose("false_positive", [fid], "Scanner misreads the version", "bob")
    assert ran.triage_decide(d["id"], "approve", "bob", "ok for 10 days")["state"] == "active"
    assert status(ran, fid) == "accepted" and fid not in open_ids(ran)


def test_triage_closes_and_expiry_reopens_the_ticket(ran, tracker):
    w = item_of(ran, open_ids(ran, kind="vuln")[0])
    assert w.ticket_key and w.state == "dispatched"
    d = ran.triage_propose_work_item(w.key, "risk_acceptance", "Vendor patch due next sprint", "alice",
                                     controls="Not reachable from the internet", expires_on=TODAY + timedelta(days=5))
    ran.triage_decide(d["id"], "approve", "bob")
    out = ran.run()
    assert out["verify"]["triaged"] == 1
    with ran.session() as s:
        w2 = s.get(WorkItem, w.key)
    assert w2.state == "triaged" and tracker.status(w.ticket_key) == "done"
    assert "Closing as triaged, not as fixed" in tracker.issues[w.ticket_key]["comments"][-1]

    with ran.session() as s:  # the expiry date comes
        assert triage.expire_due(s, today=TODAY + timedelta(days=5)) == 1
    out = ran.run()
    with ran.session() as s:
        w3 = s.get(WorkItem, w.key)
        assert s.get(TriageDecision, d["id"]).state == "expired"
    assert w3.state == "dispatched" and tracker.status(w.ticket_key) == "new"
    assert "a triage decision ended" in tracker.issues[w.ticket_key]["comments"][-1]


def test_false_positive_survives_rescans_and_a_clean_scan_still_fixes(day1):
    day1.run()
    with day1.session() as s:
        rule = "prowler:s3_bucket_level_public_access_block"
        fid = s.scalars(select(Finding.id).where(Finding.rule_key == rule)).one()
    d = day1.triage_propose("false_positive", [fid], "Bucket is public by design: static website", "alice")
    day1.triage_decide(d["id"], "approve", "bob")
    day1.ingest("prowler", scan("prowler-aws-day1.ocsf.json"))  # reported again: stays triaged
    assert status(day1, fid) == "false_positive"
    day1.ingest("prowler", scan("prowler-aws-day2.ocsf.json"))  # no longer reported: fixed, although triaged
    assert status(day1, fid) == "fixed"
    day1.ingest("prowler", scan("prowler-aws-day1.ocsf.json"))  # it returns: back under its decision
    assert status(day1, fid) == "false_positive"
    day1.triage_decide(d["id"], "revoke", "carol", "Website moved to CloudFront")
    assert status(day1, fid) == "open"


def test_reject_and_withdraw_change_nothing(ran):
    fid = open_ids(ran)[0]
    d = ran.triage_propose("false_positive", [fid], "Looks like a test fixture", "alice")
    with pytest.raises(triage.TriageError):
        ran.triage_decide(d["id"], "reject", "bob", "")
    assert ran.triage_decide(d["id"], "reject", "bob", "It is production code")["state"] == "rejected"
    d2 = ran.triage_propose("false_positive", [fid], "Second try with evidence", "alice")
    assert ran.triage_decide(d2["id"], "revoke", "alice", "withdrawn")["state"] == "revoked"
    assert status(ran, fid) == "open"
    with ran.session() as s:
        s.get(Finding, fid).status = "fixed"
        s.commit()
    with pytest.raises(triage.TriageError, match="only open"):
        ran.triage_propose("false_positive", [fid], "Too late, it is fixed", "alice")


def test_four_eyes_off_lets_an_admin_self_approve_and_the_report_warns(ran):
    ran.set_policy({"triage_four_eyes": False}, "admin")
    fid = open_ids(ran)[0]
    d = ran.triage_propose("false_positive", [fid], "Duplicate of a vendor advisory", "alice", can_approve=True)
    assert d["state"] == "active" and status(ran, fid) == "false_positive"
    rep = ran.triage_report(TODAY - timedelta(days=1), TODAY, "auditor")
    sod = next(c for c in rep["controls"] if c["name"] == "Segregation of duties")
    assert sod["status"] == "warn" and sod["items"] == [d["id"]]


def test_notes_are_append_only_and_audited(ran):
    fid = open_ids(ran)[0]
    w = item_of(ran, fid)
    ran.add_note("finding", str(fid), "alice", "Asked the team on Slack")
    ran.add_note("work_item", w.key, "bob", "Fix scheduled for Friday")
    with pytest.raises(triage.TriageError, match="not found"):
        ran.add_note("finding", "999999", "alice", "x")
    with pytest.raises(triage.TriageError):
        ran.add_note("scan", "1", "alice", "x")
    with ran.session() as s:
        assert [n.body for n in triage.notes_for(s, "finding", str(fid))] == ["Asked the team on Slack"]
        assert s.scalars(select(AuditEvent).where(AuditEvent.action == "note.add")).all()


def test_report_register_checks_and_digest(ran):
    ids = open_ids(ran)
    ra = ran.triage_propose("risk_acceptance", ids[:2], "Accepted until the vendor ships 2.0", "alice",
                            controls="Network isolation", reference="GRC-42", expires_on=TODAY + timedelta(days=7))
    ran.triage_decide(ra["id"], "approve", "bob", "approved in CAB")
    fp = ran.triage_propose("false_positive", ids[2:3], "Scanner reads the wrong package", "alice")
    ran.add_note("decision", str(fp["id"]), "bob", "Waiting for the scanner vendor reply")
    rep = ran.triage_report(TODAY - timedelta(days=30), TODAY, "auditor")
    assert [x["id"] for x in rep["risk_acceptances"]] == [ra["id"]]
    x = rep["risk_acceptances"][0]
    assert (x["four_eyes"], x["reference"], x["finding_count"], x["decided_by"]) == (True, "GRC-42", 2, "bob")
    assert rep["false_positives"][0]["state"] == "proposed"
    checks = {c["name"]: c["status"] for c in rep["controls"]}
    assert checks["Segregation of duties"] == checks["Audit trail"] == checks["Status integrity"] == "pass"
    assert checks["Expiring soon"] == "warn"
    assert {e["action"] for e in rep["events"]} >= {"triage.propose", "triage.approve", "note.add"}
    body = {k: v for k, v in rep.items() if k != "digest"}
    assert rep["digest"] == triage.digest(json.loads(json.dumps(body, default=str)))
    rows = triage.register_rows(rep)
    assert len(rows) == 2 and len(rows[0]) == len(triage.REGISTER_COLUMNS)
    old = ran.triage_report(TODAY - timedelta(days=400), TODAY - timedelta(days=300), "auditor")
    assert old["summary"]["decisions"] == 0


def test_defectdojo_hints_become_suggestions_not_decisions(svc):
    svc.ingest("defectdojo", scan("defectdojo-payments-checkout.json"))
    svc.rebuild()
    with svc.session() as s:
        sug = triage.suggestions(s)
        assert {(x["dd_id"], x["kind"]) for x in sug} == {(105, "false_positive"), (106, "risk_acceptance")}
        assert all(x["f"].status == "open" for x in sug)
        assert s.scalars(select(TriageDecision)).all() == []


# -- console and API -----------------------------------------------------------


@pytest.fixture
def clients(ran):
    ran.settings.api_tokens = f"me:admin:{ADMIN},boss:viewer:{VIEW},second:admin:{OTHER},ana:analyst:{ANALYST}"
    app = create_app(ran)
    out = {}
    for name, tok in (("me", ADMIN), ("second", OTHER), ("viewer", VIEW), ("ana", ANALYST)):
        c = TestClient(app, base_url="https://testserver")
        login(c, tok)
        out[name] = c
    return ran, out


def test_console_propose_approve_report(clients):
    k, c = clients
    fid = open_ids(k, kind="vuln")[0]
    page = c["ana"].get(f"/ui/vulnerabilities/{fid}").text
    assert 'id="triage"' in page and "Notes" in page
    r = c["ana"].post("/ui/triage", data={"csrf": csrf(page), "kind": "false_positive", "finding_ids": str(fid),
                                          "reason": "Package is vendored but never imported"},
                      follow_redirects=True)
    assert "is proposed" in r.text
    did = int(re.search(r"/ui/triage/(\d+)", str(r.url)).group(1))
    assert "Approve decision" not in r.text  # analysts cannot approve
    d_page = c["me"].get(f"/ui/triage/{did}").text
    r = c["me"].post(f"/ui/triage/{did}/approve", data={"csrf": csrf(d_page), "note": "checked imports"},
                     follow_redirects=True)
    assert "is active" in r.text and status(k, fid) == "false_positive"

    tri = c["viewer"].get("/ui/triage").text
    assert f"#{did}" in tri and "Triage" in tri
    rep = c["viewer"].get("/ui/triage/report").text
    assert "Risk acceptance register" in rep and "Package is vendored" in rep and "sha256:" in rep
    js = c["viewer"].get("/ui/triage/report.json")
    assert js.headers["x-report-digest"] == js.json()["digest"]
    csv_text = c["viewer"].get("/ui/triage/report.csv").text
    assert csv_text.splitlines()[0].startswith("decision,kind,state")
    note_page = c["me"].get(f"/ui/triage/{did}").text
    r = c["me"].post(f"/ui/notes/decision/{did}", data={"csrf": csrf(note_page), "body": "Re-check after upgrade"},
                     follow_redirects=True)
    assert "Re-check after upgrade" in r.text
    listing = c["me"].get("/ui/vulnerabilities?status=false_positive").text
    assert f'href="/ui/vulnerabilities/{fid}"' in listing


def test_console_four_eyes_and_viewer(clients):
    k, c = clients
    fid = open_ids(k)[0]
    page = c["me"].get(f"/ui/vulnerabilities/{fid}").text
    r = c["me"].post("/ui/triage", data={"csrf": csrf(page), "kind": "risk_acceptance", "finding_ids": str(fid),
                                         "reason": "Compensated by the WAF", "controls": "WAF",
                                         "expires_on": (TODAY + timedelta(days=3)).isoformat()},
                     follow_redirects=True)
    did = int(re.search(r"/ui/triage/(\d+)", str(r.url)).group(1))
    assert "another admin approves" in r.text and "Approve decision" not in r.text
    r = c["me"].post(f"/ui/triage/{did}/approve", data={"csrf": csrf(r.text)}, follow_redirects=True)
    assert "four eyes" in r.text and status(k, fid) == "open"
    vp = c["viewer"].get(f"/ui/triage/{did}")
    r = c["viewer"].post(f"/ui/triage/{did}/revoke", data={"csrf": csrf(vp.text), "note": "x"},
                         follow_redirects=True)
    assert "cannot do this" in r.text
    w = item_of(k, open_ids(k)[-1])
    wp = c["ana"].get(f"/ui/workitems/{w.key}").text
    assert "Propose decision" in wp and 'name="work_item"' in wp


def test_api_triage(clients):
    k, _ = clients
    api = TestClient(create_app(k))
    h = {"Authorization": f"Bearer {ANALYST}"}
    fid = open_ids(k)[0]
    r = api.post("/api/v1/triage/decisions", headers=h,
                 json={"kind": "false_positive", "finding_ids": [fid], "reason": "Test data only, not shipped"})
    assert r.status_code == 201, r.text
    did = r.json()["id"]
    assert api.post(f"/api/v1/triage/decisions/{did}/approve", headers=h, json={}).status_code == 403
    ok = api.post(f"/api/v1/triage/decisions/{did}/approve", headers={"Authorization": f"Bearer {OTHER}"}, json={})
    assert ok.json()["state"] == "active"
    assert api.post(f"/api/v1/notes/finding/{fid}", headers=h, json={"body": "see #12"}).status_code == 201
    assert api.get(f"/api/v1/notes/finding/{fid}", headers=h).json()[0]["body"] == "see #12"
    assert api.get(f"/api/v1/triage/decisions/{did}", headers=h).json()["findings"][0]["status"] == "false_positive"
    rep = api.get("/api/v1/reports/triage", headers=h).json()
    assert rep["summary"]["false_positives"] == 1 and rep["digest"].startswith("sha256:")
    bad = api.post("/api/v1/triage/decisions", headers=h, json={"kind": "nope", "finding_ids": [fid],
                                                                 "reason": "xxxxxxxxxxxx"})
    assert bad.status_code == 422
    assert api.get("/api/v1/triage/decisions/9999", headers=h).status_code == 404


def test_settings_edit_triage_policy(clients):
    k, c = clients
    page = c["me"].get("/ui/settings/policy").text
    assert 'name="acc_critical"' in page and 'name="triage_four_eyes"' in page
    form = {"csrf": csrf(page), "confidence_limit": "0.7", "due_critical": "7", "due_high": "30",
            "due_medium": "90", "due_low": "180", "dispatch_min_priority": "Low", "production_tag_keys": "env",
            "production_values": "prod", "scan_stale_hours": "48",
            "acc_critical": "14", "acc_high": "60", "acc_medium": "120", "acc_low": "200"}  # four eyes unticked
    r = c["me"].post("/ui/settings/policy", data=form, follow_redirects=True)
    assert "Saved" in r.text
    assert (k.policy.acceptance_max_days["Critical"], k.policy.triage_four_eyes) == (14, False)
