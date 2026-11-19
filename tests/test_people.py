"""People view (FR-OW-09): findings mapped to engineers and leaders from the Microsoft Graph cache."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from kavlotryx.api import create_app
from kavlotryx.config import ConnectorsConfig, GraphConnectorConfig, OwnershipConfig
from kavlotryx.core import people
from kavlotryx.db import DirectoryPerson, Finding, WorkItem, init_db
from tests.test_connectors import _wiz_issue, sample_owned  # noqa: F401  (fixture)
from tests.test_web import ADMIN, login

CFG = OwnershipConfig(owners=[{"slug": "app"}, {"slug": "platform"}, {"slug": "identity"}],
                      connectors=ConnectorsConfig(graph=GraphConnectorConfig(
                          group_map={"sg-app": "app", "sg-plat": "platform"})))


def person(pid, name, groups=(), leads=(), mgr="", upn=""):
    return DirectoryPerson(id=pid, display_name=name, upn=upn or f"{pid}@example.com", mail="", nickname=pid,
                           groups=list(groups), leads=list(leads), manager_id=mgr, job_title="")


def finding(n, owner, sev=3, evidence=None, tags=None, wi=""):
    return Finding(id=n, fingerprint=f"fp{n}", kind="config", class_uid=2003, asset_key=f"a{n}", owner_slug=owner,
                   severity_id=sev, owner_evidence=evidence or {}, tags=tags or {}, work_item_key=wi)


@pytest.fixture
def org(svc):
    with svc.session() as s:
        s.add_all([
            person("vp", "Avery"),
            person("em", "Priya", leads=["sg-app"], mgr="vp"),
            person("jd", "Jordan", groups=["sg-app"], mgr="em"),
            person("nk", "Noah", groups=["sg-app"], mgr="em"),
            person("sam", "Sam", groups=["sg-plat"], mgr="vp"),
            person("x1", "Loop A", mgr="x2"), person("x2", "Loop B", mgr="x1"),  # bad directory data
        ])
        s.add(WorkItem(key="wi_late", owner_slug="app", kind="config", title="t", state="dispatched",
                       due_date=date.today() - timedelta(days=2)))
        s.add_all([
            finding(1, "app", 5, evidence={"person": "jd@example.com"}, wi="wi_late"),
            finding(2, "app", 4),
            finding(3, "platform", 4, tags={"Owner": "SAM"}),
            finding(4, "identity", 2),
        ])
        s.commit()
        yield people.build(s, CFG)


def test_engineer_gets_named_and_team_findings(org):
    jd, nk = org.rows["jd"], org.rows["nk"]
    assert (jd.role, jd.named, jd.team, jd.teams) == ("engineer", {1}, {1, 2}, ["app"])
    assert (nk.named, nk.team) == (set(), {1, 2})
    assert (jd.stats.total, jd.stats.critical, jd.stats.high, jd.stats.overdue) == (2, 1, 1, 1)


def test_person_tag_names_engineer_without_graph_rule(org):
    assert org.rows["sam"].named == {3}  # tag Owner=SAM matches the nickname, case-insensitively


def test_leaders_roll_up_through_group_owners_and_managers(org):
    em, vp = org.rows["em"], org.rows["vp"]
    assert (em.role, em.leads, em.rollup) == ("leader", ["app"], {1, 2})
    assert (vp.role, vp.rollup, sorted(vp.reports)) == ("leader", {1, 2, 3}, ["em", "sam"])
    assert [p.id for p in org.chain("jd")] == ["em", "vp"]


def test_unreached_owners_and_totals(org):
    assert org.unreached == [{"owner": "identity", "findings": 1, "why": "no Entra group is mapped to this owner"}]
    assert (org.total_open, org.named_total, org.reached_total, org.led_total) == (4, 2, 3, 3)


def test_tree_order_and_manager_cycle(org):
    order = org.order
    assert order.index("vp") < order.index("em") < order.index("jd")
    assert {"x1", "x2"} <= set(order) and len(order) == len(set(order))
    assert org.chain("x1") == [org.rows["x2"].p]


def test_findings_for(svc, org):
    with svc.session() as s:
        assert people.findings_for(s, CFG, "vp") == {1, 2, 3}
        assert people.findings_for(s, CFG, "nk") == {1, 2}
        assert people.findings_for(s, CFG, "nobody") is None


def test_old_cache_table_is_recreated(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE directory_people (id VARCHAR(128) PRIMARY KEY, upn VARCHAR(320))"))
        c.execute(text("INSERT INTO directory_people VALUES ('u1', 'a@b')"))
    init_db(eng)
    with eng.connect() as c:
        cols = {r[1] for r in c.execute(text("PRAGMA table_info(directory_people)"))}
        assert {"manager_id", "leads", "job_title"} <= cols
        assert c.execute(text("SELECT count(*) FROM directory_people")).scalar() == 0  # refilled on next sync


# -- console, with the sample org chart -------------------------------------------------


@pytest.fixture
def console(sample_owned):  # noqa: F811
    sample_owned.settings.api_tokens = f"me:admin:{ADMIN}"
    sample_owned.ingest("wiz", _wiz_issue({"Owner": "JD"}))
    c = TestClient(create_app(sample_owned),
                   base_url="https://testserver")
    login(c, ADMIN)
    return sample_owned, c


def test_people_page_empty_until_graph_sync(console):
    _, c = console
    html = c.get("/ui/ownership/people").text
    assert "No People Synced Yet" in html and "Leaders &amp; Engineers" in html


def test_people_page_and_person_drilldown(console):
    k, c = console
    k.sync_connector("graph")
    html = c.get("/ui/ownership/people").text
    for name in ("Avery Brooks", "Priya Nair", "Jordan Diaz", "VP Engineering", "Dana Whitfield"):
        assert name in html
    assert html.index("Avery Brooks") < html.index("Priya Nair") < html.index("Jordan Diaz")

    jd = "11111111-0000-4000-8000-000000000001"
    page = c.get(f"/ui/ownership/people/{jd}").text
    assert "Senior Software Engineer" in page and "Publicly exposed VM on port 22" in page
    assert "Priya Nair" in page and "Avery Brooks" in page  # manager chain breadcrumb
    vp = c.get("/ui/ownership/people/11111111-0000-4000-8000-000000000009").text
    assert "Roll-up" in vp and "Direct Reports" in vp and "Publicly exposed VM on port 22" in vp

    listing = c.get(f"/ui/vulnerabilities?person={jd}").text
    assert "person: Jordan Diaz" in listing and "Publicly exposed VM" in listing
    assert f'name="person" value="{jd}"' in listing  # the filter form keeps the person on Apply
    nobody = c.get("/ui/vulnerabilities?person=11111111-0000-4000-8000-000000000010").text  # CISO: no identity group
    assert "Publicly exposed VM" not in nobody
    assert c.get("/ui/ownership/people/missing").status_code == 404


def test_ownership_has_people_tab(console):
    _, c = console
    html = c.get("/ui/ownership").text
    assert 'href="/ui/ownership/people"' in html and "Teams &amp; Rules" in html


def test_api_people(console):
    k, _ = console
    k.sync_connector("graph")
    from tests.test_web import VIEW

    k.settings.api_tokens = f"v:viewer:{VIEW}"
    body = TestClient(create_app(k)).get("/api/v1/people", headers={"Authorization": f"Bearer {VIEW}"}).json()
    rows = {r["name"]: r for r in body["people"]}
    assert rows["Jordan Diaz"]["named"] == 1 and rows["Jordan Diaz"]["manager_id"].endswith("000000000005")
    assert rows["Avery Brooks"]["role"] == "leader" and rows["Avery Brooks"]["rollup"] == 1
    assert body["total_open"] == 1 and body["reached_leader"] == 1
