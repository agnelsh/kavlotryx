"""Microsoft Graph and LeanIX connectors (FR-EN-06) and the rules that use them."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from kavlotryx.config import ConnectorsConfig, GraphConnectorConfig, LeanixConnectorConfig, OwnershipConfig
from kavlotryx.connectors import ConnectorError, connector_mode
from kavlotryx.connectors.graph import GraphClient
from kavlotryx.connectors.leanix import LeanixClient
from kavlotryx.db import CatalogApp, ConnectorRun, DirectoryPerson, Finding

GRAPH = "https://graph.microsoft.com/v1.0"


# -- Microsoft Graph client -------------------------------------------------------------


def graph_handler(calls: list[str]):
    def h(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        calls.append(url)
        if url.startswith("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"):
            body = dict(x.split("=") for x in req.content.decode().split("&"))
            assert body["grant_type"] == "client_credentials" and "graph.microsoft.com" in body["scope"]
            return httpx.Response(200, json={"access_token": "tok"})
        assert req.headers["authorization"] == "Bearer tok"
        if "/groups?" in url and "sg-app-team" in url:
            return httpx.Response(200, json={"value": [{"id": "g1", "displayName": "sg-app-team"}]})
        if "/groups?" in url:
            return httpx.Response(200, json={"value": []})
        if "/groups/g1/transitiveMembers" in url and "skiptoken" not in url:
            return httpx.Response(200, json={"value": [{"id": "u1", "userPrincipalName": "JD@example.com",
                                                        "mailNickname": "JD", "displayName": "Jordan Diaz"}],
                                             "@odata.nextLink": f"{GRAPH}/groups/g1/transitiveMembers?skiptoken=2"})
        if "skiptoken=2" in url:
            return httpx.Response(200, json={"value": [{"id": "u2", "mail": "sam@example.com",
                                                        "displayName": "Sam"}]})
        return httpx.Response(404)
    return h


def ownership_cfg(**graph) -> OwnershipConfig:
    return OwnershipConfig(owners=[{"slug": "app", "jira_project": "APP"}, {"slug": "platform"},
                                   {"slug": "identity"}],
                           connectors=ConnectorsConfig(graph=GraphConnectorConfig(**graph)))


def test_graph_sync_reads_mapped_groups_with_paging(svc):
    calls: list[str] = []
    client = GraphClient("contoso.onmicrosoft.com", "cid", "secret",
                         transport=httpx.MockTransport(graph_handler(calls)), sleep=lambda _: None)
    cfg = ownership_cfg(group_map={"sg-app-team": "app", "sg-missing": "platform"})
    from kavlotryx.connectors.graph import sync_graph

    with svc.session() as s:
        run = sync_graph(s, svc.settings, cfg, actor="t", client=client)
        people = {p.id: p for p in s.scalars(select(DirectoryPerson))}
    assert run.status == "ok" and run.counts == {"people": 2, "groups": 1, "groups_not_found": ["sg-missing"]}
    assert people["u1"].upn == "jd@example.com" and people["u1"].nickname == "jd"
    assert set(people["u2"].groups) >= {"sg-app-team", "g1"}
    assert sum("oauth2/v2.0/token" in c for c in calls) == 1  # token reused


def test_graph_refuses_foreign_next_link():
    def h(req):
        if "login.microsoftonline.com" in str(req.url):
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/steal"})
    c = GraphClient("contoso.onmicrosoft.com", "a", "b", transport=httpx.MockTransport(h))
    with pytest.raises(ConnectorError, match="outside graph.microsoft.com"):
        c.get_all(f"{GRAPH}/groups")


@pytest.mark.parametrize("tenant", ["", "evil.example/../x", "a b", "x?y"])
def test_graph_rejects_bad_tenant(tenant):
    with pytest.raises(ConnectorError):
        GraphClient(tenant, "a", "b")


def test_graph_http_error_is_recorded(svc):
    def h(req):
        return httpx.Response(401, text="invalid_client")
    client = GraphClient("contoso.onmicrosoft.com", "a", "b", transport=httpx.MockTransport(h))
    from kavlotryx.connectors.graph import sync_graph

    with svc.session() as s, pytest.raises(ConnectorError, match="HTTP 401"):
        sync_graph(s, svc.settings, ownership_cfg(group_map={"sg-app-team": "app"}), client=client)
    with svc.session() as s:
        run = s.scalars(select(ConnectorRun)).one()
    assert run.status == "error" and "401" in run.error


# -- LeanIX client -------------------------------------------------------------------------


def leanix_handler(seen: dict):
    pages = [
        {"data": {"allFactSheets": {"pageInfo": {"hasNextPage": True, "endCursor": "c1"}, "edges": [
            {"node": {"id": "app-1", "displayName": "Checkout", "alias": "checkout-service, checkout",
                      "externalId": {"externalId": "https://github.com/acme/checkout"}, "tags": [{"name": "pci"}],
                      "subscriptions": {"edges": [
                          {"node": {"user": {"email": "JD@example.com"}, "roles": [{"name": "Responsible"}]}},
                          {"node": {"user": {"email": "x@example.com"}, "roles": [{"name": "Observer"}]}}]},
                      "relApplicationToOrganization": {"edges": [
                          {"node": {"factSheet": {"id": "t1", "displayName": "Storefront"}}}]}}}]}}},
        {"data": {"allFactSheets": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"id": "app-2", "displayName": "Argo CD", "alias": "argocd"}}]}}},
    ]

    def h(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if url == "https://acme.leanix.net/services/mtm/v1/oauth2/token":
            seen["auth"] = req.headers["authorization"]
            return httpx.Response(200, json={"access_token": "lx"})
        assert url == "https://acme.leanix.net/services/pathfinder/v1/graphql"
        assert req.headers["authorization"] == "Bearer lx"
        body = json.loads(req.content)
        seen.setdefault("afters", []).append(body["variables"]["after"])
        seen["query"] = body["query"]
        return httpx.Response(200, json=pages[0 if body["variables"]["after"] is None else 1])
    return h


def test_leanix_reads_applications_with_paging(svc):
    seen: dict = {}
    client = LeanixClient("acme.leanix.net", "api-token", transport=httpx.MockTransport(leanix_handler(seen)))
    apps = client.applications(["Responsible"])
    assert seen["auth"].startswith("Basic ") and seen["afters"] == [None, "c1"]
    assert "relApplicationToOrganization" in seen["query"]
    a = apps[0]
    assert a["aliases"] == ["checkout-service", "checkout", "pci"]
    assert a["teams"] == ["Storefront"] and a["responsible"] == ["jd@example.com"]
    assert a["repos"] == ["github.com/acme/checkout"]
    assert a["url"] == "https://acme.leanix.net/factsheet/Application/app-1"

    from kavlotryx.connectors.leanix import sync_leanix

    cfg = ownership_cfg()
    with svc.session() as s:
        run = sync_leanix(s, svc.settings, cfg, client=LeanixClient(
            "acme.leanix.net", "t", transport=httpx.MockTransport(leanix_handler({}))))
        assert run.counts == {"applications": 2, "with_team": 1}
        assert {x.name for x in s.scalars(select(CatalogApp))} == {"Checkout", "Argo CD"}


def test_leanix_graphql_errors_and_guards():
    def h(req):
        if "oauth2" in str(req.url):
            return httpx.Response(200, json={"access_token": "lx"})
        return httpx.Response(200, json={"errors": [{"message": "Field relX unknown"}]})
    with pytest.raises(ConnectorError, match="GraphQL error"):
        LeanixClient("acme.leanix.net", "t", transport=httpx.MockTransport(h)).applications([])
    for host in ("evil.example", "acme.leanix.net.evil.example", "http://acme.leanix.net@evil"):
        with pytest.raises(ConnectorError):
            LeanixClient(host, "t")
    with pytest.raises(ConnectorError):
        LeanixClient("acme.leanix.net", "t", team_relation="rel{ __schema }")


# -- snapshots, modes, API ---------------------------------------------------------------


def test_modes(settings):
    assert connector_mode(settings, "graph") == "off"
    settings.graph_tenant_id, settings.graph_client_id, settings.graph_client_secret = "t", "c", "s"
    assert connector_mode(settings, "graph") == "live"
    settings.leanix_snapshot = "x.json"
    assert connector_mode(settings, "leanix") == "snapshot"


def test_unconfigured_sync_fails_clearly(svc):
    with pytest.raises(ConnectorError, match="not configured"):
        svc.sync_connector("graph")


def test_bad_snapshot_is_recorded(svc, tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"people": "nope"}')
    svc.settings.graph_snapshot = str(bad)
    with pytest.raises(ConnectorError, match="'people' list"):
        svc.sync_connector("graph")


# -- ownership rules using the caches -----------------------------------------------------


SAMPLES_CFG = Path(__file__).resolve().parents[1] / "examples" / "samples" / "config"


def _wiz_issue(tags: dict, name: str = "web-1", rtype: str = "Deployment") -> bytes:
    from tests.test_wiz import issue, issues_csv

    return issues_csv(issue(1, **{"Resource Tags": json.dumps(tags), "Resource Name": name,
                                  "Resource Type": rtype, "Subscription ID": "sub-x"}))


@pytest.fixture
def sample_owned(tmp_path):
    from kavlotryx.config import Settings
    from kavlotryx.dispatch.fake import FakeTracker
    from kavlotryx.service import Kavlotryx

    st = Settings(database_url=f"sqlite:///{tmp_path / 'c.db'}", config_dir=SAMPLES_CFG,
                  graph_snapshot=str(SAMPLES_CFG / "graph-snapshot.json"),
                  leanix_snapshot=str(SAMPLES_CFG / "leanix-snapshot.json"))
    k = Kavlotryx(st, tracker=FakeTracker())
    return k


def _owner_of(k):
    with k.session() as s:
        fid = s.scalars(select(Finding.id)).one()
    return k.explain(fid)


def test_rules_report_unsynced_connectors(sample_owned):
    sample_owned.ingest("wiz", _wiz_issue({"Owner": "JD"}))
    a = _owner_of(sample_owned)
    reasons = {t.rule: t.reason for t in a.trace}
    assert reasons["directory"] == "Microsoft Graph not synced" and reasons["leanix"] == "LeanIX not synced"


def test_person_tag_resolves_through_graph(sample_owned):
    sample_owned.ingest("wiz", _wiz_issue({"Owner": "JD"}))
    sample_owned.sync_connector("graph")
    a = _owner_of(sample_owned)
    assert (a.owner, a.rule, a.confidence, a.needs_review) == ("app", "directory:graph", 0.8, False)
    assert a.evidence["person"] == "jd@example.com" and a.evidence["group"] == "sg-app-team"


def test_application_label_resolves_through_leanix_team(sample_owned):
    sample_owned.ingest("wiz", _wiz_issue({"app.kubernetes.io/part-of": "argocd"}))
    sample_owned.sync_connector("leanix")
    a = _owner_of(sample_owned)
    assert (a.owner, a.rule) == ("platform", "leanix:team")
    assert a.evidence["application"] == "Argo CD" and a.evidence["team"] == "Cloud Platform Team"


def test_leanix_responsible_person_falls_back_to_graph(sample_owned):
    sample_owned.ingest("wiz", _wiz_issue({"app.kubernetes.io/name": "wiz-sensor"}))
    sample_owned.sync_connector("leanix")
    assert _owner_of(sample_owned).rule != "leanix:responsible"  # needs Graph for the person
    sample_owned.sync_connector("graph")
    a = _owner_of(sample_owned)
    assert (a.owner, a.rule, a.evidence["responsible"]) == ("platform", "leanix:responsible", "sam.okafor@example.com")


def test_leanix_matches_artifact_name(sample_owned):
    sample_owned.ingest("wiz", _wiz_issue({}, name="checkout-service", rtype="Pod"))
    sample_owned.sync_connector("leanix")
    a = _owner_of(sample_owned)
    assert (a.owner, a.rule, a.evidence["matched_by"]) == ("app", "leanix:team", "artifact checkout-service")


def test_api_connectors(sample_owned):
    from fastapi.testclient import TestClient

    from kavlotryx.api import create_app
    from tests.test_web import ADMIN, VIEW

    sample_owned.settings.api_tokens = f"me:admin:{ADMIN},v:viewer:{VIEW}"
    c = TestClient(create_app(sample_owned))
    rows = c.get("/api/v1/connectors", headers={"Authorization": f"Bearer {VIEW}"}).json()
    assert {r["name"]: r["mode"] for r in rows} == {"graph": "snapshot", "leanix": "snapshot"}
    assert c.post("/api/v1/connectors/graph/sync", headers={"Authorization": f"Bearer {VIEW}"}).status_code == 403
    r = c.post("/api/v1/connectors/leanix/sync", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200 and r.json()["counts"]["applications"] == 6
    assert c.post("/api/v1/connectors/nope/sync", headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 422


def test_console_sync_button(sample_owned):
    from fastapi.testclient import TestClient

    from kavlotryx.api import create_app
    from tests.test_web import ADMIN, csrf, login

    sample_owned.settings.api_tokens = f"me:admin:{ADMIN}"
    c = TestClient(create_app(sample_owned), base_url="https://testserver")
    login(c, ADMIN)
    page = c.get("/ui/ownership").text
    assert "Sync now and rebuild owners" in page
    r = c.post("/ui/connectors/graph/sync", data={"csrf": csrf(page)}, follow_redirects=True)
    assert "graph snapshot sync: 4 people" in r.text and "Jordan Diaz" in r.text


def test_leanix_config_defaults():
    cfg = LeanixConnectorConfig()
    assert cfg.team_relation == "relApplicationToOrganization" and "app" in cfg.app_tag_keys
