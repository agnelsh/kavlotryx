"""Users and OIDC single sign-on for the console (FR-IF-10)."""

from __future__ import annotations

import re

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from kavlotryx import sso
from kavlotryx.api import create_app
from kavlotryx.config import Settings
from kavlotryx.db import AuditEvent, User
from tests.fake_idp import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdp
from tests.test_web import ADMIN, csrf

ALICE = {"sub": "u-alice", "email": "alice@example.com", "name": "Alice Admin", "groups": ["kav-admins", "staff"]}
BOB = {"sub": "u-bob", "email": "bob@example.com", "name": "Bob Builder", "groups": ["kav-admins"]}
RILEY = {"sub": "u-riley", "email": "riley@example.com", "name": "Riley Analyst", "groups": ["kav-analysts"]}
VIC = {"sub": "u-vic", "email": "vic@example.com", "name": "Vic Viewer", "groups": ["staff"]}
NOBODY = {"sub": "u-x", "email": "x@example.com", "name": "Contractor", "groups": ["contractors"]}


def configure(settings: Settings, tokens: str = f"me:admin:{ADMIN}") -> None:
    settings.api_tokens = tokens
    settings.oidc_issuer, settings.oidc_client_id = ISSUER, CLIENT_ID
    settings.oidc_client_secret = CLIENT_SECRET
    settings.oidc_redirect_url = "https://testserver/ui/sso/callback"
    settings.oidc_role_map = "admin=kav-admins,analyst=kav-analysts,viewer=staff"
    settings.oidc_label = "Example ID"


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def app(day1, idp):
    configure(day1.settings)
    day1.run()
    a = create_app(day1)
    a.state.oidc_transport = idp.transport
    return a


def client(app) -> TestClient:
    return TestClient(app, base_url="https://testserver")


def sign_in(c: TestClient, idp: FakeIdp, claims: dict, nxt: str = "/ui/triage") -> httpx.Response:
    r = c.get(f"/ui/sso/login?next={nxt}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"{ISSUER}/authorize?")
    code, state = idp.authorize(r.headers["location"], claims)
    return c.get(f"/ui/sso/callback?code={code}&state={state}", follow_redirects=False)


def test_login_page_offers_sso_and_token(app):
    html = client(app).get("/ui/login").text
    assert "Sign in with Example ID" in html and 'name="token"' in html


def test_sign_in_creates_the_user_with_a_role_from_groups(app, idp, day1):
    c = client(app)
    r = sign_in(c, idp, ALICE)
    assert r.status_code == 200 and 'content="0;url=/ui/triage"' in r.text
    cookie = r.headers["set-cookie"]
    assert "kavlo_session=u-" in cookie and "SameSite=strict" in cookie and "HttpOnly" in cookie
    page = c.get("/ui/triage")
    assert page.status_code == 200 and "alice@example.com" in page.text
    with day1.session() as s:
        u = s.scalars(select(User)).one()
        assert (u.email, u.role, u.role_source, u.groups) == ("alice@example.com", "admin", "groups",
                                                             ["kav-admins", "staff"])
        actions = [e.action for e in s.scalars(select(AuditEvent).where(AuditEvent.target == f"user:{u.id}"))]
    assert actions == ["user.create", "user.signin"]
    # the discovery, keys and token endpoints were used; PKCE and the secret were checked by the fake
    assert {q.url.path for q in idp.requests} >= {"/tenant/token", "/tenant/keys"}


def test_roles_highest_group_wins_and_unmapped_users_get_nothing(app, idp, day1):
    for claims, role in ((RILEY, "analyst"), (VIC, "viewer")):
        c = client(app)
        sign_in(c, idp, claims)
        assert claims["email"] in c.get("/ui").text
        with day1.session() as s:
            assert s.scalar(select(User.role).where(User.email == claims["email"])) == role
    c = client(app)
    r = sign_in(c, idp, NOBODY)
    assert r.status_code == 403 and "you have no access" in r.text
    assert c.get("/ui", follow_redirects=False).status_code == 303  # not signed in


def test_state_and_replay_are_rejected(app, idp):
    c = client(app)
    r = c.get("/ui/sso/login", follow_redirects=False)
    code, _ = idp.authorize(r.headers["location"], ALICE)
    bad = c.get(f"/ui/sso/callback?code={code}&state=forged")
    assert bad.status_code == 400 and "took too long" in bad.text
    fresh = client(app)  # no login cookie at all
    assert fresh.get(f"/ui/sso/callback?code={code}&state=x").status_code == 400
    c2 = client(app)
    r = c2.get("/ui/sso/login", follow_redirects=False)
    code, state = idp.authorize(r.headers["location"], ALICE)
    assert c2.get(f"/ui/sso/callback?code={code}&state={state}").status_code == 200
    c3 = client(app)  # the same code again, with a new login state
    r = c3.get("/ui/sso/login", follow_redirects=False)
    _, state3 = idp.authorize(r.headers["location"], ALICE)
    replay = c3.get(f"/ui/sso/callback?code={code}&state={state3}")
    assert replay.status_code == 400 and "refused the code" in replay.text


@pytest.mark.parametrize("override, message", [
    ({"aud": "someone-else"}, "not valid"),
    ({"iss": "https://evil.example.com"}, "not valid"),
    ({"exp": 1000}, "not valid"),
    ({"nonce": "wrong"}, "nonce"),
    ({"_key": rsa.generate_private_key(public_exponent=65537, key_size=2048)}, "not valid"),
])
def test_bad_id_tokens_are_rejected(app, idp, override, message):
    idp.overrides.update(override)
    r = sign_in(client(app), idp, ALICE)
    assert r.status_code == 400 and "Single sign-on failed" in r.text and message in r.text


def test_hs256_and_none_tokens_are_refused(day1, idp):
    configure(day1.settings)
    oc = sso.OidcClient(day1.settings, transport=idp.transport)
    import jwt

    forged = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "x"}, "secret-secret-secret-secret-1234",
                        algorithm="HS256")
    with pytest.raises(sso.OidcError, match="algorithm"):
        oc.verify(forged, "n")
    unsigned = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "x"}, None, algorithm="none")
    with pytest.raises(sso.OidcError, match="algorithm"):
        oc.verify(unsigned, "n")


def test_admin_manages_users_and_changes_apply_at_once(app, idp, day1):
    alice, bob = client(app), client(app)
    sign_in(alice, idp, ALICE)
    sign_in(bob, idp, BOB)
    with day1.session() as s:
        ids = {u.email: u.id for u in s.scalars(select(User))}
    page = alice.get("/ui/settings/users").text
    assert "Users" in page and "another admin changes your user" in page
    iam = alice.get("/ui/settings/iam").text
    assert "kav-admins" in iam and CLIENT_SECRET not in iam  # the role map is shown, the secret never

    # nobody changes their own user
    r = alice.post(f"/ui/settings/users/{ids['alice@example.com']}",
                   data={"csrf": csrf(page), "action": "deactivate"}, follow_redirects=True)
    assert "cannot change your own user" in r.text

    # a pinned role works at once and survives the next sign-in
    alice.post(f"/ui/settings/users/{ids['bob@example.com']}",
               data={"csrf": csrf(page), "action": "role", "role": "viewer"}, follow_redirects=True)
    bp = bob.get("/ui/settings/policy").text
    assert "Only admins can change the policy" in bp
    sign_in(bob, idp, BOB)
    with day1.session() as s:
        assert s.scalar(select(User.role).where(User.email == "bob@example.com")) == "viewer"

    # deactivating ends the session and blocks sign-in
    alice.post(f"/ui/settings/users/{ids['bob@example.com']}",
               data={"csrf": csrf(page), "action": "deactivate"}, follow_redirects=True)
    assert bob.get("/ui", follow_redirects=False).status_code == 303
    assert sign_in(client(app), idp, BOB).status_code == 403

    alice.post(f"/ui/settings/users/{ids['bob@example.com']}",
               data={"csrf": csrf(page), "action": "activate"}, follow_redirects=True)
    alice.post(f"/ui/settings/users/{ids['bob@example.com']}",
               data={"csrf": csrf(page), "action": "groups"}, follow_redirects=True)
    sign_in(bob, idp, BOB)
    with day1.session() as s:
        assert s.scalar(select(User.role).where(User.email == "bob@example.com")) == "admin"


def test_sign_out_everywhere(app, idp, day1):
    alice, bob = client(app), client(app)
    sign_in(alice, idp, ALICE)
    sign_in(bob, idp, BOB)
    with day1.session() as s:
        bid = s.scalar(select(User.id).where(User.email == "bob@example.com"))
    page = alice.get("/ui/settings/users").text
    alice.post(f"/ui/settings/users/{bid}", data={"csrf": csrf(page), "action": "signout"})
    assert bob.get("/ui", follow_redirects=False).status_code == 303


def test_four_eyes_between_sso_users(app, idp, day1):
    riley, alice = client(app), client(app)
    sign_in(riley, idp, RILEY)
    sign_in(alice, idp, ALICE)
    from tests.test_triage import open_ids

    fid = open_ids(day1)[0]
    page = riley.get(f"/ui/vulnerabilities/{fid}").text
    r = riley.post("/ui/triage", data={"csrf": csrf(page), "kind": "false_positive", "finding_ids": str(fid),
                                       "reason": "Test fixture, never deployed"}, follow_redirects=True)
    did = int(re.search(r"/ui/triage/(\d+)", str(r.url)).group(1))
    dp = alice.get(f"/ui/triage/{did}").text
    r = alice.post(f"/ui/triage/{did}/approve", data={"csrf": csrf(dp)}, follow_redirects=True)
    assert "is active" in r.text and "ui:riley@example.com" in r.text and "ui:alice@example.com" in r.text


def test_token_login_can_be_turned_off(day1, idp):
    configure(day1.settings)
    day1.settings.token_login = False
    app = create_app(day1)
    app.state.oidc_transport = idp.transport
    c = client(app)
    assert 'name="token"' not in c.get("/ui/login").text
    r = c.post("/ui/login", data={"token": ADMIN, "next": "/ui"}, follow_redirects=False)
    assert r.headers["location"] == "/ui/login" and "kavlo_session" not in r.headers.get("set-cookie", "")


def test_sso_only_install_starts_and_the_api_still_needs_tokens(day1, idp):
    configure(day1.settings, tokens="")
    app = create_app(day1)
    app.state.oidc_transport = idp.transport
    assert TestClient(app).get("/api/v1/findings").status_code == 401
    c = client(app)
    assert 'name="token"' in c.get("/ui/login").text  # token login stays on unless turned off
    sign_in(c, idp, ALICE)
    assert c.get("/ui").status_code == 200


def test_api_users(app, idp):
    sign_in(client(app), idp, RILEY)
    api = TestClient(app)
    h = {"Authorization": f"Bearer {ADMIN}"}
    rows = api.get("/api/v1/users", headers=h).json()
    assert rows[0]["email"] == "riley@example.com" and rows[0]["role"] == "analyst"
    r = api.patch(f"/api/v1/users/{rows[0]['id']}", headers=h, json={"role": "viewer", "active": False})
    assert (r.json()["role"], r.json()["active"], r.json()["role_source"]) == ("viewer", False, "manual")
    assert api.patch("/api/v1/users/999", headers=h, json={"role": "viewer"}).status_code == 404
    assert api.patch(f"/api/v1/users/{rows[0]['id']}", headers=h, json={"role": "root"}).status_code == 422


def test_config_checks(day1):
    assert sso.role_for(["A", "b"], sso.parse_role_map("viewer=*,admin=a")) == "admin"
    assert sso.role_for([], sso.parse_role_map("viewer=*")) == "viewer"
    assert sso.role_for(["x"], sso.parse_role_map("analyst=a|b")) == "none"
    with pytest.raises(ValueError):
        sso.parse_role_map("root=a")
    configure(day1.settings)
    day1.settings.oidc_issuer = "http://idp.example.com"
    with pytest.raises(sso.OidcError, match="https"):
        sso.OidcClient(day1.settings)
    day1.settings.oidc_issuer = ISSUER
    day1.settings.oidc_role_map = "boss=x"
    with pytest.raises(ValueError):
        create_app(day1)


def test_discovery_must_name_the_same_issuer(day1):
    configure(day1.settings)

    def handler(req):
        return httpx.Response(200, json={"issuer": "https://other.example.com", "authorization_endpoint": "x",
                                         "token_endpoint": "x", "jwks_uri": "x"})

    with pytest.raises(sso.OidcError, match="different issuer"):
        sso.OidcClient(day1.settings, transport=httpx.MockTransport(handler)).metadata()
