"""OIDC single sign-on for the console (FR-IF-10).

Authorization-code flow with PKCE (S256), ``state`` and ``nonce``, for any
OpenID Connect provider: Microsoft Entra ID, Okta, Google, Keycloak, Auth0.
Settings come from the environment only (NFR-SEC-02)::

    KAVLO_OIDC_ISSUER         https://login.microsoftonline.com/<tenant>/v2.0
    KAVLO_OIDC_CLIENT_ID      the app registration's client id
    KAVLO_OIDC_CLIENT_SECRET  its client secret
    KAVLO_OIDC_REDIRECT_URL   https://<kavlotryx host>/ui/sso/callback
    KAVLO_OIDC_ROLE_MAP       admin=<group>,analyst=<group>|<group>,viewer=*

The ID token is checked for its signature (keys from the provider's JWKS,
asymmetric algorithms only), issuer, audience, expiry and nonce. Roles come
from the groups claim (``KAVLO_OIDC_GROUPS_CLAIM``, default ``groups``); the
highest matching role wins and ``*`` matches everyone. A user who matches no
role signs in to nothing. Entra ID sends group object ids, and for users in
more than 200 groups it sends no groups at all ("overage"); map few, specific
groups, or use app roles and set the claim to ``roles``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

from kavlotryx.config import Settings

ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
ROLE_RANK = {"admin": 3, "analyst": 2, "viewer": 1}
LEEWAY = 60


class OidcError(Exception):
    """Sign-in failed. The message is safe to show to the user."""


def _check_url(url: str, what: str) -> str:
    parts = urlsplit(url or "")
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise OidcError(f"{what} must be an https URL")
    return url


def parse_role_map(spec: str) -> dict[str, list[str]]:
    """``admin=g1|g2,viewer=*`` -> {"admin": ["g1", "g2"], "viewer": ["*"]}."""
    out: dict[str, list[str]] = {}
    for item in filter(None, (p.strip() for p in (spec or "").split(","))):
        role, _, groups = item.partition("=")
        role = role.strip().lower()
        if role not in ROLE_RANK or not groups.strip():
            raise ValueError("KAVLO_OIDC_ROLE_MAP entries are role=group|group, role in admin, analyst, viewer")
        out.setdefault(role, []).extend(g.strip() for g in groups.split("|") if g.strip())
    return out


def role_for(groups: list[str], role_map: dict[str, list[str]]) -> str:
    have = {g.lower() for g in groups}
    best = "none"
    for role, wanted in role_map.items():
        if any(w == "*" or w.lower() in have for w in wanted) and ROLE_RANK[role] > ROLE_RANK.get(best, 0):
            best = role
    return best


def groups_from(claims: dict[str, Any], claim: str) -> list[str]:
    v = claims.get(claim)
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int))][:500]
    return []


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class LoginState:
    state: str
    nonce: str
    verifier: str

    @classmethod
    def new(cls) -> LoginState:
        return cls(secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48))

    @property
    def challenge(self) -> str:
        return _b64(hashlib.sha256(self.verifier.encode()).digest())


def configured(settings: Settings) -> bool:
    return bool(settings.oidc_issuer and settings.oidc_client_id and settings.oidc_redirect_url)


class OidcClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        if not configured(settings):
            raise OidcError("single sign-on is not configured")
        self.s = settings
        self.issuer = _check_url(settings.oidc_issuer.rstrip("/"), "KAVLO_OIDC_ISSUER")
        self.redirect = _check_url(settings.oidc_redirect_url, "KAVLO_OIDC_REDIRECT_URL")
        self.role_map = parse_role_map(settings.oidc_role_map)
        self.http = httpx.Client(timeout=15.0, transport=transport, headers={"Accept": "application/json"})
        self._meta: dict[str, Any] | None = None
        self._meta_at = 0.0
        self._jwks: dict[str, Any] | None = None

    # -- provider metadata ------------------------------------------------------

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = self.http.get(url)
        except httpx.HTTPError as e:
            raise OidcError(f"cannot reach the identity provider: {type(e).__name__}") from e
        if resp.status_code != 200:
            raise OidcError(f"the identity provider answered HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise OidcError("the identity provider did not answer with JSON") from e
        if not isinstance(data, dict):
            raise OidcError("the identity provider did not answer with a JSON object")
        return data

    def metadata(self) -> dict[str, Any]:
        if self._meta is None or time.time() - self._meta_at > 3600:
            meta = self._get_json(f"{self.issuer}/.well-known/openid-configuration")
            if str(meta.get("issuer", "")).rstrip("/") != self.issuer:
                raise OidcError("the discovery document names a different issuer")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                _check_url(str(meta.get(key, "")), key)
            self._meta, self._meta_at, self._jwks = meta, time.time(), None
        return self._meta

    def _key(self, kid: str | None, refresh: bool = False) -> jwt.PyJWK:
        if self._jwks is None or refresh:
            self._jwks = self._get_json(self.metadata()["jwks_uri"])
        keys = [k for k in self._jwks.get("keys", []) if isinstance(k, dict) and k.get("use", "sig") == "sig"]
        match = [k for k in keys if kid is None or k.get("kid") == kid]
        if not match:
            if not refresh:
                return self._key(kid, refresh=True)  # the provider rotated its keys
            raise OidcError("no signing key matches the ID token")
        return jwt.PyJWK(match[0])

    # -- flow -------------------------------------------------------------------------

    def authorize_url(self, ls: LoginState) -> str:
        q = {"response_type": "code", "client_id": self.s.oidc_client_id, "redirect_uri": self.redirect,
             "scope": self.s.oidc_scopes, "state": ls.state, "nonce": ls.nonce,
             "code_challenge": ls.challenge, "code_challenge_method": "S256"}
        return f"{self.metadata()['authorization_endpoint']}?{urlencode(q)}"

    def exchange(self, code: str, ls: LoginState) -> dict[str, Any]:
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect,
                "client_id": self.s.oidc_client_id, "code_verifier": ls.verifier}
        if self.s.oidc_client_secret:
            data["client_secret"] = self.s.oidc_client_secret
        try:
            resp = self.http.post(self.metadata()["token_endpoint"], data=data)
        except httpx.HTTPError as e:
            raise OidcError(f"cannot reach the token endpoint: {type(e).__name__}") from e
        if resp.status_code != 200:
            raise OidcError(f"the token endpoint refused the code (HTTP {resp.status_code})")
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        token = body.get("id_token") if isinstance(body, dict) else None
        if not token:
            raise OidcError("the token endpoint returned no ID token")
        return self.verify(token, ls.nonce)

    def verify(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as e:
            raise OidcError("the ID token is malformed") from e
        if header.get("alg") not in ALGORITHMS:
            raise OidcError("the ID token uses an algorithm Kavlotryx does not accept")
        key = self._key(header.get("kid"))
        try:
            claims = jwt.decode(id_token, key.key, algorithms=[header["alg"]], audience=self.s.oidc_client_id,
                                issuer=self.metadata()["issuer"], leeway=LEEWAY,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWTError as e:
            raise OidcError(f"the ID token is not valid: {e}") from e
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("the ID token nonce does not match this sign-in")
        return claims
