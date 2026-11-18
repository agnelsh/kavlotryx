"""An in-memory OIDC provider for tests (httpx MockTransport)."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.com/tenant"
CLIENT_ID = "kavlotryx-test"
CLIENT_SECRET = "test-client-secret-0123456789"


class FakeIdp:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, Any] = {}  # tweak the next ID token (tests of bad tokens)
        self.requests: list[httpx.Request] = []

    def jwk(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def id_token(self, claims: dict[str, Any], nonce: str) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": nonce, **claims,
                **self.overrides}
        key = self.overrides.pop("_key", self.key)
        return jwt.encode({k: v for k, v in body.items() if not k.startswith("_")}, key, algorithm="RS256",
                          headers={"kid": self.kid})

    def authorize(self, authorize_url: str, claims: dict[str, Any]) -> tuple[str, str]:
        """What the provider does after the person signs in: returns (code, state)."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(authorize_url).query).items()}
        assert q["client_id"] == CLIENT_ID and q["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"claims": claims, "nonce": q["nonce"], "challenge": q["code_challenge"],
                            "redirect_uri": q["redirect_uri"]}
        return code, q["state"]

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        path = req.url.path
        if path == "/tenant/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/keys"})
        if path == "/tenant/keys":
            return httpx.Response(200, json={"keys": [self.jwk()]})
        if path == "/tenant/token":
            form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            grant = self.codes.pop(form.get("code", ""), None)
            if grant is None or form.get("client_secret") != CLIENT_SECRET:
                return httpx.Response(400, json={"error": "invalid_grant"})
            verifier = form.get("code_verifier", "")
            calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if calc != grant["challenge"] or form.get("redirect_uri") != grant["redirect_uri"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(grant["claims"], grant["nonce"]),
                                             "access_token": "unused", "token_type": "Bearer"})
        return httpx.Response(404)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
