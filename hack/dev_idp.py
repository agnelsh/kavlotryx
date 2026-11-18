"""A development-only OIDC provider for the Kavlotryx demo. Never use it for anything else.

It listens on localhost only, has no passwords: you pick one of four made-up
people, and it signs an ID token with a key it makes at start. It checks the
client secret, the redirect URI and PKCE, like a real provider would.

    .venv/bin/python hack/dev_idp.py 8189     # hack/demo-samples.sh --serve starts it for you
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import secrets
import sys
import time
from urllib.parse import urlencode

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8189
ISSUER = f"http://localhost:{PORT}"
CLIENT_ID = os.environ.get("KAVLO_OIDC_CLIENT_ID", "kavlotryx-demo")
CLIENT_SECRET = os.environ.get("KAVLO_OIDC_CLIENT_SECRET", "dev-only-secret")
PEOPLE = {
    "avery": {"name": "Avery Brooks", "email": "avery@example.com", "groups": ["kavlotryx-admins"],
              "note": "admin (group kavlotryx-admins)"},
    "dana": {"name": "Dana Whitfield", "email": "dana@example.com", "groups": ["kavlotryx-admins"],
             "note": "admin, a second approver"},
    "riley": {"name": "Riley Chen", "email": "riley@example.com", "groups": ["kavlotryx-analysts"],
              "note": "analyst (group kavlotryx-analysts)"},
    "vic": {"name": "Vic Lee", "email": "vic@example.com", "groups": ["all-staff"], "note": "viewer (group all-staff)"},
    "sam": {"name": "Sam Contractor", "email": "sam@example.com", "groups": ["contractors"],
            "note": "no mapped group: no access"},
}

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = secrets.token_hex(4)
CODES: dict[str, dict] = {}
app = FastAPI(title="Kavlotryx dev IdP", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/.well-known/openid-configuration")
def discovery():
    return {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/keys", "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"]}


@app.get("/keys")
def keys():
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


@app.get("/authorize", response_class=HTMLResponse)
def authorize(request: Request):
    q = dict(request.query_params)
    if q.get("client_id") != CLIENT_ID or q.get("code_challenge_method") != "S256":
        return HTMLResponse("unknown client or no PKCE", status_code=400)
    hidden = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
                     for k, v in q.items() if k in ("redirect_uri", "state", "nonce", "code_challenge"))
    buttons = "".join(f'<button name="who" value="{k}"><b>{html.escape(p["name"])}</b><br>'
                      f'<small>{html.escape(p["note"])}</small></button>' for k, p in PEOPLE.items())
    return (f"<!doctype html><meta charset=utf-8><title>Dev IdP</title><style>body{{font:15px system-ui;"
            f"max-width:420px;margin:40px auto}}button{{display:block;width:100%;text-align:left;margin:8px 0;"
            f"padding:10px;border:1px solid #888;border-radius:8px;background:#fff;cursor:pointer}}</style>"
            f"<h2>Development sign-in</h2><p>Made-up people for the Kavlotryx demo. No passwords.</p>"
            f'<form method="post" action="/authorize">{hidden}{buttons}</form>')


@app.post("/authorize")
def approve(who: str = Form(...), redirect_uri: str = Form(...), state: str = Form(...), nonce: str = Form(...),
            code_challenge: str = Form(...)):
    if who not in PEOPLE or not redirect_uri.startswith(("http://localhost:", "http://127.0.0.1:")):
        return HTMLResponse("bad request", status_code=400)
    code = secrets.token_urlsafe(24)
    CODES[code] = {"who": who, "nonce": nonce, "challenge": code_challenge, "redirect_uri": redirect_uri,
                   "exp": time.time() + 60}
    return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=303)


@app.post("/token")
def token(grant_type: str = Form(...), code: str = Form(...), redirect_uri: str = Form(...),
          client_id: str = Form(...), code_verifier: str = Form(...), client_secret: str = Form("")):
    g = CODES.pop(code, None)
    calc = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    if (g is None or g["exp"] < time.time() or grant_type != "authorization_code" or client_id != CLIENT_ID
            or not secrets.compare_digest(client_secret, CLIENT_SECRET) or calc != g["challenge"]
            or redirect_uri != g["redirect_uri"]):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    p, now = PEOPLE[g["who"]], int(time.time())
    claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": f"dev-{g['who']}", "iat": now, "exp": now + 300,
              "nonce": g["nonce"], "email": p["email"], "name": p["name"], "groups": p["groups"]}
    return {"id_token": jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID}),
            "access_token": secrets.token_urlsafe(16), "token_type": "Bearer", "expires_in": 300}


if __name__ == "__main__":
    print(f"dev IdP (development only): {ISSUER}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
