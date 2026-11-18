"""Console sign-in: a signed cookie that points at an API token or an SSO user.

The cookie never holds a token or a password. It holds an identity, an expiry
and an HMAC:

* ``t-<sha256 of the token>``: each request looks the hash up in the live token
  map, so removing a token from KAVLO_API_TOKENS signs its sessions out;
* ``u-<user id>-<epoch>``: each request reads the user, so a deactivated user,
  a changed role or a raised ``session_epoch`` takes effect at once.

Every form POST also carries a CSRF token derived from the session.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from kavlotryx.api.auth import READ, Principal

COOKIE = "kavlo_session"
FLASH = "kavlo_flash"
TTL_SECONDS = 8 * 3600
ANON = Principal("local", "admin")
VISITOR = Principal("visitor", "viewer")  # anonymous visitor of a public demo (KAVLO_DEMO_MODE=1)


def public_host(request: Request) -> str:
    """The host people use when Kavlotryx runs behind a proxy (KAVLO_PUBLIC_URL), or ''."""
    return urlsplit(getattr(request.app.state, "public_url", "") or "").netloc


def allowed_hosts(request: Request) -> set[str]:
    return {h for h in (request.headers.get("host", ""), public_host(request)) if h}


class LoginRequired(Exception):
    pass


class CsrfError(Exception):
    pass


class Forbidden(Exception):
    def __init__(self, role: str) -> None:
        super().__init__(role)
        self.role = role


def _secret() -> bytes:
    env = os.environ.get("KAVLO_SESSION_SECRET", "")
    return env.encode() if env else _PROCESS_SECRET


_PROCESS_SECRET = secrets.token_bytes(32)


def _sign(payload: str) -> str:
    return hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()


def _secure(request: Request) -> bool:
    public = getattr(request.app.state, "public_url", "") or ""
    return (request.url.scheme == "https" or public.startswith("https://")
            or os.environ.get("KAVLO_COOKIE_SECURE") == "1")


def issue(response: Response, request: Request, token_hash: str = "", user=None) -> None:
    exp = int(time.time()) + TTL_SECONDS
    ident = f"u-{user.id}-{user.session_epoch}" if user is not None else f"t-{token_hash}"
    payload = f"{ident}.{exp}"
    response.set_cookie(COOKIE, f"{payload}.{_sign(payload)}", max_age=TTL_SECONDS, httponly=True,
                        samesite="strict", secure=_secure(request), path="/")


def clear(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/")


def _session_hash(request: Request) -> str | None:
    raw = request.cookies.get(COOKIE, "")
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    token_hash, exp, sig = parts
    if not hmac.compare_digest(_sign(f"{token_hash}.{exp}"), sig):
        return None
    if not exp.isdigit() or int(exp) < time.time():
        return None
    return token_hash


def _user_principal(request: Request, ident: str) -> Principal | None:
    from kavlotryx.core.users import display
    from kavlotryx.db import User

    parts = ident.split("-")
    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
        return None
    with request.app.state.svc.session() as s:
        u = s.get(User, int(parts[1]))
        if u is None or not u.active or u.session_epoch != int(parts[2]) or u.role not in READ:
            return None
        return Principal(display(u), u.role, u.id)


def current(request: Request) -> Principal:
    """The signed-in principal, or LoginRequired."""
    tokens: dict[str, Principal] | None = request.app.state.tokens
    if tokens is None:  # --insecure-no-auth
        return ANON
    ident = _session_hash(request)
    p: Principal | None = None
    if ident and ident.startswith("u-"):
        p = _user_principal(request, ident)
    elif ident:
        p = tokens.get(ident.removeprefix("t-"))
    if p is None and getattr(request.app.state, "demo", False):
        return VISITOR
    if p is None or p.role not in READ:
        raise LoginRequired()
    return p


def csrf_token(request: Request) -> str:
    h = _session_hash(request) or "anon"
    return _sign(f"csrf.{h}")[:40]


def check_csrf(request: Request, submitted: str | None) -> None:
    if not submitted or not hmac.compare_digest(csrf_token(request), submitted):
        raise CsrfError()
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc not in allowed_hosts(request):
        raise CsrfError()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def redirect(url: str, kind: str = "", text: str = "") -> RedirectResponse:
    resp = RedirectResponse(url, status_code=303)
    if text:
        resp.set_cookie(FLASH, json.dumps({"kind": kind, "text": text[:600]}), max_age=60,
                        httponly=True, samesite="strict", path="/")
    return resp


def pop_flash(request: Request) -> dict | None:
    raw = request.cookies.get(FLASH)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return {"kind": str(data.get("kind", "")), "text": str(data.get("text", ""))}
    except ValueError:
        return None


# -- single sign-on state (FR-IF-10) -------------------------------------------------
# state, nonce and the PKCE verifier live in a signed cookie for 10 minutes. It is
# SameSite=Lax, because the identity provider sends the browser back with a
# cross-site top-level GET, and it is scoped to /ui/sso.

LOGIN_COOKIE = "kavlo_oidc"
LOGIN_TTL = 600


def issue_login_state(response: Response, request: Request, ls, next_url: str) -> None:
    import base64

    body = json.dumps({"s": ls.state, "n": ls.nonce, "v": ls.verifier, "x": next_url,
                       "e": int(time.time()) + LOGIN_TTL}, separators=(",", ":"))
    payload = base64.urlsafe_b64encode(body.encode()).decode()
    response.set_cookie(LOGIN_COOKIE, f"{payload}.{_sign('oidc.' + payload)}", max_age=LOGIN_TTL, httponly=True,
                        samesite="lax", secure=_secure(request), path="/ui/sso")


def pop_login_state(request: Request):
    """(LoginState, next) from a valid, unexpired cookie, else None."""
    import base64

    from kavlotryx.sso import LoginState

    raw = request.cookies.get(LOGIN_COOKIE, "")
    payload, _, sig = raw.partition(".")
    if not payload or not hmac.compare_digest(_sign("oidc." + payload), sig):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or int(data.get("e", 0)) < time.time():
        return None
    return LoginState(str(data["s"]), str(data["n"]), str(data["v"])), str(data.get("x") or "/ui")


def clear_login_state(response: Response) -> None:
    response.delete_cookie(LOGIN_COOKIE, path="/ui/sso")
