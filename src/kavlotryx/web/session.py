"""Console sign-in: a signed cookie that points at an API token's hash.

The cookie never holds the token itself. It holds the SHA-256 hash of the
token, an expiry and an HMAC. Each request looks the hash up in the live
token map, so removing a token from KAVLO_API_TOKENS signs its sessions out.
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
    return request.url.scheme == "https" or os.environ.get("KAVLO_COOKIE_SECURE") == "1"


def issue(response: Response, request: Request, token_hash: str) -> None:
    exp = int(time.time()) + TTL_SECONDS
    payload = f"{token_hash}.{exp}"
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


def current(request: Request) -> Principal:
    """The signed-in principal, or LoginRequired."""
    tokens: dict[str, Principal] | None = request.app.state.tokens
    if tokens is None:  # --insecure-no-auth
        return ANON
    h = _session_hash(request)
    p = tokens.get(h) if h else None
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
    if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
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
