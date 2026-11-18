"""Static API tokens with roles. Tokens are kept only as SHA-256 hashes."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ROLES = {"admin", "analyst", "viewer", "ingest"}
READ = {"admin", "analyst", "viewer"}
WRITE = {"admin", "analyst"}
INGEST = {"admin", "analyst", "ingest"}
ADMIN = {"admin"}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    user_id: int | None = None  # set for a console user from single sign-on


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def parse_tokens(spec: str) -> dict[str, Principal]:
    """``name:role:token,name:role:token`` -> {sha256(token): Principal}."""
    out: dict[str, Principal] = {}
    for item in filter(None, (p.strip() for p in spec.split(","))):
        parts = item.split(":", 2)
        if len(parts) != 3 or parts[1] not in ROLES or len(parts[2]) < 16:
            raise ValueError("KAVLO_API_TOKENS entries must be name:role:token, role in "
                             f"{sorted(ROLES)}, token at least 16 characters")
        out[_hash(parts[2])] = Principal(parts[0], parts[1])
    return out


_bearer = HTTPBearer(auto_error=False)


def require(roles: set[str]):
    def dep(request: Request,
            cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
        tokens: dict[str, Principal] | None = request.app.state.tokens
        if tokens is None:  # explicit --insecure-no-auth opt-in
            return Principal("anonymous", "admin")
        if cred is None or cred.scheme.lower() != "bearer":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token",
                                headers={"WWW-Authenticate": "Bearer"})
        digest = _hash(cred.credentials)
        principal = next((p for h, p in tokens.items() if hmac.compare_digest(h, digest)), None)
        if principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token",
                                headers={"WWW-Authenticate": "Bearer"})
        if principal.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"role {principal.role} may not do this")
        return principal

    return dep
