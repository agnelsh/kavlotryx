"""Console users from OIDC single sign-on (FR-IF-10).

A user is created on first sign-in. Each sign-in refreshes the email, name and
groups, and, unless an admin pinned the role, the role from the groups claim.
Every change is audited. Admins cannot change or deactivate their own user,
so nobody locks themself out by accident.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.db import User, audit, utcnow

ROLES = ("admin", "analyst", "viewer", "none")


class AccessDenied(Exception):
    """The identity provider signed the person in, but Kavlotryx gives them no access."""


class UserError(ValueError):
    pass


def display(u: User) -> str:
    """The principal name used in audit actors and four-eyes checks."""
    return u.email or u.name or f"user-{u.id}"


def sign_in(s: Session, issuer: str, claims: dict[str, Any], groups: list[str], role_from_groups: str) -> User:
    sub = str(claims.get("sub", ""))
    if not sub:
        raise AccessDenied("the ID token has no subject")
    u = s.scalar(select(User).where(User.issuer == issuer, User.subject == sub))
    email = str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "")[:320]
    name = str(claims.get("name") or email)[:256]
    if u is None:
        u = User(issuer=issuer, subject=sub, email=email, name=name, role=role_from_groups, role_source="groups",
                 groups=groups, created_at=utcnow())
        s.add(u)
        s.flush()
        audit(s, f"sso:{display(u)}", "user.create", f"user:{u.id}", role=u.role, groups=len(groups))
    else:
        u.email, u.name, u.groups = email or u.email, name or u.name, groups
        if u.role_source == "groups" and u.role != role_from_groups:
            audit(s, "sso", "user.role", f"user:{u.id}", previous=u.role, role=role_from_groups, source="groups")
            u.role = role_from_groups
    if not u.active or u.role == "none":
        why = "deactivated" if not u.active else "no role: none of your groups is mapped in KAVLO_OIDC_ROLE_MAP"
        audit(s, f"sso:{display(u)}", "user.denied", f"user:{u.id}", reason=why)
        s.commit()
        raise AccessDenied(why)
    u.last_login_at = utcnow()
    audit(s, f"sso:{display(u)}", "user.signin", f"user:{u.id}", role=u.role)
    s.commit()
    return u


def get(s: Session, uid: int) -> User:
    u = s.get(User, uid)
    if u is None:
        raise UserError(f"user {uid} not found")
    return u


def find(s: Session, key: str) -> User:
    """A user by id or email."""
    if key.isdigit():
        return get(s, int(key))
    u = s.scalar(select(User).where(User.email == key))
    if u is None:
        raise UserError(f"no user with the email {key!r}; they must sign in once first")
    return u


def _not_self(u: User, actor_user_id: int | None) -> None:
    if actor_user_id is not None and u.id == actor_user_id:
        raise UserError("you cannot change your own user; ask another admin")


def set_role(s: Session, u: User, role: str, actor: str, actor_user_id: int | None = None) -> User:
    if role not in ROLES:
        raise UserError(f"role must be one of {', '.join(ROLES)}")
    _not_self(u, actor_user_id)
    prev = (u.role, u.role_source)
    u.role, u.role_source = role, "manual"  # sessions read the role on every request: it applies at once
    audit(s, actor, "user.role", f"user:{u.id}", previous=prev[0], role=role, source="manual")
    s.commit()
    return u


def use_groups(s: Session, u: User, actor: str, actor_user_id: int | None = None) -> User:
    _not_self(u, actor_user_id)
    u.role_source = "groups"
    audit(s, actor, "user.role", f"user:{u.id}", role=u.role, source="groups", note="applies at next sign-in")
    s.commit()
    return u


def set_active(s: Session, u: User, active: bool, actor: str, actor_user_id: int | None = None) -> User:
    _not_self(u, actor_user_id)
    u.active = active
    u.session_epoch += 1
    audit(s, actor, "user.activate" if active else "user.deactivate", f"user:{u.id}")
    s.commit()
    return u


def sign_out_everywhere(s: Session, u: User, actor: str) -> User:
    u.session_epoch += 1
    audit(s, actor, "user.signout_all", f"user:{u.id}")
    s.commit()
    return u


def as_dict(u: User) -> dict[str, Any]:
    from kavlotryx.core.triage import iso

    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "role_source": u.role_source,
            "groups": u.groups, "active": u.active, "issuer": u.issuer, "created_at": iso(u.created_at),
            "last_login_at": iso(u.last_login_at)}
