"""User models for authentication + RBAC.

Phase 1.3 adds:
    * `UserRole.ANALYST` — the write-capable-but-not-admin role from
      the prompt (`admin`, `analyst`, `viewer`). We keep the legacy
      `USER` alias so existing tokens / DB rows continue to authenticate
      as an analyst.
    * `tenant_id` on `User` — every user belongs to exactly one tenant
      (Organization in prompt terminology). The JWT carries this as
      the `org_id` claim so downstream RBAC + RLS can enforce it
      without a second DB round-trip.
    * `Organization` + `Membership` Pydantic models — DB is defined in
      migration 0001 (`tenant`, `app_user`) plus 0003 (role rename);
      these are the request/response schemas used by the API layer.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    """RBAC roles.

    * `ADMIN`   — full read/write, can create/delete resources across the org.
    * `ANALYST` — read/write on scans + findings, cannot delete or manage users.
    * `VIEWER`  — read-only.
    * `USER`    — legacy alias for ANALYST kept for token backwards-compat.
    """
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    # Legacy — treated as ANALYST at check time.
    USER = "user"


# Roles that count as "write-capable" (create scans, save findings).
WRITE_ROLES: frozenset[UserRole] = frozenset(
    {UserRole.ADMIN, UserRole.ANALYST, UserRole.USER}
)

# Roles that can delete resources.
DELETE_ROLES: frozenset[UserRole] = frozenset({UserRole.ADMIN})


def role_can_write(role: UserRole | str) -> bool:
    try:
        return UserRole(role) in WRITE_ROLES
    except ValueError:
        return False


def role_can_delete(role: UserRole | str) -> bool:
    try:
        return UserRole(role) in DELETE_ROLES
    except ValueError:
        return False


class Organization(BaseModel):
    """Tenant / organization envelope.

    Backed by the `tenant` table in migration 0001.
    """
    id: str
    slug: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    plan: str = Field(default="free")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class User(BaseModel):
    """User account model."""
    id: str
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    role: UserRole = UserRole.ANALYST
    tenant_id: str | None = Field(default=None, max_length=64)
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    api_key: str | None = None


class Membership(BaseModel):
    """User↔Organization junction row (denormalised in `app_user`)."""
    user_id: str
    tenant_id: str
    role: UserRole
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UserCreate(BaseModel):
    """User registration payload."""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=100)
    tenant_id: str | None = Field(default=None, max_length=64)


class UserLogin(BaseModel):
    """User login payload."""
    email: EmailStr
    password: str


class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # 1 hour


class APIKey(BaseModel):
    """API key model.

    Phase 1.3 adds `prefix` (visible portion, safe to log) and
    `rotated_from` (previous key id, so rotation preserves an audit
    trail). Real secret is stored bcrypt-hashed in `secret_hash` and
    never returned after creation.
    """
    key: str  # returned only once on creation; None on subsequent reads
    id: str | None = None
    prefix: str | None = None
    user_id: str
    tenant_id: str | None = None
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: datetime | None = None
    is_active: bool = True
    rotated_from: str | None = None
