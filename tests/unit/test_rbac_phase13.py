"""Unit tests for Phase 1.3 RBAC + Multi-Tenancy."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from sentinel.auth.jwt_auth import (
    create_access_token,
    decode_token,
    revoke_token,
)
from sentinel.auth.models import (
    DELETE_ROLES,
    WRITE_ROLES,
    Membership,
    Organization,
    User,
    UserRole,
    role_can_delete,
    role_can_write,
)
from sentinel.auth.rbac import (
    _is_public,
    _required_role,
    _role_satisfies,
)
from sentinel.auth.revocation import (
    InMemoryRevocationStore,
    get_revocation_store,
    reset_revocation_store,
)
from sentinel.core.workspace import (
    WorkspaceError,
    resolve_upload_dir,
    resolve_workspace,
)


class TestRoles:
    def test_analyst_can_write(self):
        assert role_can_write(UserRole.ANALYST)
        assert role_can_write("analyst")

    def test_viewer_cannot_write(self):
        assert not role_can_write(UserRole.VIEWER)
        assert not role_can_write("viewer")

    def test_only_admin_can_delete(self):
        assert role_can_delete(UserRole.ADMIN)
        assert not role_can_delete(UserRole.ANALYST)
        assert not role_can_delete(UserRole.VIEWER)

    def test_legacy_user_role_treated_as_analyst(self):
        assert role_can_write(UserRole.USER)
        assert not role_can_delete(UserRole.USER)

    def test_role_frozensets(self):
        assert UserRole.ADMIN in WRITE_ROLES
        assert UserRole.VIEWER not in WRITE_ROLES
        assert UserRole.ADMIN in DELETE_ROLES
        assert UserRole.ANALYST not in DELETE_ROLES


class TestModels:
    def test_organization(self):
        o = Organization(id="t-1", slug="acme", name="Acme")
        assert o.plan == "free"

    def test_user_defaults_to_analyst(self):
        u = User(
            id="u1", email="a@b.co", username="alice",
        )
        assert u.role == UserRole.ANALYST

    def test_user_with_tenant(self):
        u = User(
            id="u1", email="a@b.co", username="alice",
            tenant_id="00000000-0000-0000-0000-000000000001",
        )
        assert u.tenant_id.startswith("00000000")

    def test_membership(self):
        m = Membership(user_id="u1", tenant_id="t1", role=UserRole.ANALYST)
        assert m.role == UserRole.ANALYST


class TestJWTClaims:
    def test_token_carries_org_id_role_and_jti(self):
        token = create_access_token(
            {"sub": "u-1"}, org_id="t-1", role="analyst",
        )
        payload = decode_token(token)
        assert payload["sub"] == "u-1"
        assert payload["org_id"] == "t-1"
        assert payload["role"] == "analyst"
        assert "jti" in payload
        assert len(payload["jti"]) == 32  # UUID4 hex

    def test_explicit_claims_not_overwritten(self):
        token = create_access_token(
            {"sub": "u", "org_id": "explicit", "jti": "custom-jti"},
            org_id="fallback",
        )
        payload = decode_token(token)
        assert payload["org_id"] == "explicit"
        assert payload["jti"] == "custom-jti"

    @pytest.mark.asyncio
    async def test_revocation_end_to_end(self):
        reset_revocation_store()
        token = create_access_token(
            {"sub": "u"}, org_id="t", role="analyst",
        )
        payload = decode_token(token)
        jti = payload["jti"]
        store = get_revocation_store()
        assert not await store.is_revoked(jti)
        await revoke_token(jti)
        assert await store.is_revoked(jti)


class TestRevocationStore:
    def test_in_memory_singleton(self):
        reset_revocation_store()
        first = get_revocation_store()
        second = get_revocation_store()
        assert first is second

    @pytest.mark.asyncio
    async def test_in_memory_isolation(self):
        s1 = InMemoryRevocationStore()
        s2 = InMemoryRevocationStore()
        await s1.revoke("abc", 60)
        assert await s1.is_revoked("abc")
        assert not await s2.is_revoked("abc")


class TestRBACMatrix:
    def test_public_paths(self):
        assert _is_public("/health")
        assert _is_public("/status")
        assert _is_public("/docs")
        assert _is_public("/auth/login")
        assert _is_public("/ui/index.html")
        assert not _is_public("/scans")

    def test_get_requires_only_viewer(self):
        assert _required_role("GET", "/scans") == UserRole.VIEWER

    def test_post_requires_analyst(self):
        assert _required_role("POST", "/scans") == UserRole.ANALYST

    def test_delete_requires_admin(self):
        assert _required_role("DELETE", "/scans/abc") == UserRole.ADMIN

    def test_role_satisfies_matrix(self):
        # Analyst can write but not delete.
        assert _role_satisfies("analyst", UserRole.VIEWER)
        assert _role_satisfies("analyst", UserRole.ANALYST)
        assert not _role_satisfies("analyst", UserRole.ADMIN)
        # Admin can do everything.
        assert _role_satisfies("admin", UserRole.ADMIN)
        # Viewer only reads.
        assert _role_satisfies("viewer", UserRole.VIEWER)
        assert not _role_satisfies("viewer", UserRole.ANALYST)
        # Bogus role rejects everything except viewer (defaults to viewer OK).
        assert _role_satisfies("badrole", UserRole.VIEWER)
        assert not _role_satisfies("badrole", UserRole.ANALYST)


class TestWorkspacePaths:
    def test_tenant_scoped_path(self, tmp_path: Path):
        p = resolve_workspace(
            tmp_path,
            session_id="sess_abcd1234",
            tenant_id="00000000-0000-0000-0000-000000000001",
        )
        assert p.parent.name == "00000000-0000-0000-0000-000000000001"
        assert p.name == "sess_abcd1234"

    def test_no_tenant_falls_back_to_public(self, tmp_path: Path):
        p = resolve_workspace(tmp_path, session_id="sess_abcd1234")
        assert p.parent.name == "public"

    def test_upload_dir(self, tmp_path: Path):
        d = resolve_upload_dir(tmp_path, tenant_id="00000000-0000-0000-0000-000000000001")
        assert d.name == "uploads"
        assert d.parent.name == "00000000-0000-0000-0000-000000000001"

    def test_reject_path_traversal_in_tenant(self, tmp_path: Path):
        with pytest.raises(WorkspaceError):
            resolve_workspace(tmp_path, session_id="sess_ok12345",
                              tenant_id="../etc")

    def test_reject_path_traversal_in_session(self, tmp_path: Path):
        with pytest.raises(WorkspaceError):
            resolve_workspace(tmp_path, session_id="../etc/passwd",
                              tenant_id="00000000-0000-0000-0000-000000000001")

    def test_reject_too_short_session(self, tmp_path: Path):
        with pytest.raises(WorkspaceError):
            resolve_workspace(tmp_path, session_id="short")

    def test_reject_unicode_in_session(self, tmp_path: Path):
        with pytest.raises(WorkspaceError):
            resolve_workspace(tmp_path, session_id="sessión12345",
                              tenant_id="00000000-0000-0000-0000-000000000001")
