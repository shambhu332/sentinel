"""Unit tests for the tenancy ContextVar + RLS GUC helper."""
from __future__ import annotations

import asyncio

import pytest

from sentinel.tenancy import (
    TenantContextError,
    current_tenant_id,
    set_session_tenant,
    tenant_scope,
)


@pytest.mark.asyncio
async def test_no_tenant_outside_scope():
    assert current_tenant_id() is None


@pytest.mark.asyncio
async def test_scope_binds_and_unbinds():
    assert current_tenant_id() is None
    async with tenant_scope("tenant_abc123") as tid:
        assert tid == "tenant_abc123"
        assert current_tenant_id() == "tenant_abc123"
    assert current_tenant_id() is None


@pytest.mark.asyncio
async def test_invalid_tenant_id_rejected():
    with pytest.raises(TenantContextError):
        async with tenant_scope("bad id with spaces"):
            pass
    with pytest.raises(TenantContextError):
        async with tenant_scope(""):
            pass


@pytest.mark.asyncio
async def test_nested_rebind_forbidden():
    async with tenant_scope("tenant_alpha"):
        with pytest.raises(TenantContextError):
            async with tenant_scope("tenant_beta"):
                pass


@pytest.mark.asyncio
async def test_nested_same_tenant_allowed():
    """Same-tenant nesting is harmless and supports refactor-friendly code."""
    async with tenant_scope("tenant_alpha"):
        async with tenant_scope("tenant_alpha"):
            assert current_tenant_id() == "tenant_alpha"
        assert current_tenant_id() == "tenant_alpha"


@pytest.mark.asyncio
async def test_context_isolated_across_tasks():
    """Two parallel tasks must not see each other's tenant binding."""
    seen: dict[str, str | None] = {}

    async def task(name: str, tid: str) -> None:
        async with tenant_scope(tid):
            await asyncio.sleep(0.01)
            seen[name] = current_tenant_id()

    await asyncio.gather(
        task("a", "tenant_alpha"),
        task("b", "tenant_beta"),
    )
    assert seen == {"a": "tenant_alpha", "b": "tenant_beta"}
    assert current_tenant_id() is None


@pytest.mark.asyncio
async def test_set_session_tenant_refuses_none():
    class _Conn:
        async def execute(self, *a, **kw):  # pragma: no cover - never called
            return None

    with pytest.raises(TenantContextError):
        await set_session_tenant(_Conn(), None)


@pytest.mark.asyncio
async def test_set_session_tenant_invokes_set_config_asyncpg_style():
    seen: list[tuple] = []

    class _Conn:
        async def execute(self, sql, *args):
            seen.append((sql, args))

    await set_session_tenant(_Conn(), "tenant_alpha")
    assert len(seen) == 1
    sql, args = seen[0]
    assert "set_config" in sql
    assert "sentinel.tenant_id" in sql
    assert args == ("tenant_alpha",)
