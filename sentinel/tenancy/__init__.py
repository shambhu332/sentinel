"""Tenancy primitives for SENTINEL SaaS.

This package isolates everything that depends on running in a
multi-tenant context. The OSS / single-user CLI does not import from
here at all — the rest of the codebase treats `tenant_id` as an
optional value on `Finding` and the API gateway sets it from the JWT
before persisting.

Public surface:
    current_tenant_id()      — ContextVar-backed read (returns None outside SaaS)
    tenant_scope(tenant_id)  — async context manager binding tenant for the request
    set_session_tenant(conn) — apply the RLS GUC on a Postgres connection
"""
from sentinel.tenancy.context import (
    TenantContextError,
    current_tenant_id,
    set_session_tenant,
    tenant_scope,
)

__all__ = [
    "TenantContextError",
    "current_tenant_id",
    "set_session_tenant",
    "tenant_scope",
]
