"""Tenant context binding — ContextVar + Postgres RLS GUC plumbing.

The flow at request time looks like::

    async with tenant_scope(jwt_claims["tenant_id"]):
        async with engine.begin() as conn:
            await set_session_tenant(conn, current_tenant_id())
            # ... queries hit only this tenant's rows ...

`current_tenant_id()` returns the active value anywhere in the
call-stack inside `tenant_scope` (including from background tasks
that inherit the ContextVar). Outside the scope it returns None —
the OSS CLI never touches this module, and code that does should
fail closed when it sees None.

We use a Postgres GUC (`sentinel.tenant_id`) rather than per-tenant
roles because (a) one connection pool keeps PgBouncer compatibility
and (b) `SET LOCAL` resets at COMMIT/ROLLBACK so we cannot leak the
value to the next request reusing the same connection.
"""
from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import AsyncIterator

logger = logging.getLogger(__name__)

# UUID v4 / v7 shape; we accept the loose alnum form too so the OSS
# session-id format works in tests without forcing UUID generation.
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

# The single source of truth for "which tenant is this request for".
# Default None — a None value means "no tenancy bound", which the API
# layer must reject before touching the DB.
_current_tenant: ContextVar[str | None] = ContextVar(
    "sentinel_current_tenant", default=None,
)


class TenantContextError(RuntimeError):
    """Raised when tenant context is missing, malformed, or rebound."""


def current_tenant_id() -> str | None:
    """Return the tenant bound to the current async context, or None.

    Outside `tenant_scope` this is always None. Callers that require
    a tenant should raise `TenantContextError` themselves rather than
    silently fall through — making the failure mode explicit.
    """
    return _current_tenant.get()


@asynccontextmanager
async def tenant_scope(tenant_id: str) -> AsyncIterator[str]:
    """Bind a tenant for the duration of the `async with` block.

    Re-entrant scopes are forbidden by default: the API gateway should
    bind once per request and never re-bind. A nested `tenant_scope`
    raises `TenantContextError` rather than silently shadow the
    outer value — that would let a privilege bug in a background
    task escalate to cross-tenant reads.
    """
    if not isinstance(tenant_id, str) or not _TENANT_ID_RE.match(tenant_id):
        raise TenantContextError(
            f"Invalid tenant_id format: {tenant_id!r}"
        )

    prior = _current_tenant.get()
    if prior is not None and prior != tenant_id:
        raise TenantContextError(
            f"Cannot rebind tenant from {prior!r} to {tenant_id!r}"
        )

    token = _current_tenant.set(tenant_id)
    try:
        yield tenant_id
    finally:
        _current_tenant.reset(token)


async def set_session_tenant(conn, tenant_id: str | None) -> None:
    """Apply the Postgres RLS GUC for this transaction.

    `conn` is anything with an async `execute` method — SQLAlchemy
    AsyncConnection, asyncpg Connection, etc. We don't import the
    backend types here to keep the OSS install free of those deps.

    `SET LOCAL` is used deliberately: the value is scoped to the
    current transaction. When the pool returns the connection, the
    next request that does not set the GUC will see no rows under
    RLS — fail-closed.

    Refuses to silently no-op on None: that's a programming error,
    and the alternative is "you accidentally see no rows" which
    looks like a successful empty result to callers.
    """
    if tenant_id is None:
        raise TenantContextError(
            "set_session_tenant called with None — bind a tenant first"
        )
    if not _TENANT_ID_RE.match(tenant_id):
        raise TenantContextError(f"Invalid tenant_id format: {tenant_id!r}")

    # Use parameterised SET via `set_config` to defend against any
    # path where tenant_id might come from an untrusted source. SET
    # itself does NOT accept bind params, so the safe form is the
    # `set_config(name, value, is_local)` function.
    sql = "SELECT set_config('sentinel.tenant_id', $1, true)"
    try:
        # asyncpg-style
        await conn.execute(sql, tenant_id)
    except TypeError:
        # SQLAlchemy AsyncConnection.execute takes a text() clause
        from sqlalchemy import text  # local import — opt-in dep
        await conn.execute(
            text("SELECT set_config('sentinel.tenant_id', :tid, true)"),
            {"tid": tenant_id},
        )
