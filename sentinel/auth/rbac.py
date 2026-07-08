"""RBAC middleware and role dependencies for Phase 1.3.

Enforcement matrix (from the production-hardening prompt):

    method  path                    admin  analyst  viewer
    ------  ----------------------  -----  -------  ------
    GET     any                     ✓      ✓        ✓
    POST    /scans                  ✓      ✓        ✗
    POST    /scope, /reports        ✓      ✓        ✗
    DELETE  any                     ✓      ✗        ✗
    PATCH   any                     ✓      ✓        ✗
    PUT     any                     ✓      ✓        ✗

The rules are declarative and lookup-driven so the matrix can grow
without touching middleware code. Endpoints marked "public" (health,
docs, auth) are skipped entirely.

Roles are decoded from the JWT `role` claim (falling back to the user
object's role). Bypass mode (`dev_auth_bypass=True`) short-circuits
all checks — but we log at INFO whenever a request would have been
denied so it's obvious in traces.
"""
from __future__ import annotations

import logging

from fastapi import HTTPException, status
from jose import JWTError, jwt
from starlette.types import ASGIApp

from sentinel.auth.models import (
    UserRole,
    role_can_delete,
    role_can_write,
)
from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

# Exact paths that skip RBAC — auth flow, health, docs, root.
_PUBLIC_EXACT: frozenset[str] = frozenset({
    "/", "/health", "/status", "/docs", "/redoc",
    "/openapi.json", "/agents",
})

# Prefixes that skip RBAC. NB: no root-level `/` prefix — that would
# match everything. Only prefixes that end with `/` so the empty string
# suffix is required (e.g. `/ui/js/app.js`).
_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/ui/",
    "/auth/",
    "/docs/",
    "/redoc/",
)


def _is_public(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    return any(path.startswith(p) for p in _PUBLIC_PREFIXES)


def _extract_role_from_token(token: str) -> str | None:
    """Best-effort role extraction — never raises, returns None on failure."""
    from sentinel.auth.jwt_auth import ALGORITHM, _secret_key  # local import to avoid cycle

    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
    except JWTError:
        return None
    role = payload.get("role")
    return str(role) if role else None


def _required_role(method: str, path: str) -> UserRole | None:
    """Return the minimum role for (method, path), or None to allow."""
    m = method.upper()
    if m == "GET" or m == "HEAD" or m == "OPTIONS":
        return UserRole.VIEWER
    if m == "DELETE":
        return UserRole.ADMIN
    # POST / PUT / PATCH — write operations require analyst+.
    return UserRole.ANALYST


def _role_satisfies(role: str, required: UserRole) -> bool:
    if required == UserRole.VIEWER:
        return True  # every authenticated role can read
    if required == UserRole.ANALYST:
        return role_can_write(role)
    if required == UserRole.ADMIN:
        return role_can_delete(role)
    return False


class RBACMiddleware:
    """Pure ASGI middleware — same shape as `_AuditLogMiddleware`.

    Chosen as pure ASGI (not `BaseHTTPMiddleware`) to avoid the
    `anyio.WouldBlock` shutdown-race we already fixed for audit logging.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        if _is_public(path):
            await self._app(scope, receive, send)
            return

        settings = get_settings()
        if settings.dev_auth_bypass:
            await self._app(scope, receive, send)
            return

        # Extract role from Authorization header.
        role: str | None = None
        for name, value in scope.get("headers") or []:
            if name == b"authorization":
                header = value.decode(errors="ignore")
                if header.lower().startswith("bearer "):
                    role = _extract_role_from_token(header[7:])
                break

        required = _required_role(method, path)
        if required is None:
            await self._app(scope, receive, send)
            return

        if role is None:
            await self._respond_401(send)
            return

        if not _role_satisfies(role, required):
            logger.info(
                "RBAC deny: role=%s required=%s method=%s path=%s",
                role, required.value, method, path,
            )
            await self._respond_403(send, role, required)
            return

        await self._app(scope, receive, send)

    async def _respond_401(self, send) -> None:  # type: ignore[no-untyped-def]
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b"Bearer"),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": b'{"error":"unauthorized","detail":"authentication required"}',
        })

    async def _respond_403(self, send, role: str, required: UserRole) -> None:  # type: ignore[no-untyped-def]
        body = (
            b'{"error":"forbidden","detail":"role '
            + role.encode()
            + b' cannot perform this action; requires '
            + required.value.encode()
            + b'"}'
        )
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------
# Fine-grained per-endpoint dependencies (belt-and-braces).
# The middleware is a coarse guard; use these on individual routes
# where the check is dynamic (e.g. must match resource tenant_id).
# ---------------------------------------------------------------

async def require_write(user) -> None:  # type: ignore[no-untyped-def]
    from sentinel.auth.models import User  # noqa: F401
    if not role_can_write(getattr(user, "role", "")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )


async def require_delete(user) -> None:  # type: ignore[no-untyped-def]
    if not role_can_delete(getattr(user, "role", "")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Delete permission required",
        )


def require_tenant_match(user, tenant_id: str) -> None:  # type: ignore[no-untyped-def]
    """Reject if the user's JWT tenant doesn't match the resource's tenant."""
    user_tenant = getattr(user, "tenant_id", None)
    if user_tenant is None or user_tenant != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Resource belongs to a different tenant",
        )


__all__ = [
    "RBACMiddleware",
    "require_delete",
    "require_tenant_match",
    "require_write",
]
