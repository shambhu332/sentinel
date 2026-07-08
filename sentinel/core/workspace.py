"""Tenant-scoped workspace path helpers (Phase 1.3).

Requirement from the production-hardening prompt:

    Every file path must be `workspace/{org_id}/{session_id}/`.

Old layout: `<workspace_root>/<session_id>/...`
New layout: `<workspace_root>/<tenant_id>/<session_id>/...`

`resolve_workspace()` is the single source of truth. Callers that
still use the old two-arg (`workspace_root`, `session_id`) form get
routed through the "public" tenant bucket so unauthenticated / local
CLI runs continue to work. Anything that opens a POST /scans handler
must supply the authenticated user's `tenant_id`.
"""
from __future__ import annotations

import re
from pathlib import Path

_TENANT_PUBLIC = "public"
_UUID_RE = re.compile(r"^[a-fA-F0-9\-]{8,64}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")


class WorkspaceError(ValueError):
    """Raised when tenant/session inputs would escape the workspace root."""


def _validate_tenant(tenant_id: str | None) -> str:
    """Return a filesystem-safe tenant segment, defaulting to `public`."""
    if not tenant_id:
        return _TENANT_PUBLIC
    if tenant_id == _TENANT_PUBLIC:
        return _TENANT_PUBLIC
    if not _UUID_RE.match(tenant_id):
        raise WorkspaceError(
            f"tenant_id {tenant_id!r} must be a UUID-shaped string "
            f"(alphanumeric, dash, 8-64 chars)"
        )
    return tenant_id


def _validate_session(session_id: str) -> str:
    if not _SESSION_RE.match(session_id):
        raise WorkspaceError(
            f"session_id {session_id!r} must be 8-64 chars, "
            f"alphanumeric/underscore/dash"
        )
    return session_id


def resolve_workspace(
    workspace_root: Path,
    session_id: str,
    tenant_id: str | None = None,
) -> Path:
    """Return `<workspace_root>/<tenant_id>/<session_id>/`.

    Both segments are validated against strict regexes to prevent
    path traversal. `..` / absolute paths / unicode tricks are rejected.
    """
    tenant_segment = _validate_tenant(tenant_id)
    session_segment = _validate_session(session_id)
    resolved = (workspace_root / tenant_segment / session_segment).resolve()

    # Belt-and-braces — confirm the resolved path is still under root.
    root_resolved = workspace_root.resolve()
    if not str(resolved).startswith(str(root_resolved)):
        raise WorkspaceError(
            f"Resolved path {resolved} escapes workspace root {root_resolved}"
        )
    return resolved


def resolve_upload_dir(
    workspace_root: Path,
    tenant_id: str | None = None,
) -> Path:
    """Return `<workspace_root>/<tenant_id>/uploads/`."""
    tenant_segment = _validate_tenant(tenant_id)
    return (workspace_root / tenant_segment / "uploads").resolve()


__all__ = [
    "WorkspaceError",
    "resolve_upload_dir",
    "resolve_workspace",
]
