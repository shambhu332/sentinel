"""VAPT report endpoints.

Reports are written by R_001 (Phase 8) to
``<workspace>/<session_id>/reports/VAPT_Report_<session_id>.{md,html,json}``.
This router exposes them for the frontend Reports tab.

The endpoints are intentionally minimal:

* ``GET /reports`` — list every report on disk under the configured
  workspace, newest first.
* ``GET /reports/{session_id}/{fmt}`` — stream the requested artifact
  (``markdown`` / ``html`` / ``json``).

Auth is not required — the gateway binds to ``127.0.0.1`` by default
and reports never leave the workspace volume. If the deployment wants
auth they can apply ``Depends(get_current_active_user)`` later.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# Session IDs match this exact pattern (see sentinel/core/scan_context.py)
_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

_FORMATS: dict[str, dict[str, str]] = {
    "markdown": {"ext": ".md", "mime": "text/markdown"},
    "html": {"ext": ".html", "mime": "text/html"},
    "json": {"ext": ".json", "mime": "application/json"},
}


@router.get("")
def list_reports() -> JSONResponse:
    """Return every VAPT report on disk in the workspace, newest first."""
    settings = get_settings()
    workspace_root = Path(settings.workspace)
    reports: list[dict] = []

    if not workspace_root.exists():
        return JSONResponse(content=reports)

    # Layout: <workspace>/<session_id>/reports/VAPT_Report_<id>.{md,html,json}
    for session_dir in workspace_root.iterdir():
        if not session_dir.is_dir():
            continue
        reports_dir = session_dir / "reports"
        if not reports_dir.exists():
            continue
        session_id = session_dir.name
        md = reports_dir / f"VAPT_Report_{session_id}.md"
        html = reports_dir / f"VAPT_Report_{session_id}.html"
        json_path = reports_dir / f"VAPT_Report_{session_id}.json"
        if not any(p.exists() for p in (md, html, json_path)):
            continue

        # Use the JSON artifact's mtime if present, else the dir mtime.
        ref = json_path if json_path.exists() else session_dir
        mtime = datetime.fromtimestamp(ref.stat().st_mtime, tz=timezone.utc)

        # Parse a tiny set of fields out of the JSON for the list view.
        summary = _read_json_summary(json_path) if json_path.exists() else {}

        reports.append({
            "session_id": session_id,
            "generated_at": mtime.isoformat(timespec="seconds"),
            "formats": {
                fmt: {
                    "available": (reports_dir / f"VAPT_Report_{session_id}{meta['ext']}").exists(),
                    "url": f"/reports/{session_id}/{fmt}",
                    "size_bytes": _size_of(reports_dir / f"VAPT_Report_{session_id}{meta['ext']}"),
                }
                for fmt, meta in _FORMATS.items()
            },
            "package": summary.get("package", ""),
            "version": summary.get("version", ""),
            "risk_score": summary.get("risk", {}).get("score"),
            "risk_band": summary.get("risk", {}).get("band"),
            "severity_counts": summary.get("severity_counts", {}),
            "total_findings": len(summary.get("findings") or []),
        })

    reports.sort(key=lambda r: r["generated_at"], reverse=True)
    return JSONResponse(content=reports)


@router.get("/{session_id}/{fmt}")
def get_report(session_id: str, fmt: str) -> FileResponse:
    """Stream a single VAPT-report artifact."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid session_id",
        )
    meta = _FORMATS.get(fmt)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown format {fmt!r}; expected one of {list(_FORMATS)}",
        )
    settings = get_settings()
    candidate = (
        Path(settings.workspace)
        / session_id
        / "reports"
        / f"VAPT_Report_{session_id}{meta['ext']}"
    )
    if not candidate.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no {fmt} report for session {session_id}",
        )
    # FileResponse handles range requests + correct content-type +
    # last-modified for free.
    return FileResponse(
        path=str(candidate),
        media_type=meta["mime"],
        filename=candidate.name,
    )


# ---------- helpers ----------


def _size_of(path: Path) -> int:
    try:
        return path.stat().st_size if path.exists() else 0
    except OSError:
        return 0


def _read_json_summary(path: Path) -> dict:
    """Read the JSON report's top-level fields; tolerate parse errors."""
    import json
    try:
        return json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
