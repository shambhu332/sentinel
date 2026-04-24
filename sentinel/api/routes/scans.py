"""Scan lifecycle endpoints.

These are STUB implementations for Sprint 1.2b. Real orchestrator integration
arrives in Sprint 2. Each stub returns the correct shape so the CLI and GUI
can be built against a stable API contract.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field
from sentinel.core.finding import BountyScope
from sentinel.core.scan_context import generate_session_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreateRequest(BaseModel):
    apk_path: str = Field(..., min_length=1, max_length=2000)
    scope: BountyScope | None = None
    data_sensitivity: Literal["public", "private"] = "public"
    agents: list[str] | None = None  # agent ID filter; None = all
    allow_destructive: bool = False


class ScanSummary(BaseModel):
    session_id: str
    apk_path: str
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    data_sensitivity: str
    started_at: datetime
    findings_count: int = 0


class ScanCreateResponse(BaseModel):
    session_id: str
    status: str


# Temporary in-memory registry. Sprint 2 replaces this with SQLite.
_scans: dict[str, ScanSummary] = {}


@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(req: ScanCreateRequest) -> ScanCreateResponse:
    """Enqueue a new scan.

    Sprint 1.2b: stub that creates a session but does not run anything.
    Sprint 2: wires to the real Orchestrator.
    """
    session_id = generate_session_id()
    summary = ScanSummary(
        session_id=session_id,
        apk_path=req.apk_path,
        status="queued",
        data_sensitivity=req.data_sensitivity,
        started_at=datetime.now(timezone.utc),
    )
    _scans[session_id] = summary
    logger.info("Scan queued: %s (apk=%s)", session_id, req.apk_path)
    return ScanCreateResponse(session_id=session_id, status="queued")


@router.get("", response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    """List all scans (newest first)."""
    return sorted(_scans.values(), key=lambda s: s.started_at, reverse=True)


@router.get("/{session_id}", response_model=ScanSummary)
def get_scan(session_id: str) -> ScanSummary:
    """Retrieve a specific scan by session ID."""
    if session_id not in _scans:
        raise HTTPException(status_code=404, detail="scan not found")
    return _scans[session_id]


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def cancel_scan(session_id: str) -> Response:
    """Cancel a scan (stub). Returns 204 No Content on success."""
    if session_id not in _scans:
        raise HTTPException(status_code=404, detail="scan not found")
    _scans[session_id].status = "cancelled"
    return Response(status_code=status.HTTP_204_NO_CONTENT)