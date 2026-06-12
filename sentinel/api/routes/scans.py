"""Scan lifecycle endpoints — wire the GUI to the real orchestrator.

POST   /scans                multipart upload of an APK + options
GET    /scans                list every scan tracked by this process
GET    /scans/{id}           summary + progress
GET    /scans/{id}/findings  full findings list
GET    /scans/{id}/result    full structured result (matches CLI JSON)
DELETE /scans/{id}           cancel + cleanup
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse

from sentinel.api.scan_runner import (
    ScanJob,
    get_registry,
    launch_scan,
)
from sentinel.auth.jwt_auth import get_current_active_user
from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

ALLOWED_EXTS = {".apk", ".aab", ".xapk"}


def _job_or_404(session_id: str) -> ScanJob:
    job = get_registry().get(session_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"scan {session_id} not found")
    return job


def _parse_options(options: str | None) -> dict[str, Any]:
    if not options:
        return {}
    try:
        data = json.loads(options)
        if not isinstance(data, dict):
            raise ValueError("options must be a JSON object")
        return data
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid options JSON: {e}",
        ) from e


def _bounded_int_option(
    opts: dict[str, Any],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = opts.get(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} must be an integer",
        ) from e
    if value < minimum or value > maximum:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} must be between {minimum} and {maximum}",
        )
    opts[name] = value
    return value


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    apk: UploadFile = File(..., description="APK/AAB file"),
    options: str | None = Form(
        default=None,
        description="JSON: {dynamic, frida, no_proxy, privacy, llm_triage, "
        "dynamic_duration, frida_duration, scope_text}",
    ),
    current_user: Any = Depends(get_current_active_user),
) -> JSONResponse:
    """Upload an APK and kick off a real scan.

    The file is streamed into `<workspace>/uploads/` so the orchestrator
    can hash and decompile it. A session_id is returned immediately
    while the scan runs in the background — poll GET /scans/{id} for
    progress.
    """
    settings = get_settings()

    if not apk.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="filename missing",
        )
    suffix = Path(apk.filename).suffix.lower()
    if suffix not in ALLOWED_EXTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported extension {suffix!r} (need .apk/.aab/.xapk)",
        )

    upload_dir = settings.workspace / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = (
        Path(apk.filename).name.replace("/", "_").replace("\\", "_")
    )
    stored_path = upload_dir / f"{uuid.uuid4().hex[:12]}-{safe_name}"

    max_bytes = settings.max_apk_size_mb * 1024 * 1024
    bytes_written = 0
    try:
        with stored_path.open("wb") as out:
            while True:
                chunk = await apk.read(1024 * 1024)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    out.close()
                    stored_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"APK exceeds {settings.max_apk_size_mb} MB "
                            "limit"
                        ),
                    )
                out.write(chunk)
    finally:
        await apk.close()

    if bytes_written == 0:
        stored_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="uploaded APK is empty",
        )

    opts = _parse_options(options)
    _bounded_int_option(opts, "dynamic_duration", 30, 1, 300)
    _bounded_int_option(opts, "frida_duration", 30, 1, 300)
    job = await launch_scan(
        apk_path=stored_path,
        apk_filename=safe_name,
        options=opts,
    )
    logger.info(
        "Scan %s launched: file=%s size=%d opts=%s",
        job.session_id, safe_name, bytes_written, opts,
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "session_id": job.session_id,
            "status": job.status,
            "apk_filename": safe_name,
            "apk_size_bytes": bytes_written,
            "created_at": job.created_at.isoformat(),
        },
    )


@router.get("")
def list_scans(
    current_user: Any = Depends(get_current_active_user),
) -> list[dict[str, Any]]:
    """Every scan tracked by this process (newest first)."""
    return [j.to_summary() for j in get_registry().all()]


@router.get("/{session_id}")
def get_scan(
    session_id: str,
    current_user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Live summary + status. Poll this for progress."""
    return _job_or_404(session_id).to_summary()


@router.get("/{session_id}/findings")
def get_findings(
    session_id: str,
    current_user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """All findings produced so far."""
    job = _job_or_404(session_id)
    return {
        "session_id": session_id,
        "status": job.status,
        "findings": job.finding_dicts(),
        "severity_counts": job.severity_counts(),
        "triage_counts": job.triage_counts(),
    }


@router.get("/{session_id}/result")
def get_result(
    session_id: str,
    current_user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Full structured scan result — same shape as the CLI --output JSON."""
    job = _job_or_404(session_id)
    return {
        "session_id": session_id,
        "status": job.status,
        "apk_filename": job.apk_filename,
        "apk_sha256": job.apk_sha256,
        "apk_size_bytes": job.apk_size_bytes,
        "manifest": job.manifest,
        "phase_timings": job.phase_timings,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": (
            job.completed_at.isoformat() if job.completed_at else None
        ),
        "error": job.error,
        "warnings": job.warnings,
        "severity_counts": job.severity_counts(),
        "triage_counts": job.triage_counts(),
        "findings": job.finding_dicts(),
        "options": job.options,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_scan(
    session_id: str,
    current_user: Any = Depends(get_current_active_user),
) -> Response:
    """Cancel a running scan and drop its record + uploaded APK."""
    ok = await get_registry().remove(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="scan not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
