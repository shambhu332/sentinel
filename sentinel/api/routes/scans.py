"""Scan lifecycle endpoints — wire the GUI to the real orchestrator.

POST   /scans                   multipart upload of an APK + options
GET    /scans                   list every scan tracked by this process
GET    /scans/{id}              summary + progress
GET    /scans/{id}/findings     full findings list
GET    /scans/{id}/result       full structured result (matches CLI JSON)
GET    /scans/{id}/events       SSE stream of real-time scan events
DELETE /scans/{id}              cancel + cleanup
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
from fastapi.responses import JSONResponse, StreamingResponse

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

    # Phase 1.3 — tenant-scoped uploads. The current_user comes from
    # the JWT-carried org_id claim; unauthenticated / dev-bypass users
    # fall into the `public` tenant bucket via resolve_upload_dir.
    from sentinel.core.workspace import resolve_upload_dir
    tenant_id = getattr(current_user, "tenant_id", None) if current_user else None
    upload_dir = resolve_upload_dir(settings.workspace, tenant_id)
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

    # Phase 1.4 — encrypt at rest when a master key is configured.
    if settings.encryption_enabled():
        from sentinel.core.crypto import decode_master_key, derive_tenant_key, encrypt_file
        master_key = decode_master_key(settings.master_key)
        dek = derive_tenant_key(master_key, tenant_id or "public")
        stored_path = encrypt_file(stored_path, dek)
        logger.debug("Encrypted upload %s", stored_path.name)

    opts = _parse_options(options)
    _bounded_int_option(opts, "dynamic_duration", 30, 1, 300)
    _bounded_int_option(opts, "frida_duration", 30, 1, 300)
    # Stash tenant_id in options so scan_runner can derive the right DEK.
    opts["_tenant_id"] = tenant_id or "public"
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
        "tool_health": job.tool_health,
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


# ---------------------------------------------------------------------------
# SSE event stream (Phase 7)
# ---------------------------------------------------------------------------

@router.get("/{session_id}/events")
async def scan_events(
    session_id: str,
    current_user: Any = Depends(get_current_active_user),
) -> StreamingResponse:
    """Server-Sent Events stream for real-time scan progress.

    Clients connect with ``EventSource('/scans/{id}/events')``.
    Each event is a JSON object matching the ScanJob state snapshot.

    When Redis pub/sub is configured (REDIS_URL set), events are
    forwarded from the Redis channel ``scan:{session_id}:events``.
    Otherwise the endpoint polls the in-process ScanJob registry at
    500ms intervals and streams state changes — no Redis required for
    local dev.

    The stream ends automatically when the scan reaches a terminal
    state (completed / failed / cancelled).
    """
    import asyncio

    _job_or_404(session_id)  # 404 early if unknown

    async def _poll_stream():
        """Polling fallback: stream ScanJob snapshots every 500ms."""
        last_status: str | None = None
        last_finding_count: int = -1

        while True:
            try:
                job: ScanJob = _job_or_404(session_id)
            except HTTPException:
                yield _sse_event({"type": "error", "detail": "scan not found"})
                return

            current_count = len(job.finding_dicts())
            if job.status != last_status or current_count != last_finding_count:
                last_status = job.status
                last_finding_count = current_count
                yield _sse_event({
                    "type": "state",
                    "session_id": session_id,
                    "status": job.status,
                    "findings_count": current_count,
                    "severity_counts": job.severity_counts(),
                    "phase_timings": job.phase_timings,
                    "error": job.error,
                })

            if job.status in ("completed", "failed", "cancelled"):
                yield _sse_event({"type": "done", "status": job.status})
                return

            await asyncio.sleep(0.5)

    async def _redis_stream():
        """Redis pub/sub: forward scan events from channel."""
        import asyncio
        import redis.asyncio as aioredis

        settings = get_settings()
        client = aioredis.from_url(settings.redis_url)
        pubsub = client.pubsub()
        channel = f"scan:{session_id}:events"
        await pubsub.subscribe(channel)

        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    raw = message["data"]
                    yield _sse_event(json.loads(raw) if isinstance(raw, (str, bytes)) else raw)
                    # Check for terminal event
                    try:
                        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
                        if data.get("type") == "done":
                            return
                    except Exception:  # noqa: BLE001
                        pass
        finally:
            await pubsub.unsubscribe(channel)
            await client.aclose()

    settings = get_settings()
    generator = _redis_stream() if settings.redis_url else _poll_stream()

    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


def _sse_event(data: dict[str, Any]) -> str:
    """Format a dict as a Server-Sent Event data line."""
    return f"data: {json.dumps(data)}\n\n"
