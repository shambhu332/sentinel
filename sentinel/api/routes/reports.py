"""VAPT report endpoints.

Reports are written by R_001 (Phase 8) to
``<workspace>/<session_id>/reports/VAPT_Report_<session_id>.{md,html,json}``.
This router exposes them for the frontend Reports tab.

The endpoints are intentionally minimal:

* ``GET /reports`` — list every report on disk under the configured
  workspace, newest first.
* ``GET /reports/{session_id}/{fmt}`` — stream the requested artifact
  (``markdown`` / ``html`` / ``json``).

Auth is required because reports contain confidential APK/package
metadata and vulnerability evidence.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from sentinel.auth.jwt_auth import get_current_active_user
from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# Session IDs match this exact pattern (see sentinel/core/scan_context.py)
_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

_FORMATS: dict[str, dict[str, str]] = {
    "markdown": {"ext": ".md", "mime": "text/markdown"},
    "html": {"ext": ".html", "mime": "text/html"},
    "json": {"ext": ".json", "mime": "application/json"},
    "sarif": {"ext": ".sarif", "mime": "application/sarif+json"},
}


@router.get("")
def list_reports(current_user=Depends(get_current_active_user)) -> JSONResponse:
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
def get_report(
    session_id: str,
    fmt: str,
    current_user=Depends(get_current_active_user),
) -> FileResponse:
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
    workspace_root = Path(settings.workspace).resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(workspace_root):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid report path",
        )
    # FileResponse handles range requests + correct content-type +
    # last-modified for free.
    return FileResponse(
        path=str(resolved),
        media_type=meta["mime"],
        filename=candidate.name,
    )


@router.post("/{session_id}/regenerate")
async def regenerate_report(
    session_id: str,
    current_user=Depends(get_current_active_user),
) -> JSONResponse:
    """Re-run VAPT report rendering for a completed scan.

    Useful when Phase 8 timed out during the original scan but the
    findings are still held by the in-memory ScanRegistry. We skip the
    full agent (and its heavy ScanContext requirements) and call the
    builder + renderers directly. LLM narrative enrichment falls back to
    deterministic boilerplate if no provider is reachable, so this stays
    fast and always produces something.
    """
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="invalid session_id")

    from sentinel.agents.reporting.builder import build_report_data
    from sentinel.agents.reporting.enrich import enrich_sections
    from sentinel.agents.reporting.templates import render_html, render_markdown
    from sentinel.api.scan_runner import get_registry
    from sentinel.core.finding import Severity, TriageState

    job = get_registry().get(session_id)
    if job is None:
        raise HTTPException(
            status_code=404, detail=f"no scan in registry for {session_id}",
        )
    findings = [
        f for f in job.findings
        if f.severity != Severity.INFO and f.triage != TriageState.FALSE_POSITIVE
    ]
    if not findings:
        raise HTTPException(
            status_code=409,
            detail="no reportable findings (all INFO or filtered) — nothing to render",
        )

    try:
        from sentinel.reports.cvss import stamp_all
        stamp_all(findings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("regen: CVSS stamping failed: %s", exc)

    data = build_report_data(
        findings=findings,
        package=job.manifest.get("package") or "(unknown)",
        version=job.manifest.get("version_name") or "(unknown)",
        session_id=session_id,
        apk_sha256=job.apk_sha256 or "",
        apk_size_bytes=job.apk_size_bytes or 0,
        generated_at=datetime.now(timezone.utc),
    )

    router_obj = None
    try:
        from sentinel.llm.router import FreeProviderRouter
        router_obj = FreeProviderRouter()
    except Exception as exc:  # noqa: BLE001
        logger.info("regen: LLM router unavailable, using boilerplate (%s)", exc)
    try:
        await enrich_sections(data.sections, router_obj)
    except Exception as exc:  # noqa: BLE001
        logger.warning("regen: narrative enrichment failed: %s", exc)
        await enrich_sections(data.sections, None)
    finally:
        if router_obj is not None:
            try:
                await router_obj.close()
            except Exception:  # noqa: BLE001
                pass

    report_dir = Path(get_settings().workspace) / session_id / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    stem = f"VAPT_Report_{session_id}"
    written: dict[str, str] = {}

    md_path = report_dir / f"{stem}.md"
    md_path.write_text(render_markdown(data), encoding="utf-8")
    written["markdown"] = str(md_path)

    html_path = report_dir / f"{stem}.html"
    html_path.write_text(render_html(data), encoding="utf-8")
    written["html"] = str(html_path)

    import json as _json
    from sentinel.agents.reporting.r001_report_agent import ReportGeneratorAgent
    json_path = report_dir / f"{stem}.json"
    json_path.write_text(
        _json.dumps(ReportGeneratorAgent._json_payload(data), indent=2, default=str),
        encoding="utf-8",
    )
    written["json"] = str(json_path)

    try:
        from sentinel.reports.sarif import render_sarif_json
        sarif_path = report_dir / f"{stem}.sarif"
        sarif_path.write_text(
            render_sarif_json([s.finding for s in data.sections], session_id),
            encoding="utf-8",
        )
        written["sarif"] = str(sarif_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("regen: SARIF render failed: %s", exc)

    return JSONResponse(content={
        "session_id": session_id,
        "regenerated": True,
        "artifacts": written,
        "finding_count": len(findings),
    })


@router.get("/{session_id}/siem.zip")
def get_siem_bundle(
    session_id: str,
    current_user=Depends(get_current_active_user),
) -> Response:
    """Build + stream a SIEM detection-rule bundle for ``session_id``."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="invalid session_id")
    findings = _load_findings_for_session(session_id)
    if not findings:
        raise HTTPException(status_code=404, detail="no findings for session")
    from sentinel.reports.siem import build_bundle
    blob = build_bundle(findings, session_id)
    return Response(
        content=blob, media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="sentinel-siem-{session_id}.zip"',
        },
    )


@router.get("/{session_id}/poc/index.json")
def get_poc_index(
    session_id: str,
    current_user=Depends(get_current_active_user),
) -> JSONResponse:
    """List PoC artifacts emitted by the PoC Studio during the scan."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="invalid session_id")
    idx_path = (
        Path(get_settings().workspace) / session_id / "poc" / "index.json"
    )
    if not idx_path.exists():
        return JSONResponse(content=[])
    import json
    try:
        return JSONResponse(content=json.loads(idx_path.read_text()))
    except (OSError, json.JSONDecodeError):
        return JSONResponse(content=[])


@router.get("/{session_id}/evidence/{filename}")
def get_evidence_file(
    session_id: str,
    filename: str,
    current_user=Depends(get_current_active_user),
) -> FileResponse:
    """Stream a visual-evidence artifact (screenshot) for a finding.

    Captured by adb_runner.screenshot() during dynamic testing and
    referenced from Finding.screenshots as a relative path like
    ``evidence/before_exploit_1718537400123.png``.
    """
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="invalid session_id")
    if "/" in filename or ".." in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="invalid filename")
    workspace_root = Path(get_settings().workspace).resolve()
    candidate = (
        workspace_root / session_id / "evidence" / filename
    ).resolve()
    if not candidate.is_relative_to(workspace_root) or not candidate.exists():
        raise HTTPException(status_code=404, detail="not found")
    # Lock to PNG/JPEG/WebP — screenshots are images only.
    suffix = candidate.suffix.lower()
    mime = {
        ".png": "image/png", ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg", ".webp": "image/webp",
    }.get(suffix)
    if mime is None:
        raise HTTPException(status_code=400, detail="unsupported media type")
    return FileResponse(path=str(candidate), media_type=mime, filename=filename)


@router.get("/{session_id}/poc/{filename}")
def get_poc_file(
    session_id: str,
    filename: str,
    current_user=Depends(get_current_active_user),
) -> FileResponse:
    """Stream one PoC artifact."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="invalid session_id")
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="invalid filename")
    workspace_root = Path(get_settings().workspace).resolve()
    candidate = (
        workspace_root / session_id / "poc" / filename
    ).resolve()
    if not candidate.is_relative_to(workspace_root) or not candidate.exists():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path=str(candidate), filename=filename)


# ---------- helpers ----------


def _load_findings_for_session(session_id: str):
    """Reconstruct Finding objects from the JSON report on disk.

    The SIEM bundle builder needs the same Finding objects the scan
    produced. Since the API process is stateless once a scan completes,
    we re-hydrate from the JSON report R_001 already wrote.
    """
    import json as _json

    from sentinel.core.finding import Finding
    json_path = (
        Path(get_settings().workspace)
        / session_id / "reports"
        / f"VAPT_Report_{session_id}.json"
    )
    if not json_path.exists():
        return []
    try:
        doc = _json.loads(json_path.read_text(errors="replace"))
    except (_json.JSONDecodeError, OSError):
        return []
    out = []
    for raw in doc.get("findings", []) or []:
        try:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            row["session_id"] = row.get("session_id") or session_id
            row["severity"] = _coerce_severity(row.get("severity")).value
            row["confidence"] = float(row.get("confidence") or 0.5)
            row["recommendation"] = row.get("recommendation") or ""
            row["evidence"] = row.get("evidence") or {}
            row.pop("finding_id", None)
            row.pop("rag_mapping", None)
            row.pop("rag_passage_ids", None)
            row.pop("triage_explanation", None)
            out.append(Finding.model_validate(row))
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "failed to rehydrate finding for SIEM bundle: %s", exc,
            )
            continue
    return out


def _coerce_severity(value: object):
    from sentinel.core.finding import Severity

    text = str(value or "").strip().lower()
    for severity in Severity:
        if text in {severity.value.lower(), severity.name.lower()}:
            return severity
    return Severity.INFO



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


# ---------------------------------------------------------------------------
# Async report generation endpoints (Phase 6)
# ---------------------------------------------------------------------------

class AsyncReportRequest(BaseModel):
    formats: list[str] = ["markdown", "html", "json", "sarif"]
    webhook_url: str = ""


@router.post("/{session_id}/generate")
def generate_report_async(
    session_id: str,
    body: AsyncReportRequest | None = None,
    current_user=Depends(get_current_active_user),
) -> JSONResponse:
    """Enqueue async report generation. Returns job_id for polling.

    When Redis is configured, delegates to an RQ worker and returns
    immediately with status=queued. When Redis is absent, generates
    synchronously and returns status=completed.
    """
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session_id")

    from sentinel.queue.jobs import enqueue_report

    req = body or AsyncReportRequest()
    result = enqueue_report(
        session_id=session_id,
        formats=req.formats,
        webhook_url=req.webhook_url,
    )
    http_status = 202 if result.get("status") == "queued" else 200
    return JSONResponse(content=result, status_code=http_status)


@router.get("/jobs/{job_id}")
def get_job_status(
    job_id: str,
    current_user=Depends(get_current_active_user),
) -> JSONResponse:
    """Poll async report job status and result."""
    from sentinel.queue.jobs import get_job_status as _get_status
    return JSONResponse(content=_get_status(job_id))
