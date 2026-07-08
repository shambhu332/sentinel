"""Async job queue for report generation and long-running scan tasks.

Workers are started with:
    rq worker sentinel-default --url $REDIS_URL

Falls back to synchronous execution when Redis is not configured so local
dev never requires a running Redis instance.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_QUEUE_NAME = "sentinel-default"


def _get_queue() -> Any | None:
    """Return an RQ Queue or None when Redis is unavailable."""
    try:
        from sentinel.core.config import get_settings
        settings = get_settings()
        if not settings.redis_url:
            return None
        import redis
        from rq import Queue  # type: ignore[import-untyped]
        conn = redis.from_url(settings.redis_url)
        return Queue(_QUEUE_NAME, connection=conn)
    except Exception as e:  # noqa: BLE001
        logger.debug("[queue] Redis unavailable, falling back to sync: %s", e)
        return None


def enqueue_report(
    session_id: str,
    formats: list[str] | None = None,
    webhook_url: str = "",
    job_timeout: int = 3600,
) -> dict[str, Any]:
    """Enqueue async report generation. Returns job metadata."""
    if formats is None:
        formats = ["markdown", "html", "json", "sarif"]

    queue = _get_queue()
    if queue is None:
        # Synchronous fallback — generate inline.
        logger.info("[queue] sync fallback: generating report for %s", session_id)
        result = _generate_report_sync(session_id, formats, webhook_url)
        return {"job_id": None, "status": "completed", "result": result}

    try:
        from rq.job import Job  # type: ignore[import-untyped]
        job = queue.enqueue(
            "sentinel.queue.jobs._generate_report_sync",
            session_id,
            formats,
            webhook_url,
            job_timeout=job_timeout,
            result_ttl=86400,
        )
        logger.info("[queue] enqueued report job %s for session %s", job.id, session_id)
        return {"job_id": job.id, "status": "queued"}
    except Exception as e:  # noqa: BLE001
        logger.warning("[queue] enqueue failed, falling back to sync: %s", e)
        result = _generate_report_sync(session_id, formats, webhook_url)
        return {"job_id": None, "status": "completed", "result": result}


def get_job_status(job_id: str) -> dict[str, Any]:
    """Return current job status and result (if finished)."""
    try:
        from sentinel.core.config import get_settings
        settings = get_settings()
        if not settings.redis_url:
            return {"job_id": job_id, "status": "unknown", "error": "Redis not configured"}
        import redis
        from rq.job import Job  # type: ignore[import-untyped]
        conn = redis.from_url(settings.redis_url)
        job = Job.fetch(job_id, connection=conn)
        status = job.get_status()
        return {
            "job_id": job_id,
            "status": str(status),
            "progress": job.meta.get("progress", 0),
            "result": job.result if job.is_finished else None,
            "error": str(job.exc_info) if job.is_failed else None,
        }
    except Exception as e:  # noqa: BLE001
        return {"job_id": job_id, "status": "error", "error": str(e)}


def _generate_report_sync(
    session_id: str,
    formats: list[str],
    webhook_url: str = "",
) -> dict[str, Any]:
    """Synchronous report generation — called directly or by RQ worker."""
    import asyncio
    from pathlib import Path

    from sentinel.core.config import get_settings

    settings = get_settings()
    workspace = Path(settings.workspace) / session_id
    reports_dir = workspace / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    generated: list[str] = []

    # Load findings from the scan's JSON summary if available.
    findings_file = workspace / "findings.json"
    findings_data: list[dict[str, Any]] = []
    if findings_file.exists():
        import json
        try:
            findings_data = json.loads(findings_file.read_text())
        except Exception:  # noqa: BLE001
            pass

    for fmt in formats:
        try:
            out_path = _render_format(fmt, session_id, findings_data, reports_dir)
            if out_path:
                generated.append(str(out_path))
        except Exception as e:  # noqa: BLE001
            logger.warning("[queue] report format %s failed: %s", fmt, e)

    result = {
        "session_id": session_id,
        "formats_generated": generated,
        "findings_count": len(findings_data),
    }

    if webhook_url:
        asyncio.run(_fire_webhook(webhook_url, session_id, result))

    return result


def _render_format(
    fmt: str,
    session_id: str,
    findings: list[dict[str, Any]],
    out_dir: "Path",
) -> "Path | None":
    """Render a single format. Returns output path or None on skip."""
    from pathlib import Path

    if fmt == "json":
        import json
        path = out_dir / f"VAPT_Report_{session_id}.json"
        path.write_text(json.dumps(findings, indent=2))
        return path

    if fmt == "sarif":
        from sentinel.reports.sarif import render_sarif
        path = out_dir / f"VAPT_Report_{session_id}.sarif"
        path.write_text(render_sarif(session_id, findings))
        return path

    # markdown / html — delegate to existing report agent templates if available.
    try:
        if fmt == "markdown":
            from sentinel.agents.reporting.templates.markdown import render_markdown
            path = out_dir / f"VAPT_Report_{session_id}.md"
            path.write_text(render_markdown(session_id, findings))
            return path
        if fmt == "html":
            from sentinel.agents.reporting.templates.html import render_html
            path = out_dir / f"VAPT_Report_{session_id}.html"
            path.write_text(render_html(session_id, findings))
            return path
    except Exception as e:  # noqa: BLE001
        logger.debug("[queue] template render error for %s: %s", fmt, e)

    return None


async def _fire_webhook(url: str, session_id: str, result: dict[str, Any]) -> None:
    """POST completion notification to a webhook URL."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json={"session_id": session_id, "status": "completed", **result})
            logger.info("[queue] webhook fired for session %s → %s", session_id, url)
    except Exception as e:  # noqa: BLE001
        logger.warning("[queue] webhook failed for %s: %s", url, e)
