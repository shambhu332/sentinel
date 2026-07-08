"""Background janitor task for SENTINEL (Phase 1.4).

Responsibilities
----------------
1. Prune scan workspace directories older than SCAN_RETENTION_DAYS.
2. (Future) Purge revoked/expired JWT JTI records from the revocation store.

The janitor is started as a fire-and-forget asyncio.Task from the FastAPI
lifespan so it never blocks request handling.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL_S = 3600  # run once per hour


async def _prune_old_workspaces(workspace_root: Path, retention_days: int) -> int:
    """Delete session dirs whose mtime predates the retention window.

    Layout: ``<workspace_root>/<tenant_id>/<session_id>/``
    We only descend two levels so the janitor cannot accidentally walk
    arbitrary filesystem paths.
    """
    if not workspace_root.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    for tenant_dir in workspace_root.iterdir():
        if not tenant_dir.is_dir():
            continue
        for session_dir in tenant_dir.iterdir():
            if not session_dir.is_dir():
                continue
            mtime = datetime.fromtimestamp(
                session_dir.stat().st_mtime, tz=timezone.utc
            )
            if mtime < cutoff:
                shutil.rmtree(session_dir, ignore_errors=True)
                logger.info(
                    "janitor: pruned %s (last modified %s)",
                    session_dir.name,
                    mtime.date(),
                )
                removed += 1
    return removed


async def _janitor_loop(
    workspace_root: Path,
    retention_days: int,
    interval_seconds: int,
) -> None:
    """Infinite loop — runs until the task is cancelled at shutdown."""
    logger.info(
        "janitor: starting (retention=%dd, interval=%ds)",
        retention_days,
        interval_seconds,
    )
    while True:
        try:
            n = await _prune_old_workspaces(workspace_root, retention_days)
            if n:
                logger.info("janitor: pruned %d expired workspace(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("janitor: non-fatal error: %s", exc)
        await asyncio.sleep(interval_seconds)


def start_janitor(
    workspace_root: Path,
    retention_days: int = 30,
    interval_seconds: int = _DEFAULT_INTERVAL_S,
) -> "asyncio.Task[None]":
    """Create and return the janitor background task.

    Must be called from inside a running event loop (e.g., FastAPI lifespan).
    Cancel the returned task on shutdown to allow clean teardown.
    """
    return asyncio.create_task(
        _janitor_loop(workspace_root, retention_days, interval_seconds),
        name="sentinel-janitor",
    )


__all__ = ["start_janitor"]
