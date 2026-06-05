"""In-process scan runner used by the FastAPI gateway.

Wraps the full Orchestrator pipeline so the GUI can launch a real scan
against an uploaded APK and poll for status/findings. Keeps an
in-memory registry of running and completed scans so multiple GET
requests can read progress without re-launching the work.

This is intentionally simple — single process, in-memory state. A
persistent SQLite-backed scheduler can replace it later, but until
then this is what makes "click scan -> see findings" actually work.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.agents.auth import HardcodedSecretsAgent
from sentinel.agents.auth_storage import InsecureAuthStorageAgent
from sentinel.agents.backup import InsecureBackupAgent
from sentinel.agents.cert_pinning import MissingCertPinningAgent
from sentinel.agents.cloud import FirebaseMisconfigAgent
from sentinel.agents.crypto import WeakCryptoAgent
from sentinel.agents.data_storage import WorldReadableStorageAgent
from sentinel.agents.deep_links import DeepLinkHijackAgent
from sentinel.agents.dynamic import (
    CertPinningBypassAgent,
    DataInTransitAgent,
    ImproperTLSAgent,
    RuntimeCryptoAgent,
)
from sentinel.agents.logging import InsecureLoggingAgent
from sentinel.agents.meta import ObfuscationDetectorAgent
from sentinel.agents.network import CleartextTrafficAgent
from sentinel.agents.platform import ContentProviderIDORAgent, IntentRedirectAgent
from sentinel.agents.random_gen import InsecureRandomAgent
from sentinel.agents.shared_prefs import InsecureSharedPrefsAgent
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.agents.webview import InsecureWebViewAgent
from sentinel.core.config import get_settings
from sentinel.core.finding import BountyScope, Finding
from sentinel.core.orchestrator import Orchestrator, ScanResult
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.llm.router import FreeProviderRouter
from sentinel.memory import LightweightMemory
from sentinel.triage import LLMTriager

logger = logging.getLogger(__name__)


SAST_AGENTS = [
    ObfuscationDetectorAgent,
    PipelineSmokeTestAgent,
    InsecureAuthStorageAgent,
    HardcodedSecretsAgent,
    InsecureLoggingAgent,
    InsecureRandomAgent,
    InsecureBackupAgent,
    WorldReadableStorageAgent,
    InsecureWebViewAgent,
    InsecureSharedPrefsAgent,
    WeakCryptoAgent,
    FirebaseMisconfigAgent,
    MissingCertPinningAgent,
    CleartextTrafficAgent,
    DeepLinkHijackAgent,
    ContentProviderIDORAgent,
    IntentRedirectAgent,
]


class ScanJob:
    """One scan tracked by the gateway."""

    def __init__(
        self,
        session_id: str,
        apk_path: Path,
        apk_filename: str,
        options: dict[str, Any],
    ) -> None:
        self.session_id = session_id
        self.apk_path = apk_path
        self.apk_filename = apk_filename
        self.options = options
        self.status: str = "queued"
        self.phase: str = "init"
        self.created_at = datetime.now(timezone.utc)
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.error: str | None = None
        self.warnings: list[str] = []
        self.findings: list[Finding] = []
        self.phase_timings: dict[str, float] = {}
        self.manifest: dict[str, Any] = {}
        self.apk_sha256: str = ""
        self.apk_size_bytes: int = 0
        self.task: asyncio.Task | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "apk_filename": self.apk_filename,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "error": self.error,
            "warnings_count": len(self.warnings),
            "findings_count": len(self.findings),
            "phase_timings": self.phase_timings,
            "apk_sha256": self.apk_sha256,
            "apk_size_bytes": self.apk_size_bytes,
            "manifest": {
                "package": self.manifest.get("package"),
                "version_name": self.manifest.get("version_name"),
                "target_sdk": self.manifest.get("target_sdk"),
                "permissions_count": len(self.manifest.get("permissions", [])),
                "activities_count": len(self.manifest.get("activities", [])),
            },
            "severity_counts": self.severity_counts(),
            "triage_counts": self.triage_counts(),
            "options": self.options,
        }

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value.lower()] = (
                counts.get(f.severity.value.lower(), 0) + 1
            )
        return counts

    def triage_counts(self) -> dict[str, int]:
        counts = {"verified": 0, "filtered": 0, "uncertain": 0, "skipped": 0}
        for f in self.findings:
            ev = f.evidence or {}
            triage = ev.get("_triage") if isinstance(ev, dict) else None
            outcome = (
                triage.get("outcome") if isinstance(triage, dict) else None
            )
            if outcome in counts:
                counts[outcome] += 1
        return counts

    def finding_dicts(self) -> list[dict[str, Any]]:
        out = []
        for f in self.findings:
            ev = f.evidence or {}
            triage = ev.get("_triage") if isinstance(ev, dict) else None
            outcome = (
                triage.get("outcome")
                if isinstance(triage, dict)
                else "skipped"
            )
            out.append({
                "finding_id": f.finding_id,
                "agent_id": f.agent_id,
                "vuln_class": f.vuln_class,
                "severity": f.severity.value.lower(),
                "severity_label": f.severity.value,
                "confidence": f.confidence,
                "triage": outcome or "skipped",
                "recommendation": f.recommendation,
                "evidence": _clean_evidence(ev),
                "cvss_vector": f.cvss_vector,
                "owasp": f.owasp,
                "masvs": f.masvs,
                "created_at": f.created_at.isoformat(),
            })
        return out


def _clean_evidence(ev: dict[str, Any]) -> dict[str, Any]:
    """Drop the internal _triage key and clamp giant blobs for the API."""
    out: dict[str, Any] = {}
    for k, v in ev.items():
        if k == "_triage":
            continue
        if isinstance(v, str) and len(v) > 4000:
            out[k] = v[:4000] + f"…[truncated {len(v) - 4000} chars]"
        else:
            out[k] = v
    return out


class ScanRegistry:
    """Thin in-memory registry of scan jobs."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()

    async def add(self, job: ScanJob) -> None:
        async with self._lock:
            self._jobs[job.session_id] = job

    def get(self, session_id: str) -> ScanJob | None:
        return self._jobs.get(session_id)

    def all(self) -> list[ScanJob]:
        return sorted(
            self._jobs.values(),
            key=lambda j: j.created_at,
            reverse=True,
        )

    async def remove(self, session_id: str) -> bool:
        async with self._lock:
            job = self._jobs.pop(session_id, None)
            if job and job.task and not job.task.done():
                job.task.cancel()
            if job and job.apk_path.exists():
                try:
                    job.apk_path.unlink()
                except OSError:
                    pass
            return job is not None


_registry: ScanRegistry | None = None


def get_registry() -> ScanRegistry:
    """Module-level singleton — one registry per process."""
    global _registry
    if _registry is None:
        _registry = ScanRegistry()
    return _registry


async def launch_scan(
    apk_path: Path,
    apk_filename: str,
    options: dict[str, Any],
) -> ScanJob:
    """Create a ScanJob, register it, and start the orchestrator in the bg."""
    session_id = generate_session_id()
    job = ScanJob(session_id, apk_path, apk_filename, options)
    registry = get_registry()
    await registry.add(job)
    job.task = asyncio.create_task(_run_job(job))
    return job


async def _run_job(job: ScanJob) -> None:
    """The actual work — runs the orchestrator end-to-end."""
    settings = get_settings()
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    job.phase = "ingestion"

    memory = LightweightMemory(data_dir=settings.workspace.parent / "data")
    router: FreeProviderRouter | None = None
    triager: LLMTriager | None = None

    try:
        await memory.connect()

        if job.options.get("llm_triage", False):
            try:
                router = FreeProviderRouter(
                    force_local=bool(job.options.get("privacy", False)),
                )
                triager = LLMTriager(router=router)
            except Exception as e:  # noqa: BLE001
                logger.warning("LLM triage unavailable, continuing without: %s", e)
                job.warnings.append(f"LLM triage disabled: {e}")
                router = None
                triager = None

        scope = BountyScope()
        scope_text = job.options.get("scope_text")
        if scope_text:
            try:
                from sentinel.scope import parse_scope
                scope = parse_scope(text=scope_text)
            except Exception as e:  # noqa: BLE001
                logger.warning("Scope parse failed: %s", e)
                job.warnings.append(f"Scope parse failed: {e}")

        ctx = ScanContext(
            session_id=job.session_id,
            apk_path=job.apk_path,
            workspace=settings.workspace,
            scope=scope,
        )

        dynamic = bool(job.options.get("dynamic", False))
        frida = bool(job.options.get("frida", False))
        no_proxy = bool(job.options.get("no_proxy", False))

        agent_list = list(SAST_AGENTS)
        if dynamic:
            agent_list.extend([ImproperTLSAgent, DataInTransitAgent])
        if dynamic and frida:
            agent_list.append(RuntimeCryptoAgent)
            agent_list.append(CertPinningBypassAgent)

        orch = Orchestrator(
            context=ctx,
            memory=memory,
            agents=agent_list,
            triager=triager,
            dynamic_enabled=dynamic,
            dynamic_duration_seconds=int(
                job.options.get("dynamic_duration", 30),
            ),
            frida_enabled=frida,
            frida_duration_seconds=int(
                job.options.get("frida_duration", 30),
            ),
            proxy_enabled=not no_proxy,
        )

        job.phase = "scanning"
        result: ScanResult = await orch.run()

        # Pull final state into the job
        job.findings = result.findings
        job.warnings.extend(result.warnings)
        job.phase_timings = result.phase_timings
        job.manifest = ctx.manifest or {}
        job.apk_sha256 = ctx.apk_sha256
        job.apk_size_bytes = ctx.apk_size_bytes
        job.status = (
            "completed" if result.status == "completed" else "failed"
        )
        job.error = result.error
        job.phase = "done"
        logger.info(
            "Scan %s finished: status=%s findings=%d warnings=%d",
            job.session_id, job.status, len(job.findings), len(job.warnings),
        )
    except asyncio.CancelledError:
        job.status = "cancelled"
        job.error = "Scan cancelled by user"
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("Scan %s failed", job.session_id)
        job.status = "failed"
        job.error = f"{type(e).__name__}: {e}"
    finally:
        job.completed_at = datetime.now(timezone.utc)
        if router is not None:
            try:
                await router.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            await memory.close()
        except Exception:  # noqa: BLE001
            pass
