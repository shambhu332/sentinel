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
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Optional D_07x / D_08x — resolved by attribute lookup so missing
# entries don't crash the API import.
from sentinel.agents import dynamic as _dyn_mod
from sentinel.agents.auth import (
    BiometricBypassAgent,
    HardcodedSecretsAgent,
    MagicLinkTokenAgent,
    RefreshTokenReuseAgent,
    SessionFixationAgent,
    SessionTokenInUrlAgent,
    TapJackingAgent,
)
from sentinel.agents.auth_storage import InsecureAuthStorageAgent
from sentinel.agents.backup import InsecureBackupAgent
from sentinel.agents.business import (
    ClientSideAuthzAgent,
    IapBypassAgent,
    OAuthRedirectUriAgent,
    RaceConditionAgent,
    RestIdorAgent,
    UnsignedUpdateAgent,
)
from sentinel.agents.cert_pinning import MissingCertPinningAgent
from sentinel.agents.cloud import FcmTokenDisclosureAgent, FirebaseMisconfigAgent
from sentinel.agents.crossplatform import FlutterAgent, ReactNativeAgent
from sentinel.agents.crypto import (
    AesGcmNonceReuseAgent,
    CbcPredictableIvAgent,
    EcbModeAgent,
    HardcodedCryptoKeysAgent,
    HashKdfAgent,
    JavaSerializationAgent,
    KeystoreMisuseAgent,
    SQLCipherKeyDerivationAgent,
    WeakCryptoAgent,
    WeakPrngSeedAgent,
)
from sentinel.agents.data_storage import WorldReadableStorageAgent
from sentinel.agents.dynamic import (
    CertPinningBypassAgent,
    DeepLinkBombAgent,
    FileProviderFuzzerAgent,
    HiddenApiHunterAgent,
    IapSpoofingAgent,
    IntentXssAgent,
    JniShadowAgent,
    MobileSsrfAgent,
    PinningStressTestAgent,
    ProviderLfiAgent,
    ProviderSqliAgent,
    RaceConditionTargetAgent,
    RuntimeCryptoAgent,
    ServiceLeakerAgent,
    SymbolicIntentAgent,
    WebViewUniversalXssAgent,
)
from sentinel.agents.logging import InsecureLoggingAgent
from sentinel.agents.meta import DebuggableManifestAgent, ObfuscationDetectorAgent
from sentinel.agents.native import LoadLibraryTaintAgent, NativeLibraryAgent
from sentinel.agents.network import (
    ApiKeyLeakageAgent,
    CleartextTrafficAgent,
    DnsLeakAgent,
    GraphqlFuzzerAgent,
    GraphqlIntrospectionAgent,
    HardcodedMtlsKeyAgent,
    InsecureTrustManagerAgent,
    InsecureWebSocketAgent,
    OkHttpLoggingAgent,
    WebViewDebugFlagAgent,
)
from sentinel.agents.platform import (
    ActivityResultLeakAgent,
    ContentProviderIDORAgent,
    DeepLinkHijackAgent,
    ExcessivePermissionsAgent,
    IntentRedirectAgent,
    IpcExposureAgent,
    MutablePendingIntentAgent,
    ReceiverChainHijackAgent,
    UnprotectedBroadcastAgent,
)
from sentinel.agents.random_gen import InsecureRandomAgent
from sentinel.agents.resilience import AntiTamperAgent
from sentinel.agents.semgrep import SemgrepAgent
from sentinel.agents.shared_prefs import (
    BackupRulesAgent,
    ExternalStorageCredentialAgent,
    InsecureFileProviderAgent,
    InsecureSharedPrefsAgent,
    PlaintextPasswordFileAgent,
    SqliteWalLeakAgent,
)
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.agents.supply_chain import SCAAgent
from sentinel.agents.taint import TaintAgent
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
    DebuggableManifestAgent,
    PipelineSmokeTestAgent,
    InsecureAuthStorageAgent,
    HardcodedSecretsAgent,
    InsecureLoggingAgent,
    BiometricBypassAgent,
    TapJackingAgent,
    SessionTokenInUrlAgent,
    RefreshTokenReuseAgent,
    SessionFixationAgent,
    MagicLinkTokenAgent,
    RestIdorAgent,
    InsecureRandomAgent,
    RaceConditionAgent,
    IapBypassAgent,
    OAuthRedirectUriAgent,
    UnsignedUpdateAgent,
    ClientSideAuthzAgent,
    InsecureBackupAgent,
    WorldReadableStorageAgent,
    InsecureWebViewAgent,
    HardcodedCryptoKeysAgent,
    EcbModeAgent,
    WeakCryptoAgent,
    SQLCipherKeyDerivationAgent,
    KeystoreMisuseAgent,
    AesGcmNonceReuseAgent,
    JavaSerializationAgent,
    CbcPredictableIvAgent,
    WeakPrngSeedAgent,
    HashKdfAgent,
    FirebaseMisconfigAgent,
    FcmTokenDisclosureAgent,
    MissingCertPinningAgent,
    CleartextTrafficAgent,
    ApiKeyLeakageAgent,
    GraphqlIntrospectionAgent,
    InsecureTrustManagerAgent,
    WebViewDebugFlagAgent,
    OkHttpLoggingAgent,
    GraphqlFuzzerAgent,
    DnsLeakAgent,
    InsecureWebSocketAgent,
    HardcodedMtlsKeyAgent,
    DeepLinkHijackAgent,
    ExcessivePermissionsAgent,
    UnprotectedBroadcastAgent,
    ActivityResultLeakAgent,
    ContentProviderIDORAgent,
    IntentRedirectAgent,
    ReceiverChainHijackAgent,
    MutablePendingIntentAgent,
    IpcExposureAgent,
    NativeLibraryAgent,
    LoadLibraryTaintAgent,
    AntiTamperAgent,
    SCAAgent,
    TaintAgent,
    ReactNativeAgent,
    FlutterAgent,
    SemgrepAgent,
    InsecureSharedPrefsAgent,
    InsecureFileProviderAgent,
    ExternalStorageCredentialAgent,
    BackupRulesAgent,
    PlaintextPasswordFileAgent,
    SqliteWalLeakAgent,
]

_HYBRID_DAST_AGENTS = [
    DeepLinkBombAgent,
    HiddenApiHunterAgent,
    RaceConditionTargetAgent,
    PinningStressTestAgent,
    ServiceLeakerAgent,
    SymbolicIntentAgent,
    ProviderSqliAgent,
    FileProviderFuzzerAgent,
    JniShadowAgent,
    IapSpoofingAgent,
    MobileSsrfAgent,
    WebViewUniversalXssAgent,
    ProviderLfiAgent,
    IntentXssAgent,
]

_HYBRID_OPTIONAL_NAMES = [
    "PendingIntentEscalationAgent",
    "SchemeConfuserAgent",
    "BiometricCryptoUnwrapperAgent",
    "BackupDataExtractorAgent",
]

_HYBRID_OPTIONAL = [
    cls for name in _HYBRID_OPTIONAL_NAMES
    if (cls := getattr(_dyn_mod, name, None)) is not None
]


def _discover_all_agents() -> list[type]:
    """Walk every sentinel.agents.* package and return all BaseAgent
    subclasses. Mirrors the discovery used by /agents so the scan
    roster never lags behind the visible catalog.
    """
    import importlib
    import pkgutil

    from sentinel.agents.base.base_agent import BaseAgent

    try:
        agents_pkg = importlib.import_module("sentinel.agents")
    except ImportError:
        return []
    for _f, name, _is in pkgutil.walk_packages(
        agents_pkg.__path__, prefix="sentinel.agents.",
    ):
        try:
            importlib.import_module(name)
        except Exception as e:  # noqa: BLE001
            logger.debug("scan-roster: skip %s (%s)", name, e)

    seen: dict[str, type] = {}
    stack: list[type] = list(BaseAgent.__subclasses__())
    while stack:
        cls = stack.pop()
        aid = getattr(cls, "AGENT_ID", "")
        if aid and aid not in seen:
            seen[aid] = cls
        stack.extend(cls.__subclasses__())
    return list(seen.values())


def _build_full_roster(dynamic: bool, frida: bool) -> list[type]:
    """Build the per-scan agent list from the live class registry.

    Phase 2 SAST agents always run. Pure-dynamic observers (the D_001..
    D_041 batch + ImproperTLSAgent / DataInTransitAgent / pinning-bypass
    crew that need a live device) are only scheduled when --dynamic
    is on. Hybrid SAST→DAST agents are scheduled whenever --dynamic
    is on so the Phase 4.5 dispatcher has something to fire.
    """
    # Start from the curated SAST list so its ordering is preserved.
    roster: list[type] = list(SAST_AGENTS)
    seen_ids = {getattr(c, "AGENT_ID", id(c)) for c in roster}

    discovered = _discover_all_agents()
    dynamic_module_prefix = "sentinel.agents.dynamic."
    for cls in discovered:
        aid = getattr(cls, "AGENT_ID", None)
        if not aid or aid in seen_ids:
            continue
        is_dynamic_only = cls.__module__.startswith(dynamic_module_prefix)
        if is_dynamic_only and not dynamic:
            continue  # device-required agent, no point scheduling it
        roster.append(cls)
        seen_ids.add(aid)

    if dynamic and frida:
        # Frida-only agents that need the script bundle injected.
        for extra in (RuntimeCryptoAgent, CertPinningBypassAgent):
            if getattr(extra, "AGENT_ID", None) not in seen_ids:
                roster.append(extra)
                seen_ids.add(extra.AGENT_ID)

    logger.info(
        "Scan roster: %d agents (dynamic=%s, frida=%s)",
        len(roster), dynamic, frida,
    )
    return roster


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
    ctx: ScanContext | None = None

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
            data_sensitivity="private" if bool(job.options.get("privacy", False)) else "public",
            active_replay=bool(job.options.get("active_replay", False)),
            allow_live_poc=bool(job.options.get("allow_live_poc", False)),
            planner_enabled=bool(job.options.get("planner", False)),
            device_serial=str(job.options.get("device_serial", "") or ""),
            fuzz_enabled=bool(job.options.get("fuzz", False)),
            fuzz_time_per_harness_s=int(
                job.options.get("fuzz_time", 60),
            ),
            ml_strategy=bool(job.options.get("ml_strategy", False)),
            ml_model_path=str(job.options.get("ml_model_path", "") or ""),
        )

        dynamic = bool(job.options.get("dynamic", False))
        frida = bool(job.options.get("frida", False))
        no_proxy = bool(job.options.get("no_proxy", False))

        # Single source of truth: walk every BaseAgent subclass on disk
        # so the /scans roster matches the /agents catalog the UI shows.
        # The hand-curated SAST_AGENTS list (above) is kept for ordering
        # of the SAST tier; everything else discovered via introspection
        # is appended after de-dup. Dynamic-only agents are excluded
        # unless --dynamic was passed (they require a live device).
        agent_list = _build_full_roster(dynamic=dynamic, frida=frida)

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
        if ctx is not None and not bool(job.options.get("keep_workspace", False)):
            _cleanup_web_scan_artifacts(ctx.workspace, job.apk_path)


def _cleanup_web_scan_artifacts(session_workspace: Path, uploaded_apk: Path) -> None:
    """Remove bulky web-scan artifacts while preserving generated reports."""
    try:
        uploaded_apk.unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove uploaded APK: %s", uploaded_apk)

    if not session_workspace.exists():
        return
    for child in session_workspace.iterdir():
        if child.name == "reports":
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except OSError:
            logger.warning("Could not remove scan artifact: %s", child)
