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
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

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
    C001ECBModeAgent,
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
    D091RaspDetectorAgent,
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
    ExcessivePermissionsAgent,
    IntentRedirectAgent,
    IpcExposureAgent,
    MutablePendingIntentAgent,
    P001DeepLinkHijackAgent,
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
    C001ECBModeAgent,
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
    P001DeepLinkHijackAgent,
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
    D091RaspDetectorAgent,
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


_DYNAMIC_MITM_NAMES = [
    "ImproperTLSAgent",
    "DataInTransitAgent",
    "RaceConditionCandidateAgent",
    "IdorCandidateAgent",
    "JwtWeaknessAgent",
    "ThirdPartyPiiLeakAgent",
    "CookieHardeningAgent",
    "GraphqlPersistedQueryAgent",
]

_FRIDA_RUNTIME_NAMES = [
    "RuntimeCryptoAgent",
    "CertPinningBypassAgent",
    "ClipboardLeakAgent",
    "FlagSecureMissingAgent",
    "BiometricWeakAgent",
    "AntiTamperCoverageAgent",
    "DynamicCodeLoadingAgent",
    "StaticIvReuseAgent",
    "IapBypassAgent",
    "WebViewRuntimeAgent",
    "NotificationLeakAgent",
    "ImplicitIntentLeakAgent",
    "AccessibilityAbuseAgent",
    "SmsPermissionAbuseAgent",
    "ScreenCaptureAgent",
    "DynamicReceiverExportAgent",
    "PendingIntentMutableAgent",
    "LocalSocketServerAgent",
    "ContentProviderUriExposureAgent",
    "FileProviderTraversalAgent",
    "BackgroundLocationLeakAgent",
    "InsecureKeystoreUsageAgent",
    "ZipPathTraversalAgent",
    "InsecureRandomRuntimeAgent",
    "InsecureHostnameVerifierAgent",
    "InAppUpdateInsecureAgent",
    "UnsafeJsonDeserializationAgent",
    "SqliteCommandInjectionAgent",
    "UnsafeReflectionInvokeAgent",
    "ExportedActivityResultLeakAgent",
    "LocalFileLogLeakAgent",
    "ClipboardListenerSnoopAgent",
    "BroadcastWiretapAgent",
    "InsecureTrustManagerRuntimeAgent",
    "OkHttpLoggingRuntimeAgent",
    "BiometricDeviceCredentialFallbackAgent",
    "NotificationFloodAgent",
    "BiometricReplayAgent",
    "SqliteProberAgent",
    "MemoryDumpTargetAgent",
    "WebViewXssAgent",
    "NotificationSnoopAgent",
    "SideChannelAgent",
    "GraphqlFuzzerAgent",
    "NativeHeapAgent",
    "BiometricTimingAgent",
    "StatePoisonerAgent",
    "WebSocketInjectorAgent",
    "ClipboardHijackAgent",
    "SensorSpoofingAgent",
    "KeyExtractorAgent",
    "BinderBombAgent",
    "JobHijackerAgent",
    "A11yAbuserAgent",
    "SplitApkAgent",
    "WearableBridgeAgent",
    "AutofillSnifferAgent",
    "PipSpyAgent",
    "TwaBreakerAgent",
    "IntentAuthVerifierAgent",
]


def _dynamic_agents_by_name(names: list[str]) -> list[type]:
    out: list[type] = []
    for name in names:
        cls = getattr(_dyn_mod, name, None)
        if cls is None:
            logger.debug("scan-roster: dynamic agent missing: %s", name)
            continue
        out.append(cls)
    return out


_DYNAMIC_MITM_AGENTS = _dynamic_agents_by_name(_DYNAMIC_MITM_NAMES)
_FRIDA_RUNTIME_AGENTS = _dynamic_agents_by_name(_FRIDA_RUNTIME_NAMES)

_FAST_AGENT_IDS = {
    "META_001",
    "META_002",
    "TEST_001",
    "A_001",
    "A_014",
    "A_004",
    "LOG_002",
    "B_001",
    "B_007",
    "BAK_001",
    "STG_001",
    "WV_002",
    "C_001",
    "C_005",
    "C_007",
    "F_001",
    "F_002",
    "N_001",
    "N_002",
    "N_006",
    "N_008",
    "N_010",
    "P_001",
    "P_004",
    "P_005",
    "P_006",
    "P_010",
    "P_012",
    "P_015",
    "IPC_001",
    "SCA_001",
    "STG_006",
    "STG_007",
    "STG_008",
    "STG_009",
}

_FAST_DYNAMIC_AGENT_IDS = {
    "N_003",
    "N_004",
    "D_075",
    "N_005",
}


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


def _build_full_roster(
    dynamic: bool,
    frida: bool,
    scan_profile: str = "standard",
) -> list[type]:
    """Build the per-scan agent list from the live class registry.

    Static agents always run. mitmproxy-backed dynamic agents only run
    when dynamic scanning is enabled. Frida-backed observers and
    SAST-to-DAST target producers only run when Frida is enabled too.
    """
    # Start from the curated SAST list so its ordering is preserved.
    roster: list[type] = list(SAST_AGENTS)
    seen_ids = {getattr(c, "AGENT_ID", id(c)) for c in roster}

    def add_agents(classes: Sequence[type]) -> None:
        for cls in classes:
            aid = getattr(cls, "AGENT_ID", None)
            if not aid or aid in seen_ids:
                continue
            roster.append(cls)
            seen_ids.add(aid)

    discovered = _discover_all_agents()
    dynamic_module_prefix = "sentinel.agents.dynamic."
    for cls in discovered:
        aid = getattr(cls, "AGENT_ID", None)
        if not aid or aid in seen_ids:
            continue
        if cls.__module__.startswith(dynamic_module_prefix):
            continue
        roster.append(cls)
        seen_ids.add(aid)

    if dynamic:
        add_agents(_DYNAMIC_MITM_AGENTS)

    if dynamic and frida:
        add_agents(_FRIDA_RUNTIME_AGENTS)
        add_agents(_HYBRID_DAST_AGENTS)
        add_agents(_HYBRID_OPTIONAL)

    if scan_profile == "fast":
        allowed = set(_FAST_AGENT_IDS)
        if dynamic:
            allowed.update({"N_003", "N_004"})
        if dynamic and frida:
            allowed.update(_FAST_DYNAMIC_AGENT_IDS)
        roster = [
            cls for cls in roster
            if getattr(cls, "AGENT_ID", "") in allowed
        ]

    logger.info(
        "Scan roster: %d agents (dynamic=%s, frida=%s, profile=%s)",
        len(roster), dynamic, frida, scan_profile,
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
        self.tool_health: dict[str, Any] = {}
        self.manifest: dict[str, Any] = {}
        self.apk_sha256: str = ""
        self.apk_size_bytes: int = 0
        self.task: asyncio.Task[Any] | None = None

    def to_state(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "apk_path": str(self.apk_path),
            "apk_filename": self.apk_filename,
            "options": self.options,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at.isoformat(),
            "started_at": (
                self.started_at.isoformat() if self.started_at else None
            ),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "error": self.error,
            "warnings": self.warnings,
            "phase_timings": self.phase_timings,
            "tool_health": self.tool_health,
            "manifest": self.manifest,
            "apk_sha256": self.apk_sha256,
            "apk_size_bytes": self.apk_size_bytes,
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }

    @classmethod
    def from_state(cls, state: dict[str, Any], workspace: Path) -> "ScanJob":
        session_id = str(state["session_id"])
        fallback_apk = workspace / session_id / "uploaded.apk"
        job = cls(
            session_id=session_id,
            apk_path=Path(str(state.get("apk_path") or fallback_apk)),
            apk_filename=str(state.get("apk_filename") or "unknown.apk"),
            options=_dict_or_empty(state.get("options")),
        )
        job.status = str(state.get("status") or "failed")
        if job.status in {"queued", "running"}:
            job.status = "interrupted"
            job.error = "Scan interrupted before completion"
        else:
            job.error = _optional_str(state.get("error"))
        job.phase = str(state.get("phase") or "done")
        job.created_at = _parse_dt(state.get("created_at")) or job.created_at
        job.started_at = _parse_dt(state.get("started_at"))
        job.completed_at = _parse_dt(state.get("completed_at"))
        job.warnings = _str_list(state.get("warnings"))
        job.phase_timings = _float_map(state.get("phase_timings"))
        job.tool_health = _dict_or_empty(state.get("tool_health"))
        job.manifest = _dict_or_empty(state.get("manifest"))
        job.apk_sha256 = str(state.get("apk_sha256") or "")
        job.apk_size_bytes = int(state.get("apk_size_bytes") or 0)
        job.findings = _load_state_findings(state.get("findings"))
        return job

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
            "tool_health": self.tool_health,
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
            row = f.model_dump(mode="json")
            row.update({
                "finding_id": f.finding_id,
                "severity": f.severity.value.lower(),
                "severity_label": f.severity.value,
                "review_state": f.triage.value,
                "triage": outcome or "skipped",
                "evidence": _clean_evidence(ev),
                "created_at": f.created_at.isoformat(),
            })
            out.append(row)
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
    """Registry of scan jobs with file-backed completed-state restore."""

    def __init__(self, workspace: Path | None = None) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()
        self._workspace = (workspace or get_settings().workspace).resolve()
        self._load_persisted_jobs()

    async def add(self, job: ScanJob) -> None:
        async with self._lock:
            self._jobs[job.session_id] = job
        self.persist(job)

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
            try:
                await job.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                # Orchestrator's finally block runs here — swallow so caller
                # sees a clean cancel rather than the worker's exception.
                pass
        if job and job.apk_path.exists():
            try:
                job.apk_path.unlink()
            except OSError:
                logger.warning("Could not remove APK for session %s", session_id)
        _state_path(self._workspace, session_id).unlink(missing_ok=True)
        return job is not None

    def persist(self, job: ScanJob) -> None:
        path = _state_path(self._workspace, job.session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(job.to_state(), indent=2, sort_keys=True))
            tmp.replace(path)
        except OSError:
            logger.exception("Could not persist scan state for %s", job.session_id)

    def _load_persisted_jobs(self) -> None:
        if not self._workspace.exists():
            return
        for session_dir in self._workspace.iterdir():
            if not session_dir.is_dir():
                continue
            job = _load_persisted_job(self._workspace, session_dir)
            if job is not None:
                self._jobs[job.session_id] = job


_registry: ScanRegistry | None = None


def get_registry() -> ScanRegistry:
    """Module-level singleton — one registry per process."""
    global _registry
    if _registry is None:
        _registry = ScanRegistry()
    return _registry


def _state_path(workspace: Path, session_id: str) -> Path:
    return workspace / session_id / "reports" / "scan_state.json"


def _load_persisted_job(workspace: Path, session_dir: Path) -> ScanJob | None:
    state_path = session_dir / "reports" / "scan_state.json"
    if state_path.exists():
        try:
            return ScanJob.from_state(
                json.loads(state_path.read_text(errors="replace")),
                workspace,
            )
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            logger.exception("Could not restore scan state from %s", state_path)
            return None
    return _load_legacy_report_job(workspace, session_dir)


def _load_legacy_report_job(workspace: Path, session_dir: Path) -> ScanJob | None:
    session_id = session_dir.name
    report_path = (
        session_dir / "reports" / f"VAPT_Report_{session_id}.json"
    )
    if not report_path.exists():
        return None
    try:
        doc = json.loads(report_path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None

    job = ScanJob(
        session_id=session_id,
        apk_path=workspace / session_id / "uploaded.apk",
        apk_filename=str(doc.get("apk_filename") or "unknown.apk"),
        options={},
    )
    generated_at = _parse_dt(doc.get("generated_at"))
    mtime = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc)
    job.status = "completed"
    job.phase = "done"
    job.created_at = generated_at or mtime
    job.started_at = generated_at or mtime
    job.completed_at = generated_at or mtime
    job.apk_sha256 = str(doc.get("apk_sha256") or "")
    job.apk_size_bytes = int(doc.get("apk_size_bytes") or 0)
    job.manifest = {
        "package": doc.get("package"),
        "version_name": doc.get("version"),
    }
    job.findings = _load_state_findings(doc.get("findings"))
    return job


def _load_state_findings(raw_findings: object) -> list[Finding]:
    if not isinstance(raw_findings, list):
        return []
    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        row.pop("finding_id", None)
        row.pop("rag_mapping", None)
        row.pop("rag_passage_ids", None)
        row.pop("triage_explanation", None)
        try:
            findings.append(Finding.model_validate(row))
        except ValueError:
            logger.debug("Skipping invalid persisted finding", exc_info=True)
    return findings


def _parse_dt(value: object) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _optional_str(value: object) -> str | None:
    return None if value is None else str(value)


def _dict_or_empty(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _str_list(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _float_map(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, float] = {}
    for key, raw in value.items():
        try:
            out[str(key)] = float(raw)
        except (TypeError, ValueError):
            continue
    return out


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
    registry = get_registry()
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    job.phase = "ingestion"
    registry.persist(job)

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

        # Phase 1.4 — decrypt encrypted uploads to a temp plaintext path.
        # The .enc file stays on disk (the at-rest copy); the plaintext is
        # removed by the registry.remove() cleanup path after the scan ends.
        _plaintext_tmp: Path | None = None
        scan_apk_path = job.apk_path
        if settings.encryption_enabled() and scan_apk_path.suffix == ".enc":
            from sentinel.core.crypto import decode_master_key, derive_tenant_key, decrypt_file
            master_key = decode_master_key(settings.master_key)
            tenant_id = job.options.get("_tenant_id", "public")
            dek = derive_tenant_key(master_key, str(tenant_id))
            _plaintext_tmp = decrypt_file(
                scan_apk_path,
                dek,
                dst=scan_apk_path.with_suffix(""),  # strip .enc
            )
            scan_apk_path = _plaintext_tmp
            logger.debug("Decrypted %s for scan", job.apk_path.name)

        ctx = ScanContext(
            session_id=job.session_id,
            apk_path=scan_apk_path,
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
        scan_profile = _scan_profile(job.options)
        job.options["scan_profile"] = scan_profile

        # Single source of truth: walk every BaseAgent subclass on disk
        # so the /scans roster matches the /agents catalog the UI shows.
        # The hand-curated SAST_AGENTS list (above) is kept for ordering
        # of the SAST tier; everything else discovered via introspection
        # is appended after de-dup. Dynamic-only agents are excluded
        # unless --dynamic was passed (they require a live device).
        agent_list = _build_full_roster(
            dynamic=dynamic,
            frida=frida,
            scan_profile=scan_profile,
        )

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
        job.tool_health = result.tool_health
        job.manifest = ctx.manifest or {}
        job.apk_sha256 = ctx.apk_sha256
        job.apk_size_bytes = ctx.apk_size_bytes
        job.status = (
            "completed" if result.status == "completed" else "failed"
        )
        job.error = result.error
        job.phase = "done"
        registry.persist(job)
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
                logger.exception("Scan %s: router.close() failed", job.session_id)
        try:
            await memory.close()
        except Exception:  # noqa: BLE001
            logger.exception("Scan %s: memory.close() failed", job.session_id)
        # Phase 1.4 — remove the decrypted temp file; the .enc copy stays.
        if _plaintext_tmp is not None and _plaintext_tmp.exists():
            try:
                _plaintext_tmp.unlink()
            except OSError:
                logger.warning("Could not remove plaintext tmp %s", _plaintext_tmp)
        if ctx is not None and not bool(job.options.get("keep_workspace", False)):
            _cleanup_web_scan_artifacts(ctx.workspace, job.apk_path)
        registry.persist(job)


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


def _scan_profile(options: dict[str, Any]) -> str:
    raw = str(options.get("scan_profile") or "").strip().lower()
    if not raw and bool(options.get("fast", False)):
        raw = "fast"
    if raw in {"fast", "standard", "deep"}:
        return raw
    return "standard"
