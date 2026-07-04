"""Orchestrator — runs a scan through the multi-phase pipeline.

Pipeline phases:
- Phase 0: Ingestion (hash, workspace setup)
- Phase 1: Recon — runs JADX, Androguard, apktool, manifest in PARALLEL
           (Sprint 7.6.3). Each tool is crash-proof and contributes
           independently to ctx.sources. Scan continues with whatever
           succeeded.
- Phase 4: Dynamic analysis (Sprint 8.1) — mitmproxy + adb. Runs ONLY
           when --dynamic is passed. Installs APK on connected device,
           captures HTTP/HTTPS traffic via mitmproxy, stores in
           ctx.sources['mitmproxy'] for N_003/N_004 to consume.
           When --no-proxy is passed, the mitmproxy + device proxy
           steps are skipped (useful for apps with anti-MITM detection).
- Phase 4.5: Frida sub-phase (Sprint 8.2) — runs WITHIN phase 4 after
           the mitmproxy capture. Hooks runtime crypto (A_003) and
           cert pinning bypass (N_005). Stores capture in
           ctx.sources['frida']. Only runs when --frida is also passed.
- Phase 2: Static + dynamic analysis agents
- Phase 3: LLM triage (Sprint 7) — filters false positives, optional

Later sprints add:
- Phase 4 extensions: emulator automation (Sprint 8.3)
- Phase 5+: Verification, PoC, chain detection

CRASH-PROOFING:
Tool wrappers return ToolResult instead of raising (Sprint 7.6.1).
Phase 1 runs all tools concurrently via asyncio.gather(return_exceptions=True),
so a single tool failure NEVER blocks the others.
Phase 4 wraps every step in best-effort logic; rollback runs in finally
so a partial DAST failure doesn't leave the device misconfigured.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.agents.meta.meta005_profiler import ProfilerAgent
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.core.ast_cache import AstCache
from sentinel.core.dedup import dedupe
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface
from sentinel.tools.adb_runner import AdbRunner
from sentinel.tools.androguard_analyzer import AndroguardAnalyzer
from sentinel.tools.apktool import ApktoolError, ApktoolRunner
from sentinel.tools.frida_runner import ALL_RUNTIME_HOOKS, FridaRunner
from sentinel.tools.jadx import JadxRunner
from sentinel.tools.manifest import ManifestError, ManifestParser
from sentinel.tools.mitmproxy_runner import MitmproxyRunner
from sentinel.triage import LLMTriager

logger = logging.getLogger(__name__)

# Phase 8 (VAPT report generation) calls the LLM per finding to write the
# narrative + remediation prose, so wall-clock time scales linearly with
# the finding count. The 120s default was too tight for 100+-finding
# scans, leaving the workspace with no report on disk. Default bumped to
# 600s and overridable via SENTINEL_REPORT_TIMEOUT_SECONDS.
def _report_timeout_seconds() -> float:
    raw = os.getenv("SENTINEL_REPORT_TIMEOUT_SECONDS")
    if raw:
        try:
            return max(30.0, float(raw))
        except ValueError:
            logger.warning(
                "Invalid SENTINEL_REPORT_TIMEOUT_SECONDS=%r, using default", raw,
            )
    return 600.0


_REPORT_TIMEOUT_SECONDS = _report_timeout_seconds()


class OrchestratorError(Exception):
    """Scan orchestration failed."""


class ScanResult:
    """Collected outcome of a full scan."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.status: str = "pending"
        self.findings: list[Finding] = []
        self.phase_timings: dict[str, float] = {}
        self.error: str | None = None
        self.warnings: list[str] = []
        self.tool_health: dict[str, Any] = {}
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "findings_count": len(self.findings),
            "phase_timings": self.phase_timings,
            "error": self.error,
            "warnings": self.warnings,
            "tool_health": self.tool_health,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Orchestrator:
    """Runs a scan through the phase pipeline."""

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        agents: list[type[BaseAgent]] | None = None,
        triager: LLMTriager | None = None,
        dynamic_enabled: bool = False,
        dynamic_duration_seconds: int = 30,
        dynamic_port: int = 8082,
        frida_enabled: bool = False,
        frida_duration_seconds: int = 20,
        frida_spawn: bool = False,
        proxy_enabled: bool = True,
        # Visionary tier — all default off so existing scans are
        # bit-for-bit unchanged.
        impact_enabled: bool = True,
        compliance_tags_enabled: bool = True,
        learning_dir: Any = None,
        tenant_plan: str = "free",
        swarm_enabled: bool = False,
        swarm_llm_query: Any = None,
        swarm_max_concurrency: int = 4,
    ) -> None:
        self._context = context
        self._memory = memory
        self._agents = agents if agents is not None else [PipelineSmokeTestAgent]
        self._assert_unique_agent_ids(self._agents)
        self._triager = triager
        self._dynamic_enabled = dynamic_enabled
        self._dynamic_duration_seconds = dynamic_duration_seconds
        self._dynamic_port = dynamic_port
        self._frida_enabled = frida_enabled
        self._frida_duration_seconds = frida_duration_seconds
        self._frida_spawn = frida_spawn
        self._proxy_enabled = proxy_enabled
        self._impact_enabled = impact_enabled
        self._compliance_tags_enabled = compliance_tags_enabled
        self._learning_dir = learning_dir
        self._tenant_plan = tenant_plan
        self._swarm_enabled = swarm_enabled
        self._swarm_llm_query = swarm_llm_query
        self._swarm_max_concurrency = swarm_max_concurrency

    @staticmethod
    def _assert_unique_agent_ids(agents: list[type[BaseAgent]]) -> None:
        """Refuse to construct an Orchestrator with duplicate AGENT_IDs.

        Duplicate IDs cause Finding.finding_id collisions (which are
        sha256(agent_id|vuln_class|evidence)) and overwrite each other in
        memory storage. Catching this at construction time turns a silent
        data-loss bug into a loud startup failure.
        """
        seen: dict[str, str] = {}
        for cls in agents:
            aid = getattr(cls, "AGENT_ID", "")
            if not aid:
                continue
            if aid in seen:
                raise OrchestratorError(
                    f"Duplicate AGENT_ID {aid!r}: "
                    f"{seen[aid]} and {cls.__name__} both declare it. "
                    f"Rename one before registering."
                )
            seen[aid] = cls.__name__

    async def run(self) -> ScanResult:
        """Execute the full scan."""
        result = ScanResult(self._context.session_id)

        await self._memory.publish_event(
            self._context.session_id, "scan.started",
            {"apk_path": str(self._context.apk_path)},
        )

        try:
            # Phase 0: Ingestion
            start = asyncio.get_event_loop().time()
            await self._phase0_ingestion()
            # Phase 0.5: load the per-app learning profile (LEARN_001)
            # so Phase 2 agents and the verify hook can read priors.
            self._maybe_load_learning_profile()
            result.phase_timings["phase0"] = asyncio.get_event_loop().time() - start

            # Phase 1: Recon (parallel, crash-proof)
            start = asyncio.get_event_loop().time()
            await self._phase1_recon(result)
            result.phase_timings["phase1"] = asyncio.get_event_loop().time() - start

            # Phase 1.5: Profile + AST cache. Attaches the shared AstCache
            # to ctx, runs META_005 (frameworks, native libs, obfuscation,
            # API types), and narrows self._agents by the profile's
            # skip_agents prefix list before Phase 2 fans out.
            start = asyncio.get_event_loop().time()
            profile_findings = await self._phase15_profile(result)
            result.phase_timings["phase1_5"] = asyncio.get_event_loop().time() - start

            # Phase 4: Dynamic analysis (Sprint 8.1)
            if self._dynamic_enabled:
                start = asyncio.get_event_loop().time()
                try:
                    await self._phase4_dynamic(result)
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 4 dynamic analysis failed",
                                     self._context.session_id)
                    result.warnings.append(
                        f"Phase 4 dynamic analysis failed: {str(e)[:200]}",
                    )
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 4, "error": str(e)[:500]},
                    )
                result.phase_timings["phase4"] = (
                    asyncio.get_event_loop().time() - start
                )

            # Phase 2: Run agents
            start = asyncio.get_event_loop().time()
            findings = await self._phase2_agents()
            findings.extend(profile_findings)
            result.phase_timings["phase2"] = asyncio.get_event_loop().time() - start

            # Phase 2.5: dedup overlapping Semgrep / bespoke findings.
            # Pure post-processor — no LLM, no I/O. Highest-severity
            # finding per (canonical_class, file) cluster wins; losers
            # collapse into the survivor's evidence['_deduped_from'].
            pre_dedup = len(findings)
            findings = dedupe(findings)
            post_dedup = len(findings)
            if pre_dedup != post_dedup:
                logger.info(
                    "[%s] Dedup: %d findings -> %d (%d merged)",
                    self._context.session_id, pre_dedup, post_dedup,
                    pre_dedup - post_dedup,
                )

            # Phase 2.6: enrichment chain — IMPACT + COMPLIANCE + SWARM.
            # All three are best-effort: any failure logs and continues
            # rather than killing the scan.
            start = asyncio.get_event_loop().time()
            findings = await self._phase26_enrich(findings, result)
            result.phase_timings["phase2_6"] = (
                asyncio.get_event_loop().time() - start
            )
            result.findings = findings
            await self._persist_findings(result.findings)

            # Phase 4.6: hybrid SAST→DAST replay. The Phase 4 Frida
            # capture runs before Phase 2 so runtime observers can feed
            # dynamic agents. Hybrid target findings, however, only exist
            # after Phase 2. Re-attach briefly and invoke their rpc.exports
            # payloads here.
            if self._dynamic_enabled and self._frida_enabled:
                start = asyncio.get_event_loop().time()
                try:
                    await self._phase46_dynamic_target_dispatch(
                        result.findings, result,
                    )
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 4.6 dispatch failed",
                                     self._context.session_id)
                    result.warnings.append(
                        f"Phase 4.6 dynamic-target dispatch failed: "
                        f"{str(e)[:200]}",
                    )
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 4.6, "error": str(e)[:500]},
                    )
                result.phase_timings["phase4_6"] = (
                    asyncio.get_event_loop().time() - start
                )

            # Phase 4.7 — AFL++ fuzz over JNI harnesses. Opt-in via
            # ctx.fuzz_enabled. Toolchain-detects + degrades cleanly.
            if getattr(self._context, "fuzz_enabled", False):
                start = asyncio.get_event_loop().time()
                try:
                    fuzz_findings = await self._phase4_7_fuzz()
                    if fuzz_findings:
                        await self._persist_findings(fuzz_findings)
                        result.findings.extend(fuzz_findings)
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 4.7 fuzz failed",
                                     self._context.session_id)
                    result.warnings.append(
                        f"Phase 4.7 AFL++ fuzz failed: {str(e)[:200]}",
                    )
                result.phase_timings["phase4_7"] = (
                    asyncio.get_event_loop().time() - start
                )

            # Phase 3: LLM triage (optional)
            if self._triager is not None and findings:
                start = asyncio.get_event_loop().time()
                try:
                    result.findings = await self._phase3_triage(findings)
                    await self._persist_findings(result.findings)
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 3 triage failed",
                                     self._context.session_id)
                    result.warnings.append(f"Phase 3 triage failed: {str(e)[:200]}")
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 3, "error": str(e)[:500]},
                    )
                result.phase_timings["phase3"] = asyncio.get_event_loop().time() - start

            # Phase 7: Correlation (Sprint 9)
            if len(result.findings) >= 2:
                start = asyncio.get_event_loop().time()
                try:
                    chain_findings = await self._phase7_correlation()
                    result.findings.extend(chain_findings)
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 7 correlation failed",
                                     self._context.session_id)
                    result.warnings.append(f"Phase 7 correlation failed: {str(e)[:200]}")
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 7, "error": str(e)[:500]},
                    )
                result.phase_timings["phase7"] = asyncio.get_event_loop().time() - start

            # Phase 7.5: Active Exploitation & API Replay
            # Chains the ExploitDriver against every eligible High/Critical
            # finding, then writes standalone PoC scripts for anything the
            # driver promoted to Verified_Exploited. Best-effort — a failure
            # here must never kill the scan.
            if result.findings:
                start = asyncio.get_event_loop().time()
                try:
                    exploited = await self._phase7_5_active_exploitation(
                        result.findings,
                    )
                    # In-place replace so downstream phases (report) see the
                    # updated exploitation_status / poc_artifacts fields.
                    result.findings = exploited
                except Exception as e:  # noqa: BLE001
                    logger.exception(
                        "[%s] Phase 7.5 active exploitation failed",
                        self._context.session_id,
                    )
                    result.warnings.append(
                        f"Phase 7.5 active exploitation failed: {str(e)[:200]}",
                    )
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 7.5, "error": str(e)[:500]},
                    )
                result.phase_timings["phase7_5"] = (
                    asyncio.get_event_loop().time() - start
                )

            # Phase 8: VAPT report generation (R_001).
            # The agent reads every finding back out of memory and writes
            # markdown + HTML + JSON artifacts to <workspace>/reports/.
            # It is best-effort: a failure here must not kill the scan.
            if result.findings:
                start = asyncio.get_event_loop().time()
                try:
                    report_findings = await asyncio.wait_for(
                        self._phase8_report(),
                        timeout=_REPORT_TIMEOUT_SECONDS,
                    )
                    result.findings.extend(report_findings)
                except TimeoutError:
                    logger.warning(
                        "[%s] Phase 8 report generation timed out after %.0fs",
                        self._context.session_id,
                        _REPORT_TIMEOUT_SECONDS,
                    )
                    result.warnings.append(
                        f"Phase 8 report generation timed out after "
                        f"{_REPORT_TIMEOUT_SECONDS:.0f}s",
                    )
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {
                            "phase": 8,
                            "error": (
                                "report generation timed out after "
                                f"{_REPORT_TIMEOUT_SECONDS:.0f}s"
                            ),
                        },
                    )
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 8 report generation failed",
                                     self._context.session_id)
                    result.warnings.append(f"Phase 8 report generation failed: {str(e)[:200]}")
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 8, "error": str(e)[:500]},
                    )
                result.phase_timings["phase8"] = asyncio.get_event_loop().time() - start

            result.status = "completed"

        except OrchestratorError as e:
            result.status = "failed"
            result.error = str(e)
            logger.exception("Scan %s failed", self._context.session_id)
            await self._memory.publish_event(
                self._context.session_id, "scan.failed", {"error": str(e)[:500]},
            )

        result.completed_at = datetime.now(timezone.utc)
        await self._memory.publish_event(
            self._context.session_id, "scan.completed", result.to_summary(),
        )
        return result

    # ---------- Phase 0: Ingestion ----------

    async def _phase0_ingestion(self) -> None:
        """Hash the APK, create workspace, record basic metadata."""
        logger.info("[%s] Phase 0: Ingestion", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 0},
        )

        apk = self._context.apk_path
        if not apk.exists():
            raise OrchestratorError(f"APK missing: {apk}")

        h = hashlib.sha256()
        with apk.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        self._context.apk_sha256 = h.hexdigest()
        self._context.apk_size_bytes = apk.stat().st_size

        session_ws = self._context.workspace / self._context.session_id
        session_ws.mkdir(parents=True, exist_ok=True)
        self._context.workspace = session_ws

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {
                "phase": 0,
                "sha256": self._context.apk_sha256,
                "size": self._context.apk_size_bytes,
            },
        )

    # ---------- Phase 1: Recon (parallel) ----------

    async def _phase1_recon(self, scan_result: ScanResult) -> None:
        """Run all decompilers + analyzers in parallel."""
        logger.info("[%s] Phase 1: Parallel Recon", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 1},
        )

        ws = self._context.workspace
        decompile_dir = ws / "decompiled"
        resources_dir = ws / "resources"

        jadx_task = self._run_jadx(decompile_dir)
        androguard_task = self._run_androguard()
        apktool_task = self._run_apktool(resources_dir)
        manifest_task = self._run_manifest()

        jadx_res, androguard_res, apktool_res, manifest_res = await asyncio.gather(
            jadx_task, androguard_task, apktool_task, manifest_task,
            return_exceptions=True,
        )

        if isinstance(jadx_res, BaseException):
            logger.exception("JADX task crashed", exc_info=jadx_res)
            scan_result.warnings.append(f"JADX crashed: {jadx_res}")
        elif jadx_res and jadx_res.success:
            self._context.sources["jadx"] = jadx_res.data
            self._context.decompiled_dir = decompile_dir
            logger.info(
                "JADX produced %d Java files in %.1fs",
                jadx_res.data.java_file_count, jadx_res.duration_seconds,
            )
            for w in jadx_res.warnings:
                scan_result.warnings.append(f"JADX: {w}")
        else:
            error = jadx_res.error if jadx_res else "unknown"
            logger.warning("JADX failed: %s", error)
            scan_result.warnings.append(f"JADX failed: {error}")

        if isinstance(androguard_res, BaseException):
            logger.exception("Androguard task crashed", exc_info=androguard_res)
            scan_result.warnings.append(f"Androguard crashed: {androguard_res}")
        elif androguard_res and androguard_res.success:
            self._context.sources["androguard"] = androguard_res.data
            logger.info(
                "Androguard analyzed in %.1fs: %d classes, %d strings",
                androguard_res.duration_seconds,
                len(androguard_res.data.get_all_classes()),
                len(androguard_res.data.get_all_strings()),
            )
            for w in androguard_res.warnings:
                scan_result.warnings.append(f"Androguard: {w}")
        else:
            error = androguard_res.error if androguard_res else "unknown"
            logger.warning("Androguard failed: %s", error)
            scan_result.warnings.append(f"Androguard failed: {error}")

        if isinstance(apktool_res, BaseException):
            logger.exception("apktool task crashed", exc_info=apktool_res)
            scan_result.warnings.append(f"apktool crashed: {apktool_res}")
        elif apktool_res is True:
            self._context.sources["apktool"] = {"resources_dir": resources_dir}
            self._context.resources_dir = resources_dir
            logger.info("apktool produced manifest + resources")
        elif isinstance(apktool_res, str):
            logger.warning("apktool failed: %s", apktool_res)
            scan_result.warnings.append(f"apktool failed: {apktool_res}")

        if isinstance(manifest_res, BaseException):
            logger.exception("manifest task crashed", exc_info=manifest_res)
            scan_result.warnings.append(f"manifest crashed: {manifest_res}")
            self._context.manifest = {}
        elif isinstance(manifest_res, dict):
            self._context.manifest = manifest_res
        else:
            self._context.manifest = {}

        manifest = self._context.manifest
        self._context.target_sdk = manifest.get("target_sdk", 0)
        self._context.permissions = manifest.get("permissions", [])

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {
                "phase": 1,
                "package": manifest.get("package"),
                "target_sdk": manifest.get("target_sdk"),
                "permissions_count": len(manifest.get("permissions", [])),
                "activities_count": len(manifest.get("activities", [])),
                "java_files": (
                    self._context.sources["jadx"].java_file_count
                    if self._context.has_jadx() else 0
                ),
                "jadx_succeeded": self._context.has_jadx(),
                "androguard_succeeded": self._context.has_androguard(),
                "apktool_succeeded": self._context.has_apktool(),
                "warnings_count": len(scan_result.warnings),
            },
        )

    async def _run_jadx(self, output_dir: Path) -> Any:
        try:
            jadx = JadxRunner()
            return await jadx.decompile(self._context.apk_path, output_dir)
        except Exception:  # noqa: BLE001
            logger.exception("JADX runner setup failed")
            return None

    async def _run_androguard(self) -> Any:
        try:
            analyzer = AndroguardAnalyzer()
            return await analyzer.analyze(self._context.apk_path)
        except Exception:  # noqa: BLE001
            logger.exception("Androguard runner setup failed")
            return None

    async def _run_apktool(self, output_dir: Path) -> Any:
        try:
            apktool = ApktoolRunner()
            await apktool.decode(self._context.apk_path, output_dir)
            return True
        except ApktoolError as e:
            return f"ApktoolError: {e}"
        except Exception as e:  # noqa: BLE001
            logger.exception("apktool unexpected error")
            return f"{type(e).__name__}: {e}"

    async def _run_manifest(self) -> dict:
        try:
            parser = ManifestParser()
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, parser.parse, self._context.apk_path,
            )
        except ManifestError as e:
            logger.warning("Manifest parse failed: %s", e)
            return {}
        except Exception:  # noqa: BLE001
            logger.exception("Manifest parser unexpected error")
            return {}

    # ---------- Phase 4: Dynamic Analysis (Sprint 8.1) ----------

    async def _phase4_dynamic(self, scan_result: ScanResult) -> None:
        """Run dynamic analysis.

        When self._proxy_enabled is True (default): full mitmproxy capture
        + device proxy config + traffic flow. N_003/N_004 will have data.

        When self._proxy_enabled is False (--no-proxy): skip mitmproxy
        entirely. Just install (best-effort), launch app, run Frida
        sub-phase. Useful for apps with anti-MITM detection (Signal,
        banking apps) that exit when a proxy is set.

        The whole phase is best-effort. If any step fails, we log it as
        a warning and skip the rest — SAST findings still get produced.
        """
        logger.info("[%s] Phase 4: Dynamic analysis (proxy=%s)",
                    self._context.session_id, self._proxy_enabled)
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 4, "proxy_enabled": self._proxy_enabled},
        )
        health = scan_result.tool_health.setdefault("dynamic", {
            "requested": True,
            "status": "started",
            "proxy_enabled": self._proxy_enabled,
            "device_serial": None,
            "apk_installed": None,
            "app_started": False,
            "proxy_configured": False,
            "mitmproxy": "not_requested" if not self._proxy_enabled else "pending",
            "flows_captured": 0,
            "cleanup": {},
        })
        scan_result.tool_health.setdefault("frida", {
            "requested": self._frida_enabled,
            "status": "pending" if self._frida_enabled else "not_requested",
        })

        package = (self._context.manifest or {}).get("package")
        if not package:
            health["status"] = "skipped"
            health["reason"] = "package name not in manifest"
            scan_result.warnings.append(
                "Phase 4 skipped: package name not in manifest",
            )
            return

        adb = AdbRunner()
        mitmproxy = MitmproxyRunner(port=self._dynamic_port)

        # 1) Verify device available. We funnel device selection through
        # DeviceManager so multi-device deployments get round-robin
        # leasing AND honor ctx.device_serial when the user pinned one.
        # Falls back to the old AdbRunner.get_first_device() path if
        # the pool fails for any reason (no adb, weird state, ...).
        device = None
        pool_lease = None
        try:
            from sentinel.devices import DeviceUnavailable, get_device_manager
            self._device_pool = (
                getattr(self, "_device_pool", None) or get_device_manager()
            )
            preferred = getattr(self._context, "device_serial", "") or None
            try:
                pool_lease = self._device_pool.lease(
                    prefer_serial=preferred, timeout_s=30.0,
                )
                self._device_lease_ctx = pool_lease
                pool_device = await pool_lease.__aenter__()
                self._device_lease_active = True
                # Translate DeviceInfo into the AdbRunner.Device shape
                # the existing flow expects (serial + properties dict).
                fake = type("D", (), {})()
                fake.serial = pool_device.serial
                fake.properties = {
                    "model": pool_device.model,
                    "manufacturer": pool_device.manufacturer,
                    "sdk": pool_device.sdk,
                    "abi": pool_device.abi,
                }
                device = fake
                logger.info(
                    "Phase 4 device (pool-leased): %s (%s)",
                    pool_device.serial, pool_device.model or "?",
                )
            except DeviceUnavailable as e:
                scan_result.warnings.append(f"Phase 4 device pool: {e}")
        except Exception:  # noqa: BLE001
            logger.debug("DeviceManager unavailable; falling through to adb directly")

        if device is None:
            # Fallback path: original AdbRunner-first device.
            device_result = await adb.get_first_device()
            if not device_result.success:
                health["status"] = "skipped"
                health["reason"] = f"no Android device: {device_result.error}"
                scan_result.warnings.append(
                    f"Phase 4 skipped: no Android device. {device_result.error}",
                )
                return
            device = device_result.data
            logger.info("Phase 4 device: %s (%s)",
                        device.serial, device.properties.get("model", "?"))
        health["device_serial"] = device.serial

        # 2) Install the APK ONLY if it's not already on the device.
        # `adb install -r` force-stops the existing app as a side effect,
        # and if the install fails partway through (split APKs, signature
        # mismatch, etc.) the running process gets killed with nothing
        # to replace it. For DAST scans against apps installed via Play
        # Store (Signal, banking apps), the install is both unnecessary
        # and destructive — skip it.
        already_installed = await adb.is_installed(
            package, serial=device.serial,
        )
        if already_installed.success and already_installed.data:
            health["apk_installed"] = "already_present"
            logger.info(
                "Package %s already installed on device, skipping install",
                package,
            )
        else:
            install_result = await adb.install_apk(
                self._context.apk_path, serial=device.serial, replace=True,
            )
            if not install_result.success:
                health["apk_installed"] = "warning"
                logger.warning(
                    "APK install failed (may already be installed): %s",
                    install_result.error,
                )
                scan_result.warnings.append(
                    f"Phase 4: APK install warning: {install_result.error}",
                )
            else:
                health["apk_installed"] = "installed"

        # 3) Start mitmproxy (only in proxy mode)
        mitm_started = False
        proxy_host = ""
        proxy_port = 0
        if self._proxy_enabled:
            mitm_start = await mitmproxy.start(
                self._context.workspace / "dynamic",
            )
            if not mitm_start.success:
                health["status"] = "failed"
                health["mitmproxy"] = "failed"
                health["mitmproxy_error"] = mitm_start.error
                scan_result.warnings.append(
                    f"Phase 4: mitmproxy start failed: {mitm_start.error}",
                )
                return
            mitm_started = True
            proxy_host = mitm_start.data["host"]
            proxy_port = mitm_start.data["port"]
            logger.info("mitmproxy listening on %s:%d", proxy_host, proxy_port)
            health["mitmproxy"] = "running"
        else:
            health["mitmproxy"] = "skipped"
            logger.info(
                "Phase 4: --no-proxy mode, skipping mitmproxy + device proxy",
            )

        proxy_set = False
        app_started = False

        try:
            # 4) Configure device proxy (only in proxy mode)
            if self._proxy_enabled:
                proxy_result = await adb.set_global_proxy(
                    proxy_host, proxy_port, serial=device.serial,
                )
                proxy_set = proxy_result.success
                if not proxy_set:
                    health["status"] = "failed"
                    health["proxy_configured"] = False
                    health["proxy_error"] = proxy_result.error
                    scan_result.warnings.append(
                        f"Phase 4: proxy config failed: {proxy_result.error}",
                    )
                    return
                health["proxy_configured"] = True

            # 5) Launch app
            launch_result = await adb.start_app(package, serial=device.serial)
            app_started = launch_result.success
            if not app_started:
                health["status"] = "failed"
                health["app_started"] = False
                health["app_error"] = launch_result.error
                scan_result.warnings.append(
                    f"Phase 4: app launch failed: {launch_result.error}",
                )
                return
            health["app_started"] = True
            health["status"] = "capturing"

            # 6) Capture window — user interacts during this time
            logger.info(
                "Phase 4: capturing for %ds (interact with the app now)",
                self._dynamic_duration_seconds,
            )
            await self._memory.publish_event(
                self._context.session_id, "phase.progress",
                {
                    "phase": 4,
                    "status": "capturing_traffic" if self._proxy_enabled else "waiting_for_interaction",
                    "duration_seconds": self._dynamic_duration_seconds,
                    "proxy": f"{proxy_host}:{proxy_port}" if self._proxy_enabled else "(disabled)",
                    "package": package,
                },
            )
            await asyncio.sleep(self._dynamic_duration_seconds)

            # 6.5) Frida sub-phase
            if self._frida_enabled:
                await self._run_frida_subphase(
                    package, scan_result, adb, device.serial,
                )

        finally:
            # Release the DeviceManager lease the moment Phase 4 exits
            # (success or failure). Other concurrent scans waiting on
            # the pool can then pick this device up.
            try:
                if getattr(self, "_device_lease_active", False):
                    await self._device_lease_ctx.__aexit__(None, None, None)
                    self._device_lease_active = False
                    logger.info("Phase 4: released device-pool lease")
            except Exception:  # noqa: BLE001
                logger.exception("Phase 4: device-pool lease release failed")

            # 7) Teardown — always run, even on failure
            if app_started:
                stop_result = await adb.force_stop(package, serial=device.serial)
                health["cleanup"]["force_stop"] = stop_result.success
                if not stop_result.success:
                    logger.warning("force-stop returned non-success: %s",
                                   stop_result.error)

            if proxy_set:
                clear_result = await adb.clear_global_proxy(serial=device.serial)
                health["cleanup"]["clear_proxy"] = clear_result.success
                if not clear_result.success:
                    logger.warning("proxy clear returned non-success: %s",
                                   clear_result.error)

            # Only stop mitmproxy if we started it
            if mitm_started:
                mitm_stop = await mitmproxy.stop()
                if mitm_stop.success:
                    capture = mitm_stop.data
                    if capture is None:
                        scan_result.warnings.append(
                            "Phase 4: mitmproxy stop returned no capture",
                        )
                        health["status"] = "failed"
                        health["mitmproxy"] = "failed"
                        health["mitmproxy_error"] = "missing capture data"
                    else:
                        self._context.sources["mitmproxy"] = capture
                        tls_failed_count = len([
                            f for f in capture.flows if f.tls_failed
                        ])
                        https_success_count = len([
                            f for f in capture.flows
                            if f.scheme == "https" and not f.tls_failed
                        ])
                        http_count = len([
                            f for f in capture.flows if f.scheme == "http"
                        ])
                        health["mitmproxy"] = "completed"
                        health["flows_captured"] = capture.flow_count
                        health["tls_failed_count"] = tls_failed_count
                        health["https_success_count"] = https_success_count
                        health["http_count"] = http_count
                        if health.get("status") == "capturing":
                            health["status"] = "completed"
                        logger.info(
                            "Phase 4: captured %d flows in %.1fs",
                            capture.flow_count, capture.duration_seconds,
                        )
                        await self._memory.publish_event(
                            self._context.session_id, "phase.completed",
                            {
                                "phase": 4,
                                "flow_count": capture.flow_count,
                                "tls_failed_count": tls_failed_count,
                                "https_success_count": https_success_count,
                                "http_count": http_count,
                            },
                        )
                else:
                    scan_result.warnings.append(
                        f"Phase 4: mitmproxy stop failed: {mitm_stop.error}",
                    )
                    health["status"] = "failed"
                    health["mitmproxy"] = "failed"
                    health["mitmproxy_error"] = mitm_stop.error
            elif health.get("status") == "capturing":
                health["status"] = "completed"

    # ---------- Phase 4.5: Frida sub-phase (Sprint 8.2) ----------

    async def _run_frida_subphase(
        self,
        package: str,
        scan_result: ScanResult,
        adb: AdbRunner,
        serial: str,
    ) -> None:
        """Run Frida hooks against the target app.

        Re-launches the app right before attaching to handle the case
        where the app got backgrounded or killed during the long Phase 1
        decompile and the Phase 4 traffic-capture window.

        Hooks installed (combined via ALL_RUNTIME_HOOKS):
        - Cipher.getInstance (A_003): runtime crypto algorithm use
        - MessageDigest.getInstance (A_003): runtime hash algo use
        - KeyGenerator.getInstance (A_003): weak key generation
        - Pinning bypass (N_005): okhttp.CertificatePinner,
          X509TrustManager, WebViewClient, TrustKit, Conscrypt,
          HostnameVerifier
        """
        logger.info("Phase 4.5: Frida sub-phase for %s", package)
        await self._memory.publish_event(
            self._context.session_id, "phase.progress",
            {
                "phase": 4,
                "status": "frida_hooking",
                "duration_seconds": self._frida_duration_seconds,
                "package": package,
            },
        )
        health = scan_result.tool_health.setdefault("frida", {
            "requested": True,
        })
        health.update({
            "requested": True,
            "status": "attaching",
            "package": package,
            "device_serial": serial,
            "events_captured": 0,
            "script_errors": 0,
            "screenshots": 0,
        })

        # Re-launch the target app right before attach
        relaunch = await adb.start_app(package, serial=serial)
        if relaunch.success:
            logger.info(
                "Phase 4.5: re-launched %s, waiting 2s for process init",
                package,
            )
            await asyncio.sleep(2)
        else:
            logger.warning(
                "Phase 4.5: re-launch of %s failed (%s) — attempting "
                "attach anyway",
                package, relaunch.error,
            )

        frida = FridaRunner(
            evidence_dir=self._context.workspace / "evidence",
            device_serial=getattr(self._context, "device_serial", "") or None,
        )
        attach_result = await frida.attach(package, spawn=self._frida_spawn)
        if not attach_result.success:
            health["status"] = "failed"
            health["error"] = attach_result.error
            scan_result.warnings.append(
                f"Phase 4.5 Frida attach failed: {attach_result.error}",
            )
            return

        inject_result = await frida.inject_script(ALL_RUNTIME_HOOKS)
        if not inject_result.success:
            health["status"] = "failed"
            health["error"] = inject_result.error
            scan_result.warnings.append(
                f"Phase 4.5 Frida script injection failed: "
                f"{inject_result.error}",
            )
            await frida.detach()
            return
        health["status"] = "capturing"

        # In spawn mode the target was started paused so the hook
        # script could load before any app code ran; release it now.
        if self._frida_spawn:
            resume_result = await frida.resume()
            if not resume_result.success:
                scan_result.warnings.append(
                    f"Phase 4.5 Frida resume failed: "
                    f"{resume_result.error}",
                )

        logger.info(
            "Frida hooks active. Interact with the app for %ds.",
            self._frida_duration_seconds,
        )

        await frida.wait(self._frida_duration_seconds)

        detach_result = await frida.detach()
        if detach_result.success:
            capture = detach_result.data
            if capture is None:
                health["status"] = "failed"
                health["error"] = "missing capture data"
                scan_result.warnings.append(
                    "Phase 4.5 Frida detach returned no capture",
                )
                return
            self._context.sources["frida"] = capture
            # Surface evidence captures so downstream agents / the
            # report layer can attach them to runtime findings.
            if frida.screenshots:
                self._context.sources["frida_screenshots"] = list(frida.screenshots)
            health.update({
                "status": "completed",
                "events_captured": len(capture.events),
                "script_errors": len(capture.script_errors),
                "screenshots": len(frida.screenshots),
            })
            crypto_events = len([
                e for e in capture.events if e.kind.startswith("crypto.")
            ])
            tls_events = len([
                e for e in capture.events if e.kind.startswith("tls.")
            ])
            logger.info(
                "Phase 4.5: %d Frida events captured "
                "(%d crypto, %d tls, %d screenshots)",
                len(capture.events),
                crypto_events,
                tls_events,
                len(frida.screenshots),
            )
            await self._memory.publish_event(
                self._context.session_id, "phase.progress",
                {
                    "phase": 4,
                    "status": "frida_completed",
                    "event_count": len(capture.events),
                    "script_errors": len(capture.script_errors),
                },
            )
        else:
            health["status"] = "failed"
            health["error"] = detach_result.error
            scan_result.warnings.append(
                f"Phase 4.5 Frida detach failed: {detach_result.error}",
            )

    async def _phase46_dynamic_target_dispatch(
        self,
        findings: list[Finding],
        scan_result: ScanResult,
    ) -> None:
        """Replay hybrid SAST findings through Frida RPC after Phase 2."""
        targets = [
            f for f in findings
            if (f.evidence or {}).get("dynamic_target") is True
            and isinstance((f.evidence or {}).get("frida_payload"), dict)
        ]
        if not targets:
            return

        package = str((self._context.manifest or {}).get("package") or "")
        if not package:
            scan_result.warnings.append(
                "Phase 4.6 skipped: manifest package unavailable",
            )
            return

        adb = AdbRunner()
        device_result = await adb.get_first_device()
        if not device_result.success:
            scan_result.warnings.append(
                f"Phase 4.6 skipped: {device_result.error}",
            )
            return
        serial = device_result.data.serial

        relaunch = await adb.start_app(package, serial=serial)
        if relaunch.success:
            await asyncio.sleep(2)
        else:
            scan_result.warnings.append(
                f"Phase 4.6 app launch warning: {relaunch.error}",
            )

        frida = FridaRunner(
            evidence_dir=self._context.workspace / "evidence",
            device_serial=getattr(self._context, "device_serial", "") or None,
        )
        attach_result = await frida.attach(package, spawn=self._frida_spawn)
        if not attach_result.success:
            scan_result.warnings.append(
                f"Phase 4.6 Frida attach failed: {attach_result.error}",
            )
            return

        try:
            inject_result = await frida.inject_script(ALL_RUNTIME_HOOKS)
            if not inject_result.success:
                scan_result.warnings.append(
                    f"Phase 4.6 Frida script injection failed: "
                    f"{inject_result.error}",
                )
                return
            if self._frida_spawn:
                resume_result = await frida.resume()
                if not resume_result.success:
                    scan_result.warnings.append(
                        f"Phase 4.6 Frida resume failed: "
                        f"{resume_result.error}",
                    )

            from sentinel.core.dynamic_dispatch import dispatch_dynamic_targets
            from sentinel.tools.credential_manager import CredentialManager
            credential_manager = CredentialManager.from_env(
                workspace_root=self._context.workspace,
            )
            dispatch_summary = await dispatch_dynamic_targets(
                findings, frida,
                session_id=self._context.session_id,
                workspace=self._context.workspace,
                credential_manager=credential_manager,
            )
            await credential_manager.aclose()
            self._context.sources["phase4_6_dispatch"] = dispatch_summary
            await self._memory.publish_event(
                self._context.session_id,
                "phase.completed",
                {
                    "phase": 4.6,
                    "dispatched": dispatch_summary.get("dispatched", 0),
                    "succeeded": dispatch_summary.get("succeeded", 0),
                    "failed": dispatch_summary.get("failed", 0),
                },
            )
        finally:
            detach_result = await frida.detach()
            if detach_result.success:
                self._context.sources["frida_dispatch"] = detach_result.data
            await adb.force_stop(package, serial=serial)

    # ---------- LEARN_001 — per-app profile load ----------

    def _maybe_load_learning_profile(self) -> None:
        """Load the per-APK learning profile when enabled."""
        if not self._learning_dir:
            return
        try:
            from sentinel.learning import AppProfileStore
            store = AppProfileStore(root=Path(self._learning_dir))
            profile = store.record_scan_start(
                apk_sha256=self._context.apk_sha256,
                package=(self._context.manifest or {}).get("package", "") or "",
            )
            self._context.learning_profile = profile
            logger.info(
                "[%s] Learning profile loaded (scans_count=%d)",
                self._context.session_id, profile.scans_count,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "[%s] Learning profile load failed: %s",
                self._context.session_id, e,
            )

    # ---------- Phase 2.6 — Enrichment (IMPACT + COMPLIANCE + SWARM) ----------

    async def _phase26_enrich(
        self, findings: list[Finding], scan_result: ScanResult,
    ) -> list[Finding]:
        """Attach impact scores, compliance tags, and optional swarm output."""
        if not findings:
            return findings

        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 2.6},
        )

        # 1) IMPACT_001 — deterministic, cheap.
        # Pull HVT endpoints from strings.xml once and pass them to
        # every per-finding score call (free path-string augmentation).
        if self._impact_enabled:
            try:
                from sentinel.impact import (
                    attach_impact,
                    extract_hvt_endpoints_from_strings_xml,
                )
                hvt: set[str] = set()
                if self._context.resources_dir:
                    sx = (self._context.resources_dir / "res" / "values"
                          / "strings.xml")
                    hvt = extract_hvt_endpoints_from_strings_xml(sx)
                findings = [
                    attach_impact(f, tenant_plan=self._tenant_plan,
                                  hvt_endpoints=hvt)
                    for f in findings
                ]
            except Exception as e:  # noqa: BLE001
                logger.exception("[%s] IMPACT_001 enrich failed",
                                 self._context.session_id)
                scan_result.warnings.append(
                    f"IMPACT enrichment failed: {str(e)[:200]}",
                )

        # 2) COMPLIANCE_001 — pure YAML lookup
        if self._compliance_tags_enabled:
            try:
                from sentinel.compliance import attach_compliance_tags
                findings = attach_compliance_tags(findings)
            except Exception as e:  # noqa: BLE001
                logger.exception("[%s] COMPLIANCE tag attach failed",
                                 self._context.session_id)
                scan_result.warnings.append(
                    f"Compliance tag attach failed: {str(e)[:200]}",
                )

        # 3) SWARM_001 — opt-in only, severity-gated, LLM-expensive
        if self._swarm_enabled and self._swarm_llm_query is not None:
            try:
                from sentinel.swarm import SwarmOrchestrator
                swarm = SwarmOrchestrator(llm_query=self._swarm_llm_query)
                applicable = [
                    f for f in findings
                    if f.severity in {Severity.HIGH, Severity.CRITICAL}
                ]
                if applicable:
                    logger.info(
                        "[%s] SWARM_001: running on %d High/Critical findings",
                        self._context.session_id, len(applicable),
                    )
                    results = await swarm.run_many(
                        applicable,
                        max_concurrency=self._swarm_max_concurrency,
                    )
                    by_fid = {r.finding_id: r for r in results}
                    findings = [
                        swarm.attach(f, by_fid[f.finding_id])
                        if f.finding_id in by_fid else f
                        for f in findings
                    ]
            except Exception as e:  # noqa: BLE001
                logger.exception("[%s] SWARM_001 failed",
                                 self._context.session_id)
                scan_result.warnings.append(
                    f"Swarm enrichment failed: {str(e)[:200]}",
                )

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {
                "phase": 2.6,
                "impact_enabled": self._impact_enabled,
                "compliance_tags_enabled": self._compliance_tags_enabled,
                "swarm_enabled": self._swarm_enabled,
                "findings_count": len(findings),
            },
        )
        return findings

    # ---------- Phase 1.5: Profile + AST Cache ----------

    # Prefixes that are HARD-SKIPPED when the profile says they're useless.
    # Kept conservative: Java-source-only agents (TAINT_*) on hybrid apps
    # whose real logic lives in libapp.so, and native-only agents (NL_*,
    # META_006) when no .so files exist. Dynamic agents (D_*) and the rest
    # of the catalog still run — the profile is advisory, not a kill switch.
    _HARD_SKIP_HYBRID = ("TAINT_",)
    _HARD_SKIP_NO_NATIVE = ("NL_", "META_006")

    async def _phase15_profile(self, scan_result: ScanResult) -> list[Finding]:
        """Attach the shared AstCache and run the META_005 profiler.

        The profiler populates ctx.app_profile. We then narrow self._agents
        by intersecting against the hard-skip prefix lists derived from the
        profile. Returns the profiler's own findings (one INFO record).
        """
        logger.info("[%s] Phase 1.5: Profile + AST cache",
                    self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 1.5},
        )

        # Attach shared AST cache to context so Phase 2 agents reuse trees.
        if self._context.ast_cache is None:
            self._context.ast_cache = AstCache()

        # Run the profiler through the normal BaseAgent lifecycle so its
        # INFO finding gets persisted and events get emitted for free.
        profile_findings: list[Finding] = []
        try:
            profiler = ProfilerAgent(
                context=self._context, memory=self._memory,
            )
            profile_findings = await profiler.run()
        except Exception as e:  # noqa: BLE001
            logger.exception("[%s] Phase 1.5 profiler failed",
                             self._context.session_id)
            scan_result.warnings.append(f"Phase 1.5 profiler failed: {str(e)[:200]}")
            # Profiler is advisory — keep the full agent list and continue.
            await self._memory.publish_event(
                self._context.session_id, "phase.completed",
                {"phase": 1.5, "skipped_agents": 0, "profile": "unavailable"},
            )
            return profile_findings

        # Apply skip-list. Profile may carry "skip_agents" prefixes
        # plus context flags we re-derive defensively.
        skip_prefixes = self._resolve_skip_prefixes()
        if skip_prefixes:
            before = len(self._agents)
            kept = [
                cls for cls in self._agents
                if not any(
                    getattr(cls, "AGENT_ID", "").startswith(p)
                    for p in skip_prefixes
                )
            ]
            dropped = before - len(kept)
            if dropped:
                logger.info(
                    "[%s] Phase 1.5: profile dropped %d/%d agents "
                    "(skip prefixes: %s)",
                    self._context.session_id, dropped, before,
                    list(skip_prefixes),
                )
                self._agents = kept

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {
                "phase": 1.5,
                "frameworks": self._context.detected_frameworks(),
                "obfuscation": self._context.obfuscation_level(),
                "api_types": self._context.detected_api_types(),
                "remaining_agents": len(self._agents),
                "skip_prefixes": list(skip_prefixes),
                "ast_cache_attached": self._context.ast_cache is not None,
            },
        )
        return profile_findings

    def _resolve_skip_prefixes(self) -> tuple[str, ...]:
        """Derive the narrowed hard-skip prefix list from the app profile.

        Deliberately ignores any prefix suggested by the profiler that
        isn't on this orchestrator's hard-skip allow-list — the profiler
        can recommend whatever, but only the curated subset takes effect.
        """
        profile = self._context.app_profile or {}
        prefixes: set[str] = set()

        # Hybrid framework dominant? skip Java-taint agents.
        dominant_hybrids = {"Flutter", "React Native", "Xamarin/.NET", "Unity"}
        if set(profile.get("frameworks", [])) & dominant_hybrids:
            prefixes.update(self._HARD_SKIP_HYBRID)

        # No native libs? skip native-only agents.
        if profile.get("native_libs_info", {}).get("count", 0) == 0:
            prefixes.update(self._HARD_SKIP_NO_NATIVE)

        return tuple(sorted(prefixes))

    # ---------- Phase 2: Agents ----------

    async def _phase2_agents(self) -> list[Finding]:
        """Run the registered agents in parallel.

        Each BaseAgent reads ScanContext (frozen at this point) and writes
        through self._memory which serializes its own access. Agents do
        not communicate with each other, so concurrent execution is safe
        and turns a 20-agent serial walk over a 91MB APK from ~100s into
        ~10–15s (limited by the slowest agent's regex pass).

        return_exceptions=True keeps a single buggy agent from poisoning
        the gather; per-agent errors are already swallowed inside
        BaseAgent.run() but the gather-level catch is belt-and-braces.
        """
        logger.info("[%s] Phase 2: Agents (parallel, n=%d)",
                    self._context.session_id, len(self._agents))
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 2, "agent_count": len(self._agents)},
        )

        async def _run_one(agent_cls: type[BaseAgent]) -> list[Finding]:
            try:
                agent = agent_cls(context=self._context, memory=self._memory)
                return await agent.run()
            except Exception:  # noqa: BLE001
                logger.exception("Agent %s crashed at construction",
                                 agent_cls.__name__)
                return []

        results = await asyncio.gather(
            *(_run_one(cls) for cls in self._agents),
            return_exceptions=True,
        )

        all_findings: list[Finding] = []
        for cls, res in zip(self._agents, results, strict=True):
            if isinstance(res, BaseException):
                logger.exception("Agent %s gather-level failure",
                                 cls.__name__, exc_info=res)
                continue
            all_findings.extend(res)

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 2, "findings_count": len(all_findings)},
        )

        # Phase 2.1 — planner advisory pass. When ctx.planner_enabled
        # is True, run the AdaptivePlanner over the registry + findings
        # so far. Decisions are *advisory only* in this release: they
        # land in ctx.sources['planner_log'] for the report and don't
        # reorder the procedural Phase-2 execution that already ran.
        # Wiring the planner to actually drive scheduling is a careful
        # cross-phase change that lands after planner output has been
        # observed on real scans.
        if getattr(self._context, "planner_enabled", False):
            try:
                await self._run_planner_advisory(all_findings)
            except Exception:  # noqa: BLE001
                logger.exception("Planner advisory pass failed; ignoring")

        return all_findings

    async def _run_planner_advisory(self, findings: list[Finding]) -> None:
        """Run the AdaptivePlanner once per registered agent — advisory."""
        from sentinel.planner import AdaptivePlanner
        from sentinel.planner.planner import tools_from_classes

        # LLM mode requires a router; otherwise drop to heuristic mode.
        router = None
        try:
            from sentinel.llm.router import FreeProviderRouter
            router = FreeProviderRouter(force_local=self._context.is_private)
        except Exception:  # noqa: BLE001
            logger.debug("Planner: no LLM router; using heuristic mode")

        tools = tools_from_classes(self._agents)
        planner = AdaptivePlanner(
            tools=tools, router=router, max_steps=len(tools) + 1,
        )
        # Replay every agent that already ran so the planner only
        # advises on what's left (in this advisory pass, nothing — but
        # the decision log still proves the planner can rank).
        decisions: list[dict[str, Any]] = []
        for _ in range(min(8, len(tools))):
            d = await planner.decide(findings)
            decisions.append({
                "next": d.next_tool, "strategy": d.strategy, "why": d.reason,
            })
            if d.next_tool is None:
                break
            planner.mark_done(d.next_tool)
        self._context.sources.setdefault("planner_log", []).extend(decisions)
        logger.info(
            "[%s] Planner advisory: recorded %d decisions",
            self._context.session_id, len(decisions),
        )
        if router is not None:
            try:
                await router.close()
            except Exception:  # noqa: BLE001
                pass

    # ---------- Phase 3: LLM Triage (Sprint 7) ----------

    async def _phase3_triage(self, findings: list[Finding]) -> list[Finding]:
        """Run LLM triage on the collected findings."""
        assert self._triager is not None

        logger.info(
            "[%s] Phase 3: LLM triage of %d findings",
            self._context.session_id, len(findings),
        )
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 3, "findings_count": len(findings)},
        )

        triaged = await self._triager.triage(findings, self._context)

        from sentinel.triage import TriageOutcome
        outcomes: dict[str, int] = {o.value: 0 for o in TriageOutcome}
        for f in triaged:
            triage_data = (f.evidence or {}).get("_triage")
            if triage_data and isinstance(triage_data, dict):
                outcome = triage_data.get("outcome")
                if outcome in outcomes:
                    outcomes[outcome] += 1

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {
                "phase": 3,
                "verified": outcomes["verified"],
                "filtered": outcomes["filtered"],
                "uncertain": outcomes["uncertain"],
                "skipped": outcomes["skipped"],
            },
        )
        return triaged

    # ---------- Phase 7: Correlation (Sprint 9) ----------

    async def _phase7_correlation(self) -> list[Finding]:
        """Run exploit chain detection on all findings."""
        from sentinel.agents.correlation import ExploitChainAgent

        logger.info("[%s] Phase 7: Exploit chain detection", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 7},
        )

        agent = ExploitChainAgent(context=self._context, memory=self._memory)
        chain_findings = await agent.run()

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 7, "chains_detected": len(chain_findings)},
        )
        return chain_findings

    # ---------- Phase 7.5: Active Exploitation & API Replay ----------

    async def _phase7_5_active_exploitation(
        self, findings: list[Finding],
    ) -> list[Finding]:
        """Drive High/Critical findings through ExploitDriver + PoCGenerator.

        For each eligible finding the driver returns an updated Finding with
        ``exploitation_status``, ``exploit_proof``, ``api_replay_logs``, and
        ``severity_rationale`` populated. Verified_Exploited findings also
        get standalone PoC scripts written under
        ``workspace/{session}/poc_artifacts/`` with the paths recorded on
        ``Finding.poc_artifacts`` for the frontend "Download PoC" link.

        Best-effort per finding — one crashed driver call must not stop
        other findings from being processed.
        """
        from sentinel.exploit.driver import ExploitDriver
        from sentinel.exploit.poc_generator import PoCGenerator

        logger.info(
            "[%s] Phase 7.5: active exploitation over %d findings",
            self._context.session_id, len(findings),
        )
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 7.5},
        )

        credential_manager = None
        try:
            from sentinel.tools.credential_manager import CredentialManager
            credential_manager = CredentialManager.from_env(
                workspace=self._context.workspace,
            )
        except Exception:  # noqa: BLE001
            logger.debug("Phase 7.5: credential_manager unavailable")

        driver = ExploitDriver(credential_manager=credential_manager)
        poc = PoCGenerator(workspace=self._context.workspace)

        exploited_count = 0
        updated: list[Finding] = []
        for finding in findings:
            try:
                outcome = await driver.exploit(
                    finding, context=self._context,
                )
                new_finding = outcome.finding
                if outcome.exploited or outcome.poc_kind:
                    try:
                        artifacts = poc.generate_for(
                            new_finding,
                            driver_hint=outcome.poc_metadata,
                        )
                        if artifacts:
                            new_finding = new_finding.model_copy(update={
                                "poc_artifacts": [
                                    a.relative_path for a in artifacts
                                ],
                            })
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "Phase 7.5: PoC generation failed for %s",
                            finding.agent_id,
                        )
                if outcome.exploited:
                    exploited_count += 1
                # Best-effort persist — upserts by finding_id.
                try:
                    await self._memory.save_finding(new_finding)
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "Phase 7.5: memory upsert failed for %s",
                        new_finding.agent_id,
                    )
                updated.append(new_finding)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Phase 7.5: driver crashed on %s; keeping original finding",
                    finding.agent_id,
                )
                updated.append(finding)

        if credential_manager is not None:
            try:
                await credential_manager.aclose()
            except Exception:  # noqa: BLE001
                pass

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 7.5, "exploited": exploited_count},
        )
        return updated

    # ---------- Phase 4.7: AFL++ fuzz run (opt-in) ----------

    async def _phase4_7_fuzz(self) -> list[Finding]:
        """Run AFL++/libFuzzer over the JNI harnesses META_006 emitted.

        Opt-in (``ctx.fuzz_enabled``). Toolchain-detects; degrades to a
        warning when AFL++/clang/QEMU isn't on PATH. Findings come back
        as D_072 follow-ups via fuzz.run_for_session.
        """
        if not getattr(self._context, "fuzz_enabled", False):
            return []
        try:
            from sentinel.fuzz import run_for_session
        except Exception:  # noqa: BLE001
            logger.exception("Phase 4.7: fuzz module unavailable")
            return []
        logger.info("[%s] Phase 4.7: AFL++ fuzz run", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 4.7},
        )
        try:
            findings, status = run_for_session(
                workspace=self._context.workspace,
                session_id=self._context.session_id,
                time_per_harness_s=getattr(
                    self._context, "fuzz_time_per_harness_s", 60,
                ),
            )
        except Exception:  # noqa: BLE001
            logger.exception("Phase 4.7: fuzz runner crashed")
            return []
        if not status.available:
            logger.info("Phase 4.7: skipped (%s)", status.reason)
            return []
        logger.info("Phase 4.7: %d crash findings", len(findings))
        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 4.7, "crash_count": len(findings)},
        )
        return findings

    # ---------- Phase 7.5: PoC Studio (runnable exploit artifacts) ----------

    async def _phase7_5_poc_studio(self, findings: list[Finding]) -> None:
        """Emit standalone runnable PoC scripts for every confirmed finding.

        Gated by ``allow_live_poc`` on the scan context — when off, the
        studio still emits a per-finding markdown reproduction guide
        (no runnable code). The studio is a no-op when there are no
        eligible findings, which is the common case for SAST-only runs.
        """
        try:
            from sentinel.exploit.poc_studio import emit_for_scan
            out_dir = self._context.workspace / "poc"
            target_pkg = (self._context.manifest or {}).get(
                "package", "com.example.app",
            )
            allow_live = bool(getattr(self._context, "allow_live_poc", False))
            artifacts = emit_for_scan(
                findings, out_dir,
                target_package=target_pkg,
                allow_live=allow_live,
            )
            if artifacts:
                logger.info(
                    "[%s] PoC Studio: emitted %d artifacts (live=%s)",
                    self._context.session_id, len(artifacts), allow_live,
                )
                await self._memory.publish_event(
                    self._context.session_id, "poc.emitted",
                    {"count": len(artifacts), "live": allow_live},
                )
        except Exception:  # noqa: BLE001
            logger.exception("PoC Studio failed; continuing")

    # ---------- Phase 8: VAPT report generation ----------

    async def _phase8_report(self) -> list[Finding]:
        """Generate VAPT report artifacts via R_001.

        Fires the PoC Studio just before so the report can reference
        the emitted artifacts and the API can serve them from
        ``/reports/{session}/poc/...``.
        """
        from sentinel.agents.reporting import ReportGeneratorAgent

        # PoC Studio runs against everything already in memory so it
        # sees both Phase 2 SAST findings + Phase 4.5 dispatch results.
        try:
            all_findings = await self._memory.get_findings(
                session_id=self._context.session_id,
            )
            await self._phase7_5_poc_studio(all_findings)
        except Exception:  # noqa: BLE001
            logger.exception("PoC Studio pre-report hook failed")

        logger.info("[%s] Phase 8: VAPT report generation", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 8},
        )

        agent = ReportGeneratorAgent(context=self._context, memory=self._memory)
        meta_findings = await agent.run()

        if meta_findings:
            paths = meta_findings[0].evidence or {}
            await self._memory.publish_event(
                self._context.session_id, "phase.completed",
                {
                    "phase": 8,
                    "report_markdown": paths.get("report_markdown"),
                    "report_html": paths.get("report_html"),
                    "report_json": paths.get("report_json"),
                },
            )
        else:
            await self._memory.publish_event(
                self._context.session_id, "phase.completed",
                {"phase": 8, "report": "skipped (no findings to render)"},
            )
        return meta_findings

    # ---------- Helpers ----------

    async def _persist_findings(self, findings: list[Finding]) -> None:
        for finding in findings:
            try:
                await self._memory.save_finding(finding)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "[%s] could not persist finding %s: %s",
                    self._context.session_id,
                    finding.finding_id,
                    e,
                )

    async def cleanup(self, keep_workspace: bool = False) -> None:
        """Clean up session workspace unless --keep-workspace was passed."""
        if keep_workspace:
            return
        ws = self._context.workspace
        if ws.exists() and str(ws).startswith(str(Path.home())):
            shutil.rmtree(ws, ignore_errors=True)
