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
- Phase 2: Static + dynamic analysis agents
- Phase 3: LLM triage (Sprint 7) — filters false positives, optional

Later sprints add:
- Phase 4 extensions: Frida runtime hooks (Sprint 8.2), emulator
  automation (Sprint 8.3)
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
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.core.finding import Finding
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface
from sentinel.tools.adb_runner import AdbRunner
from sentinel.tools.androguard_analyzer import AndroguardAnalyzer
from sentinel.tools.apktool import ApktoolError, ApktoolRunner
from sentinel.tools.jadx import JadxRunner
from sentinel.tools.manifest import ManifestError, ManifestParser
from sentinel.tools.mitmproxy_runner import MitmproxyRunner
from sentinel.triage import LLMTriager

logger = logging.getLogger(__name__)


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
    ) -> None:
        self._context = context
        self._memory = memory
        self._agents = agents if agents is not None else [PipelineSmokeTestAgent]
        self._triager = triager
        self._dynamic_enabled = dynamic_enabled
        self._dynamic_duration_seconds = dynamic_duration_seconds
        self._dynamic_port = dynamic_port

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
            result.phase_timings["phase0"] = asyncio.get_event_loop().time() - start

            # Phase 1: Recon (parallel, crash-proof)
            start = asyncio.get_event_loop().time()
            await self._phase1_recon(result)
            result.phase_timings["phase1"] = asyncio.get_event_loop().time() - start

            # Phase 4: Dynamic analysis (Sprint 8.1) — runs BEFORE Phase 2
            # so dynamic agents have captures available. Named Phase 4 to
            # reflect logical pipeline tier (later sprints extend this with
            # Frida hooks + emulator automation), not execution order.
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
            result.phase_timings["phase2"] = asyncio.get_event_loop().time() - start
            result.findings = findings

            # Phase 3: LLM triage (optional)
            if self._triager is not None and findings:
                start = asyncio.get_event_loop().time()
                try:
                    result.findings = await self._phase3_triage(findings)
                except Exception as e:  # noqa: BLE001
                    logger.exception("[%s] Phase 3 triage failed",
                                     self._context.session_id)
                    result.warnings.append(f"Phase 3 triage failed: {str(e)[:200]}")
                    await self._memory.publish_event(
                        self._context.session_id, "phase.failed",
                        {"phase": 3, "error": str(e)[:500]},
                    )
                result.phase_timings["phase3"] = asyncio.get_event_loop().time() - start

            result.status = "completed"

        except OrchestratorError as e:
            # Only Phase 0 (ingestion) failures are fatal — APK missing/invalid
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
        """Run all decompilers + analyzers in parallel.

        Each tool's success/failure is independent of the others. Even if
        JADX times out, Androguard typically succeeds within 30s — so the
        scan can produce findings via bytecode analysis.

        ctx.sources is populated with whatever succeeded.
        """
        logger.info("[%s] Phase 1: Parallel Recon", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 1},
        )

        ws = self._context.workspace
        decompile_dir = ws / "decompiled"
        resources_dir = ws / "resources"

        # Build coroutines for all tools — they'll run concurrently
        jadx_task = self._run_jadx(decompile_dir)
        androguard_task = self._run_androguard()
        apktool_task = self._run_apktool(resources_dir)
        manifest_task = self._run_manifest()

        # Wait for all tools, exceptions become results
        jadx_res, androguard_res, apktool_res, manifest_res = await asyncio.gather(
            jadx_task, androguard_task, apktool_task, manifest_task,
            return_exceptions=True,
        )

        # Process JADX result
        if isinstance(jadx_res, BaseException):
            logger.exception("JADX task crashed", exc_info=jadx_res)
            scan_result.warnings.append(f"JADX crashed: {jadx_res}")
        elif jadx_res and jadx_res.success:
            self._context.sources["jadx"] = jadx_res.data
            self._context.decompiled_dir = decompile_dir  # backwards compat
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

        # Process Androguard result
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

        # Process apktool result
        if isinstance(apktool_res, BaseException):
            logger.exception("apktool task crashed", exc_info=apktool_res)
            scan_result.warnings.append(f"apktool crashed: {apktool_res}")
        elif apktool_res is True:
            self._context.sources["apktool"] = {"resources_dir": resources_dir}
            self._context.resources_dir = resources_dir  # backwards compat
            logger.info("apktool produced manifest + resources")
        elif isinstance(apktool_res, str):
            # Non-fatal apktool failure (string error message)
            logger.warning("apktool failed: %s", apktool_res)
            scan_result.warnings.append(f"apktool failed: {apktool_res}")

        # Process manifest result
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
        """Run JADX. Returns a ToolResult or None on internal error."""
        try:
            jadx = JadxRunner()
            return await jadx.decompile(self._context.apk_path, output_dir)
        except Exception:  # noqa: BLE001
            logger.exception("JADX runner setup failed")
            return None

    async def _run_androguard(self) -> Any:
        """Run Androguard. Returns a ToolResult or None on internal error."""
        try:
            analyzer = AndroguardAnalyzer()
            return await analyzer.analyze(self._context.apk_path)
        except Exception:  # noqa: BLE001
            logger.exception("Androguard runner setup failed")
            return None

    async def _run_apktool(self, output_dir: Path) -> Any:
        """Run apktool. Returns True on success or error string on failure.

        apktool still raises ApktoolError today (will migrate to ToolResult
        in a later sprint). We catch the exception here.
        """
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
        """Parse the APK manifest. Returns a dict (empty on failure)."""
        try:
            parser = ManifestParser()
            # ManifestParser.parse() is synchronous and CPU-bound — run in executor
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
        """Run dynamic analysis: install APK, capture traffic, store flows.

        Pipeline:
        1. Verify a device is connected via adb
        2. Get the target package from manifest (or skip if unknown)
        3. Install the APK on the device
        4. Start mitmproxy on the configured port
        5. Configure the device to proxy through laptop:port
        6. Launch the app
        7. Wait dynamic_duration_seconds for traffic capture
           (in a real run, user interacts with the app during this window)
        8. Stop the app, clear the proxy, stop mitmproxy
        9. Store the capture in ctx.sources['mitmproxy'] for dynamic agents

        The whole phase is best-effort. If any step fails, we log it as a
        warning and skip the rest — SAST findings still get produced.
        """
        logger.info("[%s] Phase 4: Dynamic analysis",
                    self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 4},
        )

        package = (self._context.manifest or {}).get("package")
        if not package:
            scan_result.warnings.append(
                "Phase 4 skipped: package name not in manifest",
            )
            return

        adb = AdbRunner()
        mitmproxy = MitmproxyRunner(port=self._dynamic_port)

        # 1) Verify device available
        device_result = await adb.get_first_device()
        if not device_result.success:
            scan_result.warnings.append(
                f"Phase 4 skipped: no Android device. {device_result.error}",
            )
            return
        device = device_result.data
        logger.info("Phase 4 device: %s (%s)",
                    device.serial, device.properties.get("model", "?"))

        # 2) Install the APK (best-effort; may already be present)
        install_result = await adb.install_apk(
            self._context.apk_path, serial=device.serial, replace=True,
        )
        if not install_result.success:
            # Install failure may not be fatal — package may already be on device
            logger.warning("APK install failed (may already be installed): %s",
                           install_result.error)
            scan_result.warnings.append(
                f"Phase 4: APK install warning: {install_result.error}",
            )

        # 3) Start mitmproxy
        mitm_start = await mitmproxy.start(
            self._context.workspace / "dynamic",
        )
        if not mitm_start.success:
            scan_result.warnings.append(
                f"Phase 4: mitmproxy start failed: {mitm_start.error}",
            )
            return

        proxy_host = mitm_start.data["host"]
        proxy_port = mitm_start.data["port"]
        logger.info("mitmproxy listening on %s:%d", proxy_host, proxy_port)

        # Track what we configured so we can roll it all back
        proxy_set = False
        app_started = False

        try:
            # 4) Configure device proxy
            proxy_result = await adb.set_global_proxy(
                proxy_host, proxy_port, serial=device.serial,
            )
            proxy_set = proxy_result.success
            if not proxy_set:
                scan_result.warnings.append(
                    f"Phase 4: proxy config failed: {proxy_result.error}",
                )
                return

            # 5) Launch app
            launch_result = await adb.start_app(package, serial=device.serial)
            app_started = launch_result.success
            if not app_started:
                scan_result.warnings.append(
                    f"Phase 4: app launch failed: {launch_result.error}",
                )
                return

            # 6) Capture window — user interacts during this time
            logger.info(
                "Phase 4: capturing traffic for %ds (interact with the app now)",
                self._dynamic_duration_seconds,
            )
            await self._memory.publish_event(
                self._context.session_id, "phase.progress",
                {
                    "phase": 4,
                    "status": "capturing",
                    "duration_seconds": self._dynamic_duration_seconds,
                    "proxy": f"{proxy_host}:{proxy_port}",
                    "package": package,
                },
            )
            await asyncio.sleep(self._dynamic_duration_seconds)

        finally:
            # 7) Teardown — always run, even on failure
            if app_started:
                stop_result = await adb.force_stop(package, serial=device.serial)
                if not stop_result.success:
                    logger.warning("force-stop returned non-success: %s",
                                   stop_result.error)

            if proxy_set:
                clear_result = await adb.clear_global_proxy(serial=device.serial)
                if not clear_result.success:
                    logger.warning("proxy clear returned non-success: %s",
                                   clear_result.error)

            mitm_stop = await mitmproxy.stop()
            if mitm_stop.success:
                capture = mitm_stop.data
                self._context.sources["mitmproxy"] = capture
                logger.info(
                    "Phase 4: captured %d flows in %.1fs",
                    capture.flow_count, capture.duration_seconds,
                )
                await self._memory.publish_event(
                    self._context.session_id, "phase.completed",
                    {
                        "phase": 4,
                        "flow_count": capture.flow_count,
                        "tls_failed_count": sum(
                            1 for f in capture.flows if f.tls_failed
                        ),
                        "https_success_count": sum(
                            1 for f in capture.flows
                            if f.scheme == "https" and not f.tls_failed
                        ),
                        "http_count": sum(
                            1 for f in capture.flows if f.scheme == "http"
                        ),
                    },
                )
            else:
                scan_result.warnings.append(
                    f"Phase 4: mitmproxy stop failed: {mitm_stop.error}",
                )

    # ---------- Phase 2: Agents ----------

    async def _phase2_agents(self) -> list[Finding]:
        """Run the registered agents."""
        logger.info("[%s] Phase 2: Agents", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 2, "agent_count": len(self._agents)},
        )

        all_findings: list[Finding] = []
        for agent_cls in self._agents:
            try:
                agent = agent_cls(context=self._context, memory=self._memory)
                findings = await agent.run()
                all_findings.extend(findings)
            except Exception:  # noqa: BLE001
                logger.exception("Agent %s failed", agent_cls.__name__)

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 2, "findings_count": len(all_findings)},
        )
        return all_findings

    # ---------- Phase 3: LLM Triage (Sprint 7) ----------

    async def _phase3_triage(self, findings: list[Finding]) -> list[Finding]:
        """Run LLM triage on the collected findings."""
        assert self._triager is not None  # guarded by caller

        logger.info(
            "[%s] Phase 3: LLM triage of %d findings",
            self._context.session_id, len(findings),
        )
        await self._memory.publish_event(
            self._context.session_id, "phase.started",
            {"phase": 3, "findings_count": len(findings)},
        )

        triaged = await self._triager.triage(findings, self._context)

        # Tally outcomes for the event log
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

    # ---------- Helpers ----------

    async def cleanup(self, keep_workspace: bool = False) -> None:
        """Clean up session workspace unless --keep-workspace was passed."""
        if keep_workspace:
            return
        ws = self._context.workspace
        if ws.exists() and str(ws).startswith(str(Path.home())):
            shutil.rmtree(ws, ignore_errors=True)
