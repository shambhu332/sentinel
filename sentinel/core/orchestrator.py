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
from sentinel.tools.frida_runner import ALL_RUNTIME_HOOKS, FridaRunner
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
        frida_enabled: bool = False,
        frida_duration_seconds: int = 20,
        frida_spawn: bool = False,
        proxy_enabled: bool = True,
    ) -> None:
        self._context = context
        self._memory = memory
        self._agents = agents if agents is not None else [PipelineSmokeTestAgent]
        self._triager = triager
        self._dynamic_enabled = dynamic_enabled
        self._dynamic_duration_seconds = dynamic_duration_seconds
        self._dynamic_port = dynamic_port
        self._frida_enabled = frida_enabled
        self._frida_duration_seconds = frida_duration_seconds
        self._frida_spawn = frida_spawn
        self._proxy_enabled = proxy_enabled

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
            logger.info(
                "Package %s already installed on device, skipping install",
                package,
            )
        else:
            install_result = await adb.install_apk(
                self._context.apk_path, serial=device.serial, replace=True,
            )
            if not install_result.success:
                logger.warning(
                    "APK install failed (may already be installed): %s",
                    install_result.error,
                )
                scan_result.warnings.append(
                    f"Phase 4: APK install warning: {install_result.error}",
                )

        # 3) Start mitmproxy (only in proxy mode)
        mitm_started = False
        proxy_host = ""
        proxy_port = 0
        if self._proxy_enabled:
            mitm_start = await mitmproxy.start(
                self._context.workspace / "dynamic",
            )
            if not mitm_start.success:
                scan_result.warnings.append(
                    f"Phase 4: mitmproxy start failed: {mitm_start.error}",
                )
                return
            mitm_started = True
            proxy_host = mitm_start.data["host"]
            proxy_port = mitm_start.data["port"]
            logger.info("mitmproxy listening on %s:%d", proxy_host, proxy_port)
        else:
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

            # Only stop mitmproxy if we started it
            if mitm_started:
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

        frida = FridaRunner()
        attach_result = await frida.attach(package, spawn=self._frida_spawn)
        if not attach_result.success:
            scan_result.warnings.append(
                f"Phase 4.5 Frida attach failed: {attach_result.error}",
            )
            return

        inject_result = await frida.inject_script(ALL_RUNTIME_HOOKS)
        if not inject_result.success:
            scan_result.warnings.append(
                f"Phase 4.5 Frida script injection failed: "
                f"{inject_result.error}",
            )
            await frida.detach()
            return

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
            self._context.sources["frida"] = capture
            logger.info(
                "Phase 4.5: %d Frida events captured (%d crypto, %d tls)",
                len(capture.events),
                sum(1 for e in capture.events if e.kind.startswith("crypto.")),
                sum(1 for e in capture.events if e.kind.startswith("tls.")),
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
            scan_result.warnings.append(
                f"Phase 4.5 Frida detach failed: {detach_result.error}",
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

    # ---------- Helpers ----------

    async def cleanup(self, keep_workspace: bool = False) -> None:
        """Clean up session workspace unless --keep-workspace was passed."""
        if keep_workspace:
            return
        ws = self._context.workspace
        if ws.exists() and str(ws).startswith(str(Path.home())):
            shutil.rmtree(ws, ignore_errors=True)
