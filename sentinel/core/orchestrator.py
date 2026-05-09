"""Orchestrator — runs a scan through the multi-phase pipeline.

Pipeline phases:
- Phase 0: Ingestion (hash, workspace setup)
- Phase 1: Recon (decompile, manifest parse) — crash-proof: tools return ToolResult
- Phase 2: Static analysis agents
- Phase 3: LLM triage (Sprint 7) — filters false positives, optional

Later sprints add:
- Phase 4: Dynamic analysis (Frida + mitmproxy + Appium)
- Phase 5+: Verification, PoC, chain detection

CRASH-PROOFING (Sprint 7.6.1):
Tool wrappers (JadxRunner) now return ToolResult instead of raising.
Phase 1 checks `result.success` and continues with whatever succeeded.
A scan can complete with partial Phase 1 results — agents that need
JADX output will simply produce no findings if JADX failed.
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
from sentinel.tools.apktool import ApktoolError, ApktoolRunner
from sentinel.tools.jadx import JadxRunner
from sentinel.tools.manifest import ManifestError, ManifestParser
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
    """Runs a scan through the phase pipeline.

    Sprint 7 adds Phase 3 (LLM triage). Sprint 7.6.1 makes Phase 1
    crash-proof via ToolResult.
    """

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        agents: list[type[BaseAgent]] | None = None,
        triager: LLMTriager | None = None,
    ) -> None:
        self._context = context
        self._memory = memory
        self._agents = agents if agents is not None else [PipelineSmokeTestAgent]
        self._triager = triager

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

            # Phase 1: Recon (crash-proof)
            start = asyncio.get_event_loop().time()
            await self._phase1_recon(result)
            result.phase_timings["phase1"] = asyncio.get_event_loop().time() - start

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

    # ---------- Phase 1: Recon (crash-proof) ----------

    async def _phase1_recon(self, scan_result: ScanResult) -> None:
        """Decompile the APK and parse its manifest.

        CRASH-PROOF: All tool failures are caught and recorded as warnings.
        Scan continues with whatever succeeded. Even if all tools fail, the
        manifest is still parseable directly from the APK binary.
        """
        logger.info("[%s] Phase 1: Recon", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 1},
        )

        ws = self._context.workspace
        decompile_dir = ws / "decompiled"
        resources_dir = ws / "resources"

        # JADX — uses ToolResult, never raises
        jadx = JadxRunner()
        jadx_result = await jadx.decompile(self._context.apk_path, decompile_dir)
        if jadx_result.success:
            logger.info(
                "JADX produced %d Java files in %.1fs",
                jadx_result.data.java_file_count,
                jadx_result.duration_seconds,
            )
            for warning in jadx_result.warnings:
                scan_result.warnings.append(f"JADX: {warning}")
        else:
            logger.warning("JADX failed: %s", jadx_result.error)
            scan_result.warnings.append(f"JADX failed: {jadx_result.error}")

        # apktool — still raises ApktoolError; we catch it here
        apktool = ApktoolRunner()
        apktool_succeeded = False
        try:
            await apktool.decode(self._context.apk_path, resources_dir)
            apktool_succeeded = True
            logger.info("apktool produced manifest + resources")
        except ApktoolError as e:
            logger.warning("apktool failed: %s", e)
            scan_result.warnings.append(f"apktool failed: {e}")
        except Exception as e:  # noqa: BLE001
            logger.exception("apktool crashed unexpectedly")
            scan_result.warnings.append(f"apktool crashed: {type(e).__name__}: {e}")

        # Manifest parsing via androguard reads the APK binary directly,
        # so it works even when both decompilers fail.
        manifest_parser = ManifestParser()
        manifest: dict[str, Any] = {}
        try:
            manifest = manifest_parser.parse(self._context.apk_path)
        except ManifestError as e:
            logger.warning("Manifest parse failed: %s", e)
            scan_result.warnings.append(f"Manifest parse failed: {e}")
            # Manifest is critical — without it, most agents can't function.
            # But we still don't crash; we let agents handle empty manifest.
            manifest = {}
        except Exception as e:  # noqa: BLE001
            logger.exception("Manifest parser crashed unexpectedly")
            scan_result.warnings.append(
                f"Manifest crashed: {type(e).__name__}: {e}"
            )
            manifest = {}

        # Set context based on what succeeded
        self._context.decompiled_dir = (
            decompile_dir if jadx_result.success else None
        )
        self._context.resources_dir = (
            resources_dir if apktool_succeeded else None
        )
        self._context.manifest = manifest
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
                    jadx_result.data.java_file_count
                    if jadx_result.success else 0
                ),
                "jadx_succeeded": jadx_result.success,
                "apktool_succeeded": apktool_succeeded,
                "warnings_count": len(scan_result.warnings),
            },
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
