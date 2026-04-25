"""Orchestrator — runs a scan through the 10-phase pipeline.

Sprint 2b implements Phase 0 (ingestion) and Phase 1 (recon).
Later sprints add Phases 2-9.
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
from sentinel.tools.jadx import JadxError, JadxRunner
from sentinel.tools.manifest import ManifestError, ManifestParser

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
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "findings_count": len(self.findings),
            "phase_timings": self.phase_timings,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Orchestrator:
    """Runs a scan through the phase pipeline.

    Sprint 2b: Phases 0 and 1 fully implemented, Phase 2 runs only TEST_001.
    """

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        agents: list[type[BaseAgent]] | None = None,
    ) -> None:
        self._context = context
        self._memory = memory
        self._agents = agents if agents is not None else [PipelineSmokeTestAgent]

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

            # Phase 1: Recon
            start = asyncio.get_event_loop().time()
            await self._phase1_recon()
            result.phase_timings["phase1"] = asyncio.get_event_loop().time() - start

            # Phase 2: Run agents (only TEST_001 in Sprint 2b)
            start = asyncio.get_event_loop().time()
            findings = await self._phase2_agents()
            result.phase_timings["phase2"] = asyncio.get_event_loop().time() - start
            result.findings = findings

            result.status = "completed"

        except (OrchestratorError, JadxError, ApktoolError, ManifestError) as e:
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

        # SHA-256 hash for deduplication / caching
        h = hashlib.sha256()
        with apk.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        self._context.apk_sha256 = h.hexdigest()
        self._context.apk_size_bytes = apk.stat().st_size

        # Create per-session workspace
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

    # ---------- Phase 1: Recon ----------

    async def _phase1_recon(self) -> None:
        """Decompile the APK and parse its manifest.

        JADX and apktool run independently — a failure in one does not
        cancel the other. Manifest parsing via androguard is independent
        of both decompilers and reads the APK binary directly.
        """
        logger.info("[%s] Phase 1: Recon", self._context.session_id)
        await self._memory.publish_event(
            self._context.session_id, "phase.started", {"phase": 1},
        )

        ws = self._context.workspace
        decompile_dir = ws / "decompiled"
        resources_dir = ws / "resources"

        jadx = JadxRunner()
        apktool = ApktoolRunner()
        manifest_parser = ManifestParser()

        jadx_result = None
        apktool_result = None

        try:
            jadx_result = await jadx.decompile(self._context.apk_path, decompile_dir)
            logger.info("JADX produced %d Java files", jadx_result.java_file_count)
        except JadxError as e:
            logger.warning("JADX failed: %s", e)

        try:
            apktool_result = await apktool.decode(self._context.apk_path, resources_dir)
            logger.info("apktool produced manifest + resources")
        except ApktoolError as e:
            logger.warning("apktool failed: %s", e)

        # Manifest parsing via androguard reads the APK binary directly,
        # so it works even when both decompilers fail.
        manifest = manifest_parser.parse(self._context.apk_path)

        self._context.decompiled_dir = decompile_dir if jadx_result else None
        self._context.resources_dir = resources_dir if apktool_result else None
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
                "java_files": jadx_result.java_file_count if jadx_result else 0,
                "jadx_succeeded": jadx_result is not None,
                "apktool_succeeded": apktool_result is not None,
            },
        )

    # ---------- Phase 2: Agents ----------

    async def _phase2_agents(self) -> list[Finding]:
        """Run the registered agents. Sprint 2b runs only TEST_001."""
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
                logger.exception("Agent %s failed to initialise", agent_cls.__name__)

        await self._memory.publish_event(
            self._context.session_id, "phase.completed",
            {"phase": 2, "findings_count": len(all_findings)},
        )
        return all_findings

    # ---------- Helpers ----------

    async def cleanup(self, keep_workspace: bool = False) -> None:
        """Clean up session workspace unless --keep-workspace was passed."""
        if keep_workspace:
            return
        ws = self._context.workspace
        if ws.exists() and str(ws).startswith(str(Path.home())):
            shutil.rmtree(ws, ignore_errors=True)
