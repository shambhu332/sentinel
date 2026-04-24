"""TEST_001 — Pipeline smoke test agent.

Purpose: prove that the full pipeline works end-to-end without depending on
external tools (JADX, Frida, etc). Emits one synthetic finding every scan.

This is the agent the orchestrator runs in Sprint 2 to verify the pipeline
works before we add real detection agents in Sprint 3+.
"""
from __future__ import annotations

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity


class PipelineSmokeTestAgent(BaseAgent):
    """Emits one informational finding to prove the pipeline runs."""

    AGENT_ID = "TEST_001"
    VULN_CLASS = "Pipeline Smoke Test"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return True

    async def analyze(self) -> list[Finding]:
        finding = self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=1.0,
            evidence={
                "apk_path": str(self._context.apk_path),
                "apk_sha256": self._context.apk_sha256 or "not_computed",
                "session_id": self._context.session_id,
                "test_agent": True,
            },
            recommendation=(
                "This is a synthetic finding from TEST_001. Its presence confirms "
                "the SENTINEL pipeline is working end-to-end. It does not indicate "
                "a real vulnerability."
            ),
        )
        return [finding]
