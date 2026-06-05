"""COR_001 — Exploit Chain Correlation Agent.

Runs in Phase 7 after all Phase 2 agents complete. Analyzes the full
set of findings to detect exploit chains where multiple low/medium
severity vulnerabilities combine into critical impact.

Example chains:
- Cleartext HTTP + Missing Pinning + Token in URL → Critical token theft
- WebView JS enabled + addJavascriptInterface + file access → RCE
- World-readable storage + exported provider → Data exfiltration
"""
from __future__ import annotations

import logging

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding
from sentinel.correlation.detector import ChainDetector

logger = logging.getLogger(__name__)


class ExploitChainAgent(BaseAgent):
    """Detects exploit chains across multiple findings."""

    AGENT_ID = "COR_001"
    VULN_CLASS = "Exploit Chain"
    PHASE = "Phase 7"

    async def is_applicable(self) -> bool:
        """Always applicable — runs after Phase 2 agents."""
        return True

    async def analyze(self) -> list[Finding]:
        """Detect exploit chains from all findings in this session."""
        # Fetch all findings from Phase 2
        all_findings = await self._memory.get_findings(
            session_id=self._context.session_id,
        )

        if len(all_findings) < 2:
            logger.info(
                "[%s] COR_001: Only %d findings, skipping chain detection",
                self._context.session_id, len(all_findings),
            )
            return []

        # Filter out INFO and previous chain findings
        candidate_findings = [
            f for f in all_findings
            if f.severity.value != "Info" and f.agent_id != "COR_001"
        ]

        if len(candidate_findings) < 2:
            logger.info(
                "[%s] COR_001: Only %d non-INFO findings, skipping",
                self._context.session_id, len(candidate_findings),
            )
            return []

        logger.info(
            "[%s] COR_001: Analyzing %d findings for exploit chains",
            self._context.session_id, len(candidate_findings),
        )

        # Run chain detection
        detector = ChainDetector(
            memory=self._memory,
            session_id=self._context.session_id,
        )

        chains = await detector.detect_chains(
            findings=candidate_findings,
            use_llm=False,  # LLM discovery in Task #5
        )

        # Convert chains to findings
        chain_findings: list[Finding] = []
        for chain in chains:
            finding = chain.to_finding(session_id=self._context.session_id)
            chain_findings.append(finding)

        if chain_findings:
            logger.warning(
                "[%s] COR_001: Detected %d exploit chains!",
                self._context.session_id, len(chain_findings),
            )
        else:
            logger.info(
                "[%s] COR_001: No exploit chains detected",
                self._context.session_id,
            )

        return chain_findings
