"""AIAutonomousAgent — base class for LLM-first detection agents.

Pipeline for every subclass:
  1. fast_pre_filter() — regex/rule candidates in <100ms per file
  2. LLMVulnerabilityAnalyzer.analyze_candidate() — LLM decides true/false
  3. Emit findings, flag uncertains, log false positives

Subclasses implement only fast_pre_filter(). Everything else is handled here.
"""
from __future__ import annotations

import logging
from abc import abstractmethod
from dataclasses import dataclass
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, FindingCategory, Severity, TriageState
from sentinel.core.scan_context import ScanContext
from sentinel.llm.vulnerability_analyzer import (
    LLMVulnerabilityAnalyzer,
    LLMVerdict,
    VulnerabilityVerdict,
)
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

MAX_CANDIDATES = 50


@dataclass
class Candidate:
    """A rule-suggested vulnerability candidate awaiting LLM analysis."""
    code_snippet: str
    file_path: str
    line_number: int
    column: int
    rule_triggered: str
    rule_confidence: float
    context_window: str


class AIAutonomousAgent(BaseAgent):
    """Abstract base for AI-autonomous detection.

    Subclasses must implement:
      - fast_pre_filter(ctx) → list[Candidate]

    Constructor accepts optional keyword-only `llm_analyzer` for dependency
    injection (testing, custom routers). When None, a shared singleton is
    built lazily from the process-level FreeProviderRouter.
    """

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
        *,
        llm_analyzer: LLMVulnerabilityAnalyzer | None = None,
    ) -> None:
        super().__init__(context, memory, config)
        self._llm_analyzer = llm_analyzer

    # ------------------------------------------------------------------ #
    # Abstract                                                             #
    # ------------------------------------------------------------------ #

    @abstractmethod
    async def fast_pre_filter(self, ctx: ScanContext) -> list[Candidate]:
        """Fast rule-based pre-filter. High recall, low precision is fine.

        Must complete in <100ms per file. Returns candidates for LLM analysis.
        """

    # ------------------------------------------------------------------ #
    # BaseAgent implementation                                             #
    # ------------------------------------------------------------------ #

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        candidates = await self.fast_pre_filter(ctx)
        if not candidates:
            return []

        # Cap to avoid runaway LLM costs; keep highest-confidence hits
        if len(candidates) > MAX_CANDIDATES:
            candidates = sorted(candidates, key=lambda c: c.rule_confidence, reverse=True)
            candidates = candidates[:MAX_CANDIDATES]
            self._log.info(
                "%s: capped candidates to %d (originally more)",
                self.AGENT_ID, MAX_CANDIDATES,
            )

        analyzer = self._get_analyzer()
        app_category: str = ctx.app_profile.get("category", "general")

        findings: list[Finding] = []
        for candidate in candidates:
            verdict = await analyzer.analyze_candidate(
                code_snippet=candidate.code_snippet,
                file_path=candidate.file_path,
                line_number=candidate.line_number,
                rule_triggered=candidate.rule_triggered,
                rule_confidence=candidate.rule_confidence,
                full_file_context=candidate.context_window,
                app_category=app_category,
            )
            self._log.debug(
                "%s: %s:%d → %s (conf=%.2f%s)",
                self.AGENT_ID, candidate.file_path, candidate.line_number,
                verdict.verdict.value, verdict.confidence,
                " CACHED" if verdict.cached else "",
            )

            finding = self._handle_verdict(verdict, candidate)
            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------ #
    # Verdict routing                                                      #
    # ------------------------------------------------------------------ #

    def _handle_verdict(self, verdict: LLMVerdict, candidate: Candidate) -> Finding | None:
        if verdict.verdict == VulnerabilityVerdict.TRUE_POSITIVE:
            return self._verdict_to_finding(verdict, candidate)

        if verdict.verdict == VulnerabilityVerdict.NEEDS_DAST_VALIDATION:
            f = self._verdict_to_finding(verdict, candidate)
            # Mark for human/DAST review
            object.__setattr__(f, "triage", TriageState.NEEDS_VERIFICATION)
            return f

        if verdict.verdict == VulnerabilityVerdict.UNCERTAIN:
            # Emit as Info so it's visible but deprioritised
            f = self._verdict_to_finding(verdict, candidate, override_severity=Severity.INFO)
            return f

        # FALSE_POSITIVE — log for calibration, don't emit
        self._log.info(
            "%s: false positive suppressed — %s",
            self.AGENT_ID, (verdict.false_positive_reason or "")[:120],
        )
        self._publish_calibration_event(verdict, candidate)
        return None

    def _verdict_to_finding(
        self,
        verdict: LLMVerdict,
        candidate: Candidate,
        override_severity: Severity | None = None,
    ) -> Finding:
        severity = override_severity or _SEVERITY_MAP.get(
            verdict.severity.lower(), Severity.INFO
        )

        # Truncate to Finding field limits
        vuln_class = verdict.vulnerability_type[:200] or f"{self.VULN_CLASS} — AI Detected"
        if verdict.verdict == VulnerabilityVerdict.UNCERTAIN:
            vuln_class = f"[UNCERTAIN] {vuln_class}"[:200]

        recommendation = self._build_recommendation(verdict)

        # Exploit path serialised into evidence
        exploit_path_dicts = [
            {
                "step": s.step_number,
                "action": s.action,
                "prerequisite": s.prerequisite,
                "expected_result": s.expected_result,
            }
            for s in verdict.exploit_path
        ]

        evidence: dict[str, Any] = {
            "file": candidate.file_path,
            "line": candidate.line_number,
            "column": candidate.column,
            "code_snippet": candidate.code_snippet[:500],
            "rule_triggered": candidate.rule_triggered,
            "rule_confidence": candidate.rule_confidence,
            "llm_confidence": verdict.confidence,
            "llm_provider": verdict.provider,
            "exploit_path": exploit_path_dicts,
            "business_impact": verdict.business_impact[:500],
            "similar_cves": verdict.similar_cves[:10],
            "dast_validation": verdict.dast_validation_needed,
        }

        # Strip None values (Finding validates evidence is dict[str, Any])
        evidence = {k: v for k, v in evidence.items() if v is not None}

        # OWASP ≤50 chars, MASVS ≤20 chars
        owasp = self._extract_owasp(verdict.owasp_masvs_mapping)
        masvs = self._extract_masvs(verdict.owasp_masvs_mapping)

        # CWE tags from vulnerability_type field
        compliance = self._extract_compliance_tags(verdict)

        return Finding(
            agent_id=self.AGENT_ID,
            session_id=self._context.session_id,
            vuln_class=vuln_class,
            severity=severity,
            confidence=round(max(verdict.confidence, candidate.rule_confidence * 0.8), 3),
            evidence=evidence,
            recommendation=recommendation,
            severity_rationale=verdict.reasoning[:4000],
            compliance_tags=compliance,
            owasp=owasp,
            masvs=masvs,
            finding_category=cast_category(verdict),
            code_snippet={
                "file": candidate.file_path,
                "line": candidate.line_number,
                "content": candidate.code_snippet[:4000],
            },
        )

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _get_analyzer(self) -> LLMVulnerabilityAnalyzer:
        if self._llm_analyzer is not None:
            return self._llm_analyzer
        # Lazy singleton construction — avoids import at module load time
        from sentinel.llm.router import FreeProviderRouter
        from sentinel.rag.knowledge_base import KnowledgeBase
        from sentinel.rag.retriever import KnowledgeRetriever

        router = FreeProviderRouter()
        kb_path = KnowledgeBase.default_persist_path(self._context.workspace)
        kb = KnowledgeBase(persist_path=kb_path)
        # KnowledgeBase.connect() is async; skip if not already connected —
        # the retriever handles an unconnected KB gracefully (returns [])
        retriever = KnowledgeRetriever(kb)
        self._llm_analyzer = LLMVulnerabilityAnalyzer(router=router, retriever=retriever)
        return self._llm_analyzer

    def _publish_calibration_event(self, verdict: LLMVerdict, candidate: Candidate) -> None:
        import asyncio
        payload = {
            "agent_id": self.AGENT_ID,
            "rule_triggered": candidate.rule_triggered,
            "rule_confidence": candidate.rule_confidence,
            "llm_verdict": verdict.verdict.value,
            "llm_confidence": verdict.confidence,
            "file_path": candidate.file_path,
            "line_number": candidate.line_number,
            "false_positive_reason": (verdict.false_positive_reason or "")[:200],
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(
                    self._memory.publish_event(
                        session_id=self._context.session_id,
                        event_type="calibration.disagreement",
                        payload=payload,
                    )
                )
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _build_recommendation(verdict: LLMVerdict) -> str:
        parts: list[str] = []
        if verdict.remediation_code:
            parts.append(f"Secure code example:\n{verdict.remediation_code}")
        if verdict.remediation_steps:
            steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(verdict.remediation_steps))
            parts.append(f"Steps:\n{steps}")
        return "\n\n".join(parts) or "Review and remediate the flagged code."

    @staticmethod
    def _extract_owasp(mappings: list[str]) -> str | None:
        for m in mappings:
            if m.startswith("M") and len(m) <= 50:
                return m[:50]
        return None

    @staticmethod
    def _extract_masvs(mappings: list[str]) -> str | None:
        for m in mappings:
            if "MASVS" in m and len(m) <= 20:
                return m[:20]
        return None

    @staticmethod
    def _extract_compliance_tags(verdict: LLMVerdict) -> list[str]:
        tags: list[str] = []
        vtype = verdict.vulnerability_type
        import re
        for cwe in re.findall(r"CWE-\d+", vtype):
            if cwe not in tags:
                tags.append(cwe)
        return tags


def cast_category(verdict: LLMVerdict) -> FindingCategory:
    if verdict.verdict == VulnerabilityVerdict.TRUE_POSITIVE and verdict.reasoning:
        return "AI-Powered"
    return "Static_Tool"
