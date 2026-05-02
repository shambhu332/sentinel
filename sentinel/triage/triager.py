"""LLMTriager — orchestrates LLM-based triage of agent findings.

Given a list of findings + the scan context, the triager:
1. Loads source code context for each finding
2. Renders the agent-specific prompt template
3. Calls the LLM via FreeProviderRouter.query_json()
4. Validates the JSON response against TriageVerdict
5. Updates each finding's evidence with the triage outcome
6. Returns the same list (no findings are discarded — filtered ones
   are kept with outcome="filtered" so users can audit decisions)

Design notes:
- Triage failures NEVER kill the scan. They mark the finding as UNCERTAIN.
- Findings are processed sequentially. Concurrent triage is possible but
  rate limits make sequential simpler/safer for now.
- INFO-severity findings (TEST_001, META_001) are skipped — they're not
  bugs to triage.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from pydantic import ValidationError

from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.llm.router import FreeProviderRouter, RouterError
from sentinel.triage.code_loader import load_code_context
from sentinel.triage.models import TriageOutcome, TriageResult, TriageVerdict
from sentinel.triage.prompts import SYSTEM_PROMPT, render_prompt

logger = logging.getLogger(__name__)


# Findings with these agent IDs are skipped — they're informational, not bugs
_SKIP_AGENTS = {"TEST_001", "META_001"}


class LLMTriager:
    """Reviews agent findings using LLM analysis to filter false positives.

    Wraps the existing FreeProviderRouter (Cerebras + Ollama with failover).
    Uses query_json() which handles JSON mode + markdown fence stripping
    + JSON parsing automatically.
    """

    def __init__(
        self,
        router: FreeProviderRouter,
        max_retries: int = 1,
    ) -> None:
        self._router = router
        # Note: the router itself has internal retries for transient errors.
        # `max_retries` here is for re-prompting on schema validation
        # failures (LLM returned valid JSON but wrong shape).
        self._max_retries = max_retries

    async def triage(
        self,
        findings: list[Finding],
        context: ScanContext,
    ) -> list[Finding]:
        """Triage a list of findings in place.

        Returns the same list — findings are mutated to include triage
        outcome and explanation in their evidence dict.
        """
        if not findings:
            return findings

        logger.info("[triage] Starting LLM triage of %d findings", len(findings))

        for finding in findings:
            if finding.agent_id in _SKIP_AGENTS:
                self._attach_result(finding, TriageResult(outcome=TriageOutcome.SKIPPED))
                continue

            if finding.severity == Severity.INFO:
                self._attach_result(finding, TriageResult(outcome=TriageOutcome.SKIPPED))
                continue

            result = await self._triage_one(finding, context)
            self._attach_result(finding, result)

        # Apply adjusted severity if LLM suggested one (only for verified)
        for finding in findings:
            tr = self._get_result(finding)
            if (tr and tr.outcome == TriageOutcome.VERIFIED
                    and tr.verdict and tr.verdict.adjusted_severity):
                self._apply_severity_adjustment(finding, tr.verdict.adjusted_severity)

        verified = sum(1 for f in findings if self._is_outcome(f, TriageOutcome.VERIFIED))
        filtered = sum(1 for f in findings if self._is_outcome(f, TriageOutcome.FILTERED))
        uncertain = sum(1 for f in findings if self._is_outcome(f, TriageOutcome.UNCERTAIN))
        skipped = sum(1 for f in findings if self._is_outcome(f, TriageOutcome.SKIPPED))

        logger.info(
            "[triage] Complete: %d verified, %d filtered, %d uncertain, %d skipped",
            verified, filtered, uncertain, skipped,
        )
        return findings

    async def _triage_one(
        self,
        finding: Finding,
        context: ScanContext,
    ) -> TriageResult:
        """Triage a single finding. Returns a TriageResult."""
        start = time.monotonic()

        # Load source code context
        code_snippet, file_path = load_code_context(finding, context.decompiled_dir)

        # Render prompt
        try:
            user_prompt = render_prompt(finding, code_snippet, file_path)
        except Exception as e:
            logger.warning("[triage] Prompt rendering failed for %s: %s",
                           finding.agent_id, e)
            return TriageResult(
                outcome=TriageOutcome.UNCERTAIN,
                error=f"prompt_render_failed: {type(e).__name__}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        # Build messages list (router takes a list of role/content dicts)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        # Call LLM with retries for schema validation failures
        last_error: Optional[str] = None
        last_provider: Optional[str] = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._router.query_json(messages=messages)
            except RouterError as e:
                last_error = f"router_error: {e}"
                logger.debug("[triage] Router error on attempt %d: %s",
                             attempt + 1, last_error)
                continue
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                logger.debug("[triage] Unexpected error on attempt %d: %s",
                             attempt + 1, last_error)
                continue

            last_provider = response.get("provider")
            content = response.get("content")

            # query_json() returns content as a parsed dict
            if not isinstance(content, dict):
                last_error = f"unexpected_content_type: {type(content).__name__}"
                logger.debug("[triage] LLM returned non-dict content: %r", content)
                continue

            # Validate against TriageVerdict schema
            try:
                verdict = TriageVerdict.model_validate(content)
            except ValidationError as e:
                last_error = f"schema_validation_failed: {e.errors()[0]['msg']}"
                logger.debug("[triage] Verdict validation failed: %s", e)
                continue

            # Success
            outcome = TriageOutcome.VERIFIED if verdict.is_real_bug else TriageOutcome.FILTERED
            return TriageResult(
                outcome=outcome,
                verdict=verdict,
                llm_provider=last_provider,
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        # All retries failed — return UNCERTAIN
        return TriageResult(
            outcome=TriageOutcome.UNCERTAIN,
            error=last_error or "unknown_error",
            llm_provider=last_provider,
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    @staticmethod
    def _attach_result(finding: Finding, result: TriageResult) -> None:
        """Stash the triage result inside the finding's evidence dict.

        Stored under reserved key '_triage' to avoid colliding with
        agent-produced evidence fields.
        """
        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence["_triage"] = result.model_dump(mode="json")

    @staticmethod
    def _get_result(finding: Finding) -> Optional[TriageResult]:
        """Pull triage result out of evidence (if present)."""
        if not finding.evidence:
            return None
        raw = finding.evidence.get("_triage")
        if not raw:
            return None
        try:
            return TriageResult.model_validate(raw)
        except ValidationError:
            return None

    @staticmethod
    def _is_outcome(finding: Finding, outcome: TriageOutcome) -> bool:
        """Convenience: is this finding's triage outcome X?"""
        result = LLMTriager._get_result(finding)
        return result is not None and result.outcome == outcome

    @staticmethod
    def _apply_severity_adjustment(finding: Finding, adjusted: str) -> None:
        """Update the finding's severity if the LLM suggested a change."""
        try:
            new_sev = Severity(adjusted)
        except ValueError:
            logger.debug("[triage] Invalid adjusted_severity: %s", adjusted)
            return

        if new_sev == finding.severity:
            return

        # Record adjustment in evidence so reports can reference it
        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence["_severity_original"] = finding.severity.value
        finding.evidence["_severity_adjusted_by_llm"] = True

        logger.info(
            "[triage] %s severity adjusted by LLM: %s → %s",
            finding.agent_id, finding.severity.value, new_sev.value,
        )
        # Finding has validate_assignment=True, so this triggers validation
        finding.severity = new_sev
