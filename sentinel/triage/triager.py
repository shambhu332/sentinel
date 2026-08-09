"""LLMTriager — orchestrates LLM-based triage of agent findings.

Given a list of findings + the scan context, the triager:
1. Loads source code context for each finding
2. Renders the agent-specific prompt template
3. Calls the LLM via FreeProviderRouter.query_json()
4. Validates the JSON response against TriageVerdict
5. Updates each finding's evidence with the triage outcome
6. Returns the same list (filtered findings kept with outcome="filtered"
   so users can audit decisions)

Design notes:
- Triage failures NEVER kill the scan. They mark the finding as UNCERTAIN.
- Findings are processed sequentially with a configurable inter-call delay
  to stay within free-tier RPM limits (Groq is 30 RPM = 1 call / 2s).
- INFO-severity findings (TEST_001, META_001) are skipped — they're not
  bugs to triage.
- Tolerant of LLMs that nest the verdict (e.g. {"verdict": {...}}).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from pydantic import ValidationError

from sentinel.core.finding import Finding, Severity, derive_verification_state
from sentinel.core.scan_context import ScanContext
from sentinel.llm.router import FreeProviderRouter, RouterError
from sentinel.rag.enricher import KnowledgeEnricher
from sentinel.triage.code_loader import load_code_context
from sentinel.triage.models import TriageOutcome, TriageResult, TriageVerdict
from sentinel.triage.prompts import SYSTEM_PROMPT, render_prompt

logger = logging.getLogger(__name__)


# Triage skips by severity (INFO) — see _is_skippable() below. The
# previous closed-set agent-ID list silently missed any future
# INFO-only agent, burning LLM tokens unnecessarily.

# Sleep between LLM calls to stay within free-tier rate limits.
# Groq's free tier: 30 RPM = 1 call every 2 seconds.
# Setting to 2.5s gives a safety margin and ensures we never burst.
# This adds ~30s to total scan time on a 12-finding triage but raises
# the success rate from ~50% (with 429 fallbacks to weaker models)
# to ~95% (Groq Llama 70B handles every call).
_INTER_CALL_DELAY_SECONDS = 2.5


class LLMTriager:
    """Reviews agent findings using LLM analysis to filter false positives."""

    def __init__(
        self,
        router: FreeProviderRouter,
        max_retries: int = 1,
        inter_call_delay_seconds: float = _INTER_CALL_DELAY_SECONDS,
        enricher: KnowledgeEnricher | None = None,
    ) -> None:
        self._router = router
        self._max_retries = max_retries
        # Test code can pass 0.0 to skip rate-limit sleeps
        self._inter_call_delay = inter_call_delay_seconds
        # Optional RAG layer. When provided, every triaged finding is
        # enriched with retrieved MASVS / OWASP / CWE passages, which
        # are prepended to the LLM prompt and persisted into the
        # finding's evidence so downstream consumers (the VAPT report
        # generator) can render the compliance mapping.
        self._enricher = enricher

    async def triage(
        self,
        findings: list[Finding],
        context: ScanContext,
    ) -> list[Finding]:
        """Triage a list of findings in place."""
        if not findings:
            return findings

        logger.info("[triage] Starting LLM triage of %d findings", len(findings))

        # Track whether we've made an LLM call yet — first call doesn't sleep
        first_llm_call = True

        for finding in findings:
            if finding.severity == Severity.INFO:
                self._attach_result(finding, TriageResult(outcome=TriageOutcome.SKIPPED))
                continue

            # Rate-limit: sleep before each LLM call (except the first) to stay
            # within free-tier RPM limits (Groq: 30 RPM, Cerebras: variable).
            # Local providers (vLLM, Ollama) have no external rate limit — skip
            # the delay when they answered the previous call.
            if not first_llm_call and self._inter_call_delay > 0:
                if not self._router.last_provider_is_local:
                    await asyncio.sleep(self._inter_call_delay)
                else:
                    logger.debug("[triage] local provider answered last call — skipping rate-limit sleep")
            first_llm_call = False

            result = await self._triage_one(finding, context)
            self._attach_result(finding, result)

        # Apply adjusted severity if LLM suggested one (only for verified)
        for finding in findings:
            tr = self._get_result(finding)
            if (tr and tr.outcome == TriageOutcome.VERIFIED
                    and tr.verdict and tr.verdict.adjusted_severity):
                self._apply_severity_adjustment(finding, tr.verdict.adjusted_severity)

        # Surface the triage verdict onto first-class Finding fields so the
        # detail view / classifier can use it without poking into evidence.
        # This is what flips a finding out of the "Static Tool" bucket and
        # into "AI-Powered AppSec" downstream.
        for finding in findings:
            tr = self._get_result(finding)
            self._apply_triage_to_finding(finding, tr)

        # Backfill severity_rationale for any auth_gated finding that
        # didn't already get one from the Phase 4.5 dispatcher. Static
        # paths (e.g. SAST findings the user later marks auth_gated)
        # never pass through the dispatcher, so without this step they
        # would render in the Auth-Gated bucket with no narrative.
        await self._fill_auth_gated_rationales(findings)

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

        # RAG enrichment — optional, never blocks triage on failure.
        rag_context = await self._gather_rag_context(finding)
        if rag_context:
            user_prompt = f"{rag_context}\n\n{user_prompt}"

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

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

            if not isinstance(content, dict):
                last_error = f"unexpected_content_type: {type(content).__name__}"
                logger.debug("[triage] LLM returned non-dict content: %r", content)
                continue

            # Try to extract a TriageVerdict, accommodating variations in LLM output
            verdict = self._extract_verdict(content)
            if verdict is None:
                last_error = "schema_validation_failed: could not parse verdict"
                logger.debug("[triage] Verdict parse failed for content: %r",
                             list(content.keys()) if isinstance(content, dict) else content)
                continue

            # Success
            outcome = TriageOutcome.VERIFIED if verdict.is_real_bug else TriageOutcome.FILTERED
            return TriageResult(
                outcome=outcome,
                verdict=verdict,
                llm_provider=last_provider,
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        return TriageResult(
            outcome=TriageOutcome.UNCERTAIN,
            error=last_error or "unknown_error",
            llm_provider=last_provider,
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    @staticmethod
    def _extract_verdict(content: dict[str, Any]) -> Optional[TriageVerdict]:
        """Try multiple shapes the LLM might use for the verdict.

        Most reliable: top-level dict with our four fields. But small models
        sometimes nest the verdict under 'verdict' or 'result' keys, or
        rename fields slightly. We try a few common shapes.
        """
        # Shape 1: top-level dict with our fields (most common, expected)
        try:
            return TriageVerdict.model_validate(content)
        except ValidationError:
            pass

        # Shape 2: nested under 'verdict' key
        if "verdict" in content and isinstance(content["verdict"], dict):
            try:
                return TriageVerdict.model_validate(content["verdict"])
            except ValidationError:
                pass

        # Shape 3: nested under 'result' key
        if "result" in content and isinstance(content["result"], dict):
            try:
                return TriageVerdict.model_validate(content["result"])
            except ValidationError:
                pass

        # Shape 4: synthesize from looser keys (handles models that rename fields)
        synthesized = {
            "is_real_bug": content.get("is_real_bug",
                                       content.get("real_bug",
                                                   content.get("real",
                                                               content.get("vulnerable")))),
            "confidence": content.get("confidence",
                                      content.get("confidence_score", 0.5)),
            "explanation": content.get("explanation",
                                       content.get("reasoning",
                                                   content.get("analysis",
                                                               content.get("description",
                                                                           "")))),
            "adjusted_severity": content.get("adjusted_severity",
                                             content.get("severity")),
            "false_positive_reason": content.get("false_positive_reason",
                                                 content.get("fp_reason")),
        }
        # Drop None values for required fields so validation gives a clearer error
        if synthesized["is_real_bug"] is None:
            return None
        if not synthesized["explanation"] or len(synthesized["explanation"]) < 10:
            # explanation too short — pad with whatever info we have
            synthesized["explanation"] = (
                f"LLM verdict: is_real_bug={synthesized['is_real_bug']}. "
                f"No detailed explanation provided."
            )
        try:
            return TriageVerdict.model_validate(synthesized)
        except ValidationError:
            return None

    async def _gather_rag_context(self, finding: Finding) -> str:
        """Return a prompt-ready context block for the finding, or ``""``.

        Persists the structured compliance mapping into
        ``finding.evidence['_rag_mapping']`` so downstream consumers
        (the VAPT report generator, the API) can render references
        without re-querying the knowledge base.
        """
        if self._enricher is None:
            return ""
        try:
            enriched = await self._enricher.enrich(finding)
        except Exception as exc:  # noqa: BLE001 - never block triage
            logger.warning(
                "[triage] RAG enrichment failed for %s: %s",
                finding.agent_id, exc,
            )
            return ""
        if not enriched.passages:
            return ""
        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence["_rag_mapping"] = enriched.compliance_mapping
        finding.evidence["_rag_passage_ids"] = [
            p.source for p in enriched.passages
        ]
        return enriched.prompt_context(max_passages=3)

    @staticmethod
    def _attach_result(finding: Finding, result: TriageResult) -> None:
        """Stash the triage result inside the finding's evidence dict."""
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
    def _apply_triage_to_finding(
        finding: Finding,
        result: Optional[TriageResult],
    ) -> None:
        """Lift the triage verdict onto Finding's first-class fields.

        - ``severity_rationale`` gets the LLM's explanation so the
          detail view's "Severity rationale" block has authoritative
          narrative (overrides any agent-supplied default — the LLM
          read the code, the agent didn't).
        - ``verification_status`` carries the LLM's outcome so the
          bucket classifier (frontend + R_001) can route the finding
          into "AI-Powered AppSec" instead of "Static Tool".

        Filtered findings keep ``verification_status="Code-level only"``
        (and retain whatever rationale the agent set) because the
        report layer strips them; touching their first-class fields
        would only confuse downstream consumers if they ever leak.
        """
        if result is None:
            return
        if result.outcome == TriageOutcome.SKIPPED:
            return

        verdict = result.verdict
        if verdict is None and result.outcome != TriageOutcome.UNCERTAIN:
            return

        if result.outcome == TriageOutcome.VERIFIED and verdict is not None:
            explanation = verdict.explanation.strip()
            if verdict.adjusted_severity:
                explanation = (
                    f"{explanation}\n\nSeverity adjusted by LLM triage to "
                    f"{verdict.adjusted_severity}."
                )
            try:
                finding.severity_rationale = explanation
                finding.verification_status = "Verified by LLM triage"
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[triage] could not apply verified verdict to %s: %s",
                    finding.agent_id, exc,
                )
        elif result.outcome == TriageOutcome.FILTERED and verdict is not None:
            # Don't touch verification_status — agent default ("Code-level
            # only") is correct; the finding is being filtered out anyway.
            # But do persist the FP reasoning into evidence so reviewers
            # who unhide filtered findings can see why the LLM dropped it.
            if finding.evidence is None:
                finding.evidence = {}
            finding.evidence["_filter_reason"] = (
                verdict.false_positive_reason or verdict.explanation
            )
        elif result.outcome == TriageOutcome.UNCERTAIN:
            try:
                finding.verification_status = (
                    "LLM triage uncertain — needs human review"
                )
                if verdict is not None:
                    finding.severity_rationale = verdict.explanation.strip()
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[triage] could not apply uncertain verdict to %s: %s",
                    finding.agent_id, exc,
                )

    async def _fill_auth_gated_rationales(
        self, findings: list[Finding],
    ) -> None:
        """Generate a severity rationale for every auth-gated finding
        that doesn't already have one.

        Rate-limited with the same inter-call delay as triage proper
        (Groq free-tier sits at 30 RPM). Never raises — a failed
        rationale leaves the finding untouched, which the renderer
        handles gracefully.
        """
        from sentinel.llm.severity_rationale import (
            RationaleInput,
            generate_auth_gated_rationale,
        )

        targets = [
            f for f in findings
            if derive_verification_state(f) == "auth_gated"
            and not (f.severity_rationale or "").strip()
        ]
        if not targets:
            return

        logger.info(
            "[triage] generating %d auth-gated severity rationales",
            len(targets),
        )
        first = True
        for finding in targets:
            if not first and self._inter_call_delay > 0:
                await asyncio.sleep(self._inter_call_delay)
            first = False
            blocking_reason = (
                finding.verification_status
                or "auto-login blocked the runtime probe"
            )
            try:
                rationale = await generate_auth_gated_rationale(
                    RationaleInput(
                        vuln_class=finding.vuln_class,
                        static_evidence=finding.evidence or {},
                        observed_runtime_behavior=(
                            finding.observed_result
                            or "Probe blocked before reaching the "
                               "vulnerable surface"
                        ),
                        blocking_reason=blocking_reason,
                    ),
                    router=self._router,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[triage] rationale generation failed for %s: %s",
                    finding.agent_id, exc,
                )
                continue
            if rationale:
                finding.severity_rationale = rationale

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

        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence["_severity_original"] = finding.severity.value
        finding.evidence["_severity_adjusted_by_llm"] = True

        logger.info(
            "[triage] %s severity adjusted by LLM: %s → %s",
            finding.agent_id, finding.severity.value, new_sev.value,
        )
        finding.severity = new_sev
