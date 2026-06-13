"""SWARM_001 — Adversarial swarm orchestrator.

For every High/Critical finding the orchestrator can ask the LLM to
play two roles in parallel:

  Red Agent   — Generate a *theoretical* proof-of-concept: the
                exploitation steps, the attacker's vantage point, the
                impact narrative. Output is intentionally pseudo-code
                + prose, never working executable code.
  Blue Agent  — Generate detection rules: a Semgrep pattern that would
                catch this bug in CI, a WAF rule that would catch it
                at the edge, and a log signature that would catch it
                in production.

Cost gate:
  * Severity filter — only High/Critical findings trigger the swarm.
  * Cache — keyed by sha256 of (agent_id, vuln_class, sanitised
    snippet). Same bug seen twice never hits the LLM twice.
  * Opt-in — orchestrator only runs when explicitly invoked. The
    caller (CLI / API) decides when to spend the tokens.

Privacy:
  * All evidence is run through `sentinel.swarm.sanitize.sanitize_evidence`
    *before* it goes into a prompt. The LLM provider never sees file
    paths, package names, URLs, real secrets, emails, or tenant UUIDs.

Custom async state machine (no LangGraph dependency) — keeps the dep
graph clean and the failure modes auditable.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sentinel.core.finding import Finding, Severity
from sentinel.swarm.sanitize import sanitize_evidence, sanitize_text

logger = logging.getLogger(__name__)

# Severity floor — anything below this never enters the swarm
_DEFAULT_FLOOR = {Severity.HIGH, Severity.CRITICAL}


@dataclass(frozen=True)
class RedAgentOutput:
    """Theoretical PoC from the Red agent."""

    poc_pseudocode: str
    exploitation_steps: list[str]
    impact_narrative: str
    raw_response: str           # the LLM's raw text, for audit


@dataclass(frozen=True)
class BlueAgentOutput:
    """Detection rules from the Blue agent."""

    semgrep_rule: str
    waf_rule: str
    log_signature: str
    raw_response: str


@dataclass(frozen=True)
class PurpleAgentOutput:
    """Business-impact narrative from the Purple agent.

    Complements the deterministic IMPACT_001 score with a one-paragraph
    narrative an executive can read directly. The Purple agent is run
    AFTER Red + Blue so it can reason about both attack and defence.
    """

    business_narrative: str
    affected_stakeholders: list[str]
    estimated_blast_radius: str
    raw_response: str


@dataclass(frozen=True)
class SwarmResult:
    """Combined Red + Blue (+ optional Purple) output for one finding."""

    finding_id: str
    cache_key: str
    red: RedAgentOutput | None
    blue: BlueAgentOutput | None
    purple: PurpleAgentOutput | None = None
    cached: bool = False
    error: str | None = None

    def to_evidence_block(self) -> dict[str, Any]:
        block = {
            "cached": self.cached,
            "red": _red_to_dict(self.red) if self.red else None,
            "blue": _blue_to_dict(self.blue) if self.blue else None,
            "error": self.error,
        }
        if self.purple is not None:
            block["purple"] = _purple_to_dict(self.purple)
        return block


def _red_to_dict(r: RedAgentOutput) -> dict[str, Any]:
    return {
        "poc_pseudocode": r.poc_pseudocode[:2000],
        "exploitation_steps": r.exploitation_steps[:10],
        "impact_narrative": r.impact_narrative[:1000],
    }


def _blue_to_dict(b: BlueAgentOutput) -> dict[str, Any]:
    return {
        "semgrep_rule": b.semgrep_rule[:2000],
        "waf_rule": b.waf_rule[:1000],
        "log_signature": b.log_signature[:500],
    }


def _purple_to_dict(p: PurpleAgentOutput) -> dict[str, Any]:
    return {
        "business_narrative": p.business_narrative[:2000],
        "affected_stakeholders": p.affected_stakeholders[:10],
        "estimated_blast_radius": p.estimated_blast_radius[:500],
    }


# ============================================================
# Prompt templates
# ============================================================

_RED_SYSTEM = (
    "You are the Red Agent of a security swarm — a senior offensive "
    "mobile security engineer. Given a vulnerability finding, output "
    "a THEORETICAL proof-of-concept: high-level pseudo-code (NOT working "
    "exploit code), 3–6 exploitation steps, and a one-paragraph impact "
    "narrative. Do NOT include any real package names, file paths, or "
    "secrets — those have already been scrubbed from the input. Return "
    "valid JSON with keys: poc_pseudocode (string), exploitation_steps "
    "(array of strings), impact_narrative (string)."
)
_BLUE_SYSTEM = (
    "You are the Blue Agent of a security swarm — a senior defensive "
    "engineer. Given a vulnerability finding and the Red team's PoC, "
    "produce three detection artifacts: a Semgrep rule (YAML body), a "
    "WAF rule (e.g. ModSecurity SecRule directive), and a log signature "
    "regex. The rules must catch the vulnerability class, not the "
    "specific instance — generalise. Return valid JSON with keys: "
    "semgrep_rule (string), waf_rule (string), log_signature (string)."
)
_PURPLE_SYSTEM = (
    "You are the Purple Agent of a security swarm — a senior risk "
    "officer translating technical findings into business consequences "
    "for the C-suite. Given a vulnerability, the Red team's PoC, the "
    "Blue team's detection plan, and a deterministic loss estimate, "
    "write a one-paragraph business narrative (3–5 sentences, no "
    "jargon), list 3–7 affected stakeholders (e.g. customers, "
    "merchants, regulators), and a one-line blast-radius summary "
    "(scope of compromise). Return valid JSON with keys: "
    "business_narrative (string), affected_stakeholders (array of "
    "strings), estimated_blast_radius (string)."
)


def _red_user_prompt(finding: Finding, sanitized_evidence: dict[str, Any]) -> str:
    return json.dumps({
        "agent_id":    finding.agent_id,
        "vuln_class":  sanitize_text(finding.vuln_class),
        "severity":    finding.severity.value,
        "evidence":    sanitized_evidence,
        "recommendation": sanitize_text(finding.recommendation),
    }, sort_keys=True)


def _blue_user_prompt(finding: Finding, sanitized_evidence: dict[str, Any],
                       red_pseudocode: str) -> str:
    return json.dumps({
        "vuln_class": sanitize_text(finding.vuln_class),
        "evidence":   sanitized_evidence,
        "red_poc":    red_pseudocode[:2000],
    }, sort_keys=True)


def _purple_user_prompt(
    finding: Finding, sanitized_evidence: dict[str, Any],
    red_pseudocode: str, blue_summary: str,
) -> str:
    deterministic_estimate = (
        f"${finding.financial_impact_score:,.0f}"
        if finding.financial_impact_score else "unknown"
    )
    return json.dumps({
        "vuln_class": sanitize_text(finding.vuln_class),
        "severity": finding.severity.value,
        "deterministic_loss_estimate_usd": deterministic_estimate,
        "evidence": sanitized_evidence,
        "red_poc_summary": red_pseudocode[:1000],
        "blue_detection_summary": blue_summary[:1000],
    }, sort_keys=True)


# ============================================================
# Orchestrator
# ============================================================

# Callable shape any test fixture or production code can satisfy:
#   async fn(messages, **kwargs) -> {"content": str, ...}
LLMQueryFn = Callable[..., Awaitable[dict[str, Any]]]


@dataclass
class SwarmOrchestrator:
    """Runs Red+Blue (+ optional Purple) chain per applicable finding."""

    llm_query: LLMQueryFn
    severity_floor: set[Severity] = field(default_factory=lambda: set(_DEFAULT_FLOOR))
    # Purple agent is off by default — it's a 3rd LLM call per finding
    # and IMPACT_001 already gives you a deterministic dollar figure.
    # Enable explicitly when you want a narrative for an executive
    # readout.
    purple_enabled: bool = False
    _cache: dict[str, SwarmResult] = field(default_factory=dict)
    _max_tokens: int = 1024
    _temperature: float = 0.2

    # ---------- public API ----------

    async def run_one(self, finding: Finding) -> SwarmResult:
        """Run the chain on a single finding, with cache + severity gate."""
        if finding.severity not in self.severity_floor:
            return SwarmResult(
                finding_id=finding.finding_id, cache_key="",
                red=None, blue=None,
                error=f"severity {finding.severity.value} below floor",
            )

        sanitized = sanitize_evidence(finding.evidence or {})
        cache_key = self._cache_key(finding, sanitized)

        cached = self._cache.get(cache_key)
        if cached is not None:
            return SwarmResult(
                finding_id=finding.finding_id,
                cache_key=cache_key,
                red=cached.red,
                blue=cached.blue,
                cached=True,
            )

        try:
            red = await self._run_red(finding, sanitized)
        except Exception as e:  # noqa: BLE001
            logger.exception("Red agent failed")
            result = SwarmResult(
                finding_id=finding.finding_id,
                cache_key=cache_key,
                red=None, blue=None,
                error=f"red: {str(e)[:200]}",
            )
            return result

        try:
            blue = await self._run_blue(finding, sanitized, red)
        except Exception as e:  # noqa: BLE001
            logger.exception("Blue agent failed")
            result = SwarmResult(
                finding_id=finding.finding_id,
                cache_key=cache_key,
                red=red, blue=None,
                error=f"blue: {str(e)[:200]}",
            )
            self._cache[cache_key] = result
            return result

        purple: PurpleAgentOutput | None = None
        if self.purple_enabled:
            try:
                purple = await self._run_purple(finding, sanitized, red, blue)
            except Exception as e:  # noqa: BLE001
                logger.exception("Purple agent failed (continuing without)")

        result = SwarmResult(
            finding_id=finding.finding_id,
            cache_key=cache_key,
            red=red, blue=blue, purple=purple,
        )
        self._cache[cache_key] = result
        return result

    async def run_many(
        self,
        findings: list[Finding],
        max_concurrency: int = 4,
    ) -> list[SwarmResult]:
        """Run the chain on a list of findings in bounded parallel."""
        sem = asyncio.Semaphore(max_concurrency)

        async def gated(f: Finding) -> SwarmResult:
            async with sem:
                return await self.run_one(f)

        return await asyncio.gather(*(gated(f) for f in findings))

    def attach(self, finding: Finding, result: SwarmResult) -> Finding:
        """Return a copy of `finding` with the swarm result in evidence."""
        new_ev = dict(finding.evidence or {})
        new_ev["_swarm"] = result.to_evidence_block()
        return finding.model_copy(update={"evidence": new_ev})

    # ---------- internals ----------

    async def _run_red(
        self, finding: Finding, sanitized_evidence: dict[str, Any],
    ) -> RedAgentOutput:
        raw = await self.llm_query(
            messages=[
                {"role": "system", "content": _RED_SYSTEM},
                {"role": "user",   "content": _red_user_prompt(finding, sanitized_evidence)},
            ],
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            json_mode=True,
        )
        content = raw.get("content", "")
        parsed = _safe_json(content)
        return RedAgentOutput(
            poc_pseudocode=str(parsed.get("poc_pseudocode", ""))[:4000],
            exploitation_steps=[str(s) for s in (parsed.get("exploitation_steps") or [])[:10]],
            impact_narrative=str(parsed.get("impact_narrative", ""))[:2000],
            raw_response=content[:8000],
        )

    async def _run_blue(
        self, finding: Finding, sanitized_evidence: dict[str, Any],
        red: RedAgentOutput,
    ) -> BlueAgentOutput:
        raw = await self.llm_query(
            messages=[
                {"role": "system", "content": _BLUE_SYSTEM},
                {"role": "user",   "content": _blue_user_prompt(
                    finding, sanitized_evidence, red.poc_pseudocode,
                )},
            ],
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            json_mode=True,
        )
        content = raw.get("content", "")
        parsed = _safe_json(content)
        return BlueAgentOutput(
            semgrep_rule=str(parsed.get("semgrep_rule", ""))[:4000],
            waf_rule=str(parsed.get("waf_rule", ""))[:2000],
            log_signature=str(parsed.get("log_signature", ""))[:1000],
            raw_response=content[:8000],
        )

    async def _run_purple(
        self, finding: Finding, sanitized_evidence: dict[str, Any],
        red: RedAgentOutput, blue: BlueAgentOutput,
    ) -> PurpleAgentOutput:
        raw = await self.llm_query(
            messages=[
                {"role": "system", "content": _PURPLE_SYSTEM},
                {"role": "user",   "content": _purple_user_prompt(
                    finding, sanitized_evidence,
                    red.poc_pseudocode, blue.semgrep_rule + " " + blue.waf_rule,
                )},
            ],
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            json_mode=True,
        )
        content = raw.get("content", "")
        parsed = _safe_json(content)
        return PurpleAgentOutput(
            business_narrative=str(parsed.get("business_narrative", ""))[:4000],
            affected_stakeholders=[
                str(s) for s in (parsed.get("affected_stakeholders") or [])[:10]
            ],
            estimated_blast_radius=str(parsed.get("estimated_blast_radius", ""))[:1000],
            raw_response=content[:8000],
        )

    @staticmethod
    def _cache_key(finding: Finding, sanitized_evidence: dict[str, Any]) -> str:
        # Snippet is the most discriminating signal; rest is stable.
        snippet = ""
        for key in ("snippet", "context", "value"):
            v = sanitized_evidence.get(key)
            if isinstance(v, str) and v:
                snippet = v
                break
        body = "|".join([finding.agent_id, finding.vuln_class, snippet])
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def _safe_json(text: str) -> dict[str, Any]:
    """Parse JSON loosely — accepts JSON inside a fenced block too."""
    text = text.strip()
    # Strip fences
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(line for line in lines if not line.strip().startswith("```"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last-ditch: find the first { ... } block
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return {}


__all__ = [
    "BlueAgentOutput",
    "RedAgentOutput",
    "SwarmOrchestrator",
    "SwarmResult",
]
