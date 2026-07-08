"""HON_001 — Honeypot Calibration Agent.

Tracks LLM-vs-rule disagreement events emitted by AIAutonomousAgent instances
and computes per-rule calibration metrics. Emits an Info finding when a rule's
LLM disagreement rate drifts above the configured threshold, signalling that
the rule's confidence score needs tuning.

Event flow:
  AIAutonomousAgent._handle_verdict()
      → memory.publish_event("calibration.disagreement", {...})
  HON001CalibrationAgent.analyze()
      → poll_events("calibration.disagreement")
      → compute per-rule precision estimate
      → emit Finding if drift > DRIFT_THRESHOLD
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)

DRIFT_THRESHOLD = 0.30  # emit warning when >30 % of a rule's hits are LLM-rejected
MIN_EVENTS = 5           # ignore rules with fewer events (too noisy)


class HON001CalibrationAgent(BaseAgent):
    """HON_001: reads calibration events, detects rule drift, suggests recalibration."""

    AGENT_ID = "HON_001"
    VULN_CLASS = "Calibration Drift"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, memory, config)

    async def is_applicable(self) -> bool:
        events = await self._memory.poll_events(
            session_id=self._context.session_id,
            event_type="calibration.disagreement",
        )
        return bool(events)

    async def analyze(self) -> list[Finding]:
        events = await self._memory.poll_events(
            session_id=self._context.session_id,
            event_type="calibration.disagreement",
        )
        if not events:
            return []

        metrics = self._compute_metrics(events)
        findings: list[Finding] = []

        for rule, stats in metrics.items():
            total = stats["total"]
            rejected = stats["llm_rejected"]
            if total < MIN_EVENTS:
                continue

            rejection_rate = rejected / total
            if rejection_rate < DRIFT_THRESHOLD:
                continue

            self._log.info(
                "HON_001: rule %s rejection_rate=%.1f%% (%d/%d) — drift detected",
                rule, rejection_rate * 100, rejected, total,
            )
            findings.append(self._make_drift_finding(rule, stats, rejection_rate))

        return findings

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_metrics(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"total": 0, "llm_rejected": 0, "avg_rule_confidence": 0.0,
                     "avg_llm_confidence": 0.0, "sample_files": []}
        )
        for ev in events:
            payload = ev.get("payload", {})
            rule = str(payload.get("rule_triggered", "unknown"))
            s = stats[rule]
            s["total"] += 1
            if payload.get("llm_verdict") in ("false_positive", "uncertain"):
                s["llm_rejected"] += 1
            s["avg_rule_confidence"] += float(payload.get("rule_confidence", 0.0))
            s["avg_llm_confidence"] += float(payload.get("llm_confidence", 0.0))
            fp = str(payload.get("file_path", ""))
            if fp and fp not in s["sample_files"]:
                s["sample_files"].append(fp)

        for rule, s in stats.items():
            n = s["total"] or 1
            s["avg_rule_confidence"] = round(s["avg_rule_confidence"] / n, 3)
            s["avg_llm_confidence"] = round(s["avg_llm_confidence"] / n, 3)
            s["sample_files"] = s["sample_files"][:5]

        return dict(stats)

    def _make_drift_finding(
        self,
        rule: str,
        stats: dict[str, Any],
        rejection_rate: float,
    ) -> Finding:
        ctx = self._context
        total = stats["total"]
        rejected = stats["llm_rejected"]
        avg_rc = stats["avg_rule_confidence"]

        recommendation = (
            f"Rule '{rule}' fires {total} times per scan but the LLM rejects "
            f"{rejected} ({rejection_rate*100:.0f}%) as false positives.\n"
            f"Suggested actions:\n"
            f"1. Increase entropy threshold or tighten the regex to reduce noise.\n"
            f"2. Review the {len(stats['sample_files'])} sample files flagged below.\n"
            f"3. If the rule is fundamentally noisy, reduce its confidence score "
            f"from {avg_rc:.2f} to ≤{max(0.5, avg_rc - 0.2):.2f}."
        )

        return Finding(
            agent_id=self.AGENT_ID,
            session_id=ctx.session_id,
            vuln_class=f"Calibration Drift — rule {rule} ({rejection_rate*100:.0f}% FP rate)",
            severity=Severity.INFO,
            confidence=round(rejection_rate, 3),
            recommendation=recommendation,
            evidence={
                "rule": rule,
                "total_hits": total,
                "llm_rejected": rejected,
                "rejection_rate": round(rejection_rate, 3),
                "avg_rule_confidence": avg_rc,
                "avg_llm_confidence": stats["avg_llm_confidence"],
                "sample_files": stats["sample_files"],
                "drift_threshold": DRIFT_THRESHOLD,
            },
            severity_rationale=(
                f"Rule {rule} has a {rejection_rate*100:.0f}% LLM rejection rate "
                f"across {total} candidates in this session. "
                f"This suggests the rule confidence ({avg_rc:.2f}) is overestimated."
            ),
            compliance_tags=[],
            finding_category="Static_Tool",
        )


# ------------------------------------------------------------------ #
# Standalone metrics helper — importable without running as an agent  #
# ------------------------------------------------------------------ #

def compute_session_calibration(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute calibration summary from raw event dicts. Pure function, no I/O."""
    if not events:
        return {"rules": {}, "overall_rejection_rate": 0.0, "total_events": 0}

    by_rule: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        payload = ev.get("payload", {})
        rule = str(payload.get("rule_triggered", "unknown"))
        by_rule[rule].append(payload)

    rules: dict[str, Any] = {}
    total_rejected = 0
    total_all = 0

    for rule, payloads in by_rule.items():
        n = len(payloads)
        rejected = sum(
            1 for p in payloads
            if p.get("llm_verdict") in ("false_positive", "uncertain")
        )
        total_rejected += rejected
        total_all += n
        rules[rule] = {
            "total": n,
            "rejected": rejected,
            "rejection_rate": round(rejected / n, 3) if n else 0.0,
            "drifting": (n >= MIN_EVENTS and rejected / n >= DRIFT_THRESHOLD),
        }

    return {
        "rules": rules,
        "overall_rejection_rate": round(total_rejected / total_all, 3) if total_all else 0.0,
        "total_events": total_all,
    }
