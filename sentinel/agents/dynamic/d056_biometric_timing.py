"""D_056 — Biometric onAuth timing side-channel (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_AUTH_CB_RE = re.compile(
    r"onAuthenticationSucceeded\s*\(|onAuthenticationFailed\s*\("
)
_STR_EQ_RE = re.compile(
    r"(token|password|pin|pwd|hash|secret|otp|biometric|stored)"
    r"\s*\.\s*equals\s*\("
    r"|\.equals\s*\(\s*\w*(token|password|pin|pwd|hash|secret|otp)"
    r"|\.equalsIgnoreCase\s*\(",
    re.IGNORECASE,
)


class BiometricTimingAgent(BaseAgent):
    AGENT_ID = "D_056"
    VULN_CLASS = "Biometric Timing Side-Channel (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        targets: list[str] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _AUTH_CB_RE.search(text):
                continue
            if not _STR_EQ_RE.search(text):
                continue
            targets.append(str(path.relative_to(root)))
        if not targets:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.MEDIUM,
            confidence=0.55,
            recommendation=(
                f"{len(targets)} biometric callback class(es) reference "
                "String.equals on credential-shaped values. The Frida "
                "hook will measure the wall-clock delta between "
                "onAuthenticationFailed and onAuthenticationSucceeded; "
                "a consistent >2ms differential is the timing-attack "
                "signal. Switch to MessageDigest.isEqual or "
                "Arrays.constantTimeAreEqual for any cryptographic "
                "comparison."
            ),
            evidence={
                "candidate_files": targets[:10],
                "dynamic_target": True,
                "frida_payload": {
                    "method_hooks": [
                        "onAuthenticationSucceeded",
                        "onAuthenticationFailed",
                    ],
                    "samples": 50,
                    "differential_threshold_ms": 2,
                    "safety_budget": {
                        "max_actions_total": 50,
                        "max_actions_per_sec": 2,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["BiometricTimingAgent"]
