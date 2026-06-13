"""D_047 — Heap memory-dump target (Dynamic Testing Target).

Identifies activities/services whose names match login/payment/auth
patterns and emits a Frida payload directing the DAST hook to take
a heap snapshot just after the target activity onResume fires, then
scan the snapshot for JWT / AWS-key / PAN shapes.
"""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_HOT_NAME_RE = re.compile(
    r"(login|signin|auth|payment|checkout|biometric|"
    r"otp|2fa|kyc|wallet|vault|transfer)",
    re.IGNORECASE,
)
_KEY_SCAN_PATTERNS = [
    r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",  # JWT
    r"AKIA[0-9A-Z]{16}",                                          # AWS key
    r"\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13})\b",                # PAN
    r"sk_live_[A-Za-z0-9]{24,}",                                 # Stripe
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]


class MemoryDumpTargetAgent(BaseAgent):
    AGENT_ID = "D_047"
    VULN_CLASS = "Heap Snapshot Target (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.manifest)

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        targets: list[str] = []
        for act in manifest.get("activities", []) or []:
            if not isinstance(act, dict):
                continue
            name = act.get("name", "")
            if _HOT_NAME_RE.search(name):
                targets.append(name)
        if not targets:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.75,
            recommendation=(
                f"{len(targets)} login/payment/auth activity(ies) flagged "
                "as heap-snapshot targets. The Frida hook will dump the "
                "process heap right after each target onResume and scan "
                "for JWT / AWS-key / PAN / Stripe / PEM shapes. Findings "
                "indicate secrets that survive past their useful lifetime "
                "in memory — zero buffers explicitly after use."
            ),
            evidence={
                "target_activities": targets,
                "dynamic_target": True,
                "frida_payload": {
                    "targets": targets,
                    "scan_after_event": "onResume",
                    "key_patterns": _KEY_SCAN_PATTERNS,
                    "safety_budget": {
                        "max_actions_total": 5,
                        "max_actions_per_sec": 0.2,
                        "wall_clock_budget_s": 120,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["MemoryDumpTargetAgent"]
