"""D_044 — Biometric callback replay (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_CALLBACK_RE = re.compile(
    r"new\s+BiometricPrompt\.AuthenticationCallback\b"
    r"|extends\s+BiometricPrompt\.AuthenticationCallback"
    r"|onAuthenticationSucceeded\s*\(.*?BiometricPrompt\.AuthenticationResult"
)
_TRUST_SHAPE_RE = re.compile(
    r"on(?:Auth|Authentication)Succeeded\s*\([^)]*\)\s*\{"
    r"[^}]*?(?:grantAccess|enableFeature|setUnlocked|unlock|startActivity)"
)


class BiometricReplayAgent(BaseAgent):
    AGENT_ID = "D_044"
    VULN_CLASS = "Biometric Callback Replay (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _CALLBACK_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]
            trust_path = bool(_TRUST_SHAPE_RE.search(text))
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH if trust_path else Severity.MEDIUM,
                confidence=0.70 if trust_path else 0.55,
                recommendation=(
                    f"`{class_name}` declares a BiometricPrompt callback. "
                    "The Frida hook will force-fire onAuthenticationSucceeded "
                    "without an actual biometric match and observe whether "
                    "the trust path runs. Move the privileged action behind "
                    "a server-issued token tied to the biometric attestation."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "client_trust_shape": trust_path,
                    "dynamic_target": True,
                    "frida_payload": {
                        "class_simple_name": class_name,
                        "method": "onAuthenticationSucceeded",
                        "force_callback": True,
                        "safety_budget": {
                            "max_actions_total": 5,
                            "max_actions_per_sec": 1,
                            "wall_clock_budget_s": 15,
                            "max_consecutive_crashes": 2,
                        },
                    },
                },
            ))
        return findings


__all__ = ["BiometricReplayAgent"]
