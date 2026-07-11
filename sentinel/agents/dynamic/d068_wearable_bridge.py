"""D_068 — WearOS DataLayer PII leak (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_WEAR_API_RE = re.compile(
    r"\bWearableListenerService\b|\bDataClient\b|\bMessageClient\b"
    r"|\bonDataChanged\b|\bonMessageReceived\b"
    r"|\bcom\.google\.android\.gms\.wearable\b"
)
_PII_HINTS_RE = re.compile(
    r"\b(email|phone|address|ssn|otp|token|access_token|"
    r"password|biometric)\b",
    re.IGNORECASE,
)


class WearableBridgeAgent(BaseAgent):
    AGENT_ID = "D_068"
    VULN_CLASS = "WearOS DataLayer Bridge Leak (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        if root is None:
            return []
        bridge_files: set[str] = set()
        pii_routes: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _WEAR_API_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            bridge_files.add(rel)
            if _PII_HINTS_RE.search(text):
                pii_routes.add(rel)
        if not bridge_files:
            return []
        severity = Severity.HIGH if pii_routes else Severity.LOW
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.60,
            recommendation=(
                f"{len(bridge_files)} WearOS bridge handler(s); "
                f"{len(pii_routes)} reference PII tokens (email/phone/"
                "address/SSN/OTP/token/password/biometric) in the same "
                "class. The Frida hook will subscribe to "
                "MessageClient.onMessageReceived from a controlled "
                "Wear-pair context and dump payloads. Never put PII or "
                "tokens on the WearOS bridge — use a separate authenticated "
                "channel from the watch to your backend."
            ),
            evidence={
                "bridge_files": sorted(bridge_files)[:10],
                "pii_routes": sorted(pii_routes)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_targets": [
                        "com.google.android.gms.wearable.MessageClient.onMessageReceived",
                        "com.google.android.gms.wearable.DataClient.onDataChanged",
                    ],
                    "dump_payload_bytes": True,
                    "safety_budget": {
                        "max_actions_total": 1,
                        "max_actions_per_sec": 0.2,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 1,
                    },
                },
            },
        )]


__all__ = ["WearableBridgeAgent"]
