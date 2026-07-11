"""D_049 — Notification / OTP snoop (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_NOTIFY_BUILDER_RE = re.compile(
    r"NotificationCompat\.Builder|new\s+Notification\.Builder"
)
_OTP_TEXT_RE = re.compile(
    r"\.setContentText\s*\([^)]*?(otp|verification|code|pin|2fa)",
    re.IGNORECASE,
)
_NO_PRIVACY_RE = re.compile(
    r"\.setVisibility\s*\(\s*Notification\.VISIBILITY_PRIVATE"
    r"|\.setVisibility\s*\(\s*NotificationCompat\.VISIBILITY_PRIVATE"
)


class NotificationSnoopAgent(BaseAgent):
    AGENT_ID = "D_049"
    VULN_CLASS = "Notification OTP Leak (Dynamic Testing Target)"
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
            if not _NOTIFY_BUILDER_RE.search(text):
                continue
            if not _OTP_TEXT_RE.search(text):
                continue
            has_privacy = bool(_NO_PRIVACY_RE.search(text))
            if has_privacy:
                continue  # already restricted lockscreen visibility
            rel = str(path.relative_to(root))
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.70,
                recommendation=(
                    "Notification with OTP/verification text content but no "
                    "VISIBILITY_PRIVATE / VISIBILITY_SECRET setting. The "
                    "Frida hook will trigger the notification flow and "
                    "verify whether the OTP appears on the lockscreen "
                    "via NotificationListenerService capture. Set "
                    "setVisibility(VISIBILITY_PRIVATE) and a redacted "
                    "publicVersion at minimum."
                ),
                evidence={
                    "file": rel,
                    "has_visibility_setting": has_privacy,
                    "dynamic_target": True,
                    "frida_payload": {
                        "target_file": rel,
                        "monitor_event": "NotificationListenerService.onNotificationPosted",
                        "redaction_check_required": True,
                        "safety_budget": {
                            "max_actions_total": 5,
                            "max_actions_per_sec": 1,
                            "wall_clock_budget_s": 20,
                            "max_consecutive_crashes": 2,
                        },
                    },
                },
            ))
        return findings


__all__ = ["NotificationSnoopAgent"]
