"""D_066 — Accessibility-service click hijack (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_A11Y_SVC_RE = re.compile(r"extends\s+AccessibilityService")
_DISPATCH_GESTURE_RE = re.compile(r"\.dispatchGesture\s*\(")
_PERFORM_CLICK_RE = re.compile(
    r"performAction\s*\(\s*AccessibilityNodeInfo\.ACTION_CLICK"
)


class A11yAbuserAgent(BaseAgent):
    AGENT_ID = "D_066"
    VULN_CLASS = "Accessibility Service Click Hijack (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        services: set[str] = set()
        gesture_users: set[str] = set()
        click_dispatchers: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _A11Y_SVC_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            services.add(rel)
            if _DISPATCH_GESTURE_RE.search(text):
                gesture_users.add(rel)
            if _PERFORM_CLICK_RE.search(text):
                click_dispatchers.add(rel)
        if not services:
            return []
        severity = (
            Severity.HIGH if (gesture_users or click_dispatchers)
            else Severity.MEDIUM
        )
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.70,
            recommendation=(
                f"{len(services)} AccessibilityService subclass(es) — "
                f"{len(gesture_users)} dispatch synthetic gestures, "
                f"{len(click_dispatchers)} perform ACTION_CLICK. The "
                "Frida hook will inject a synthetic AccessibilityNodeInfo "
                "click against hidden buttons (visibility=GONE, "
                "alpha=0.0). Restrict your AccessibilityService to "
                "specific package(s) via android:packageNames and reject "
                "any node whose visible bounds are 0."
            ),
            evidence={
                "a11y_services": sorted(services)[:10],
                "gesture_users": sorted(gesture_users)[:5],
                "click_dispatchers": sorted(click_dispatchers)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_targets": [
                        "android.view.accessibility.AccessibilityNodeInfo.performAction",
                        "android.accessibilityservice.AccessibilityService.dispatchGesture",
                    ],
                    "synthetic_node_filters": ["visibility=GONE", "alpha=0", "bounds=0x0"],
                    "safety_budget": {
                        "max_actions_total": 15,
                        "max_actions_per_sec": 2,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["A11yAbuserAgent"]
