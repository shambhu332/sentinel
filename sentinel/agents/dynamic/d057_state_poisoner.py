"""D_057 — Deep-link state poisoner (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_STATE_FLAG_RE = re.compile(
    r'getBooleanExtra\s*\(\s*"(\w*(?:isPremium|isAdmin|isVip|isPaid|'
    r'unlocked|debug|verified|trusted|elevated)\w*)"',
    re.IGNORECASE,
)


class StatePoisonerAgent(BaseAgent):
    AGENT_ID = "D_057"
    VULN_CLASS = "Deep-Link State Poisoning (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
            and self._context.manifest
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        manifest = self._context.manifest or {}
        deep_link_activities: list[dict[str, Any]] = []
        for act in manifest.get("activities", []) or []:
            if not isinstance(act, dict):
                continue
            for f in (act.get("intent_filters") or []):
                if not isinstance(f, dict):
                    continue
                actions = f.get("actions") or []
                if "android.intent.action.VIEW" in actions:
                    deep_link_activities.append(act)
                    break
        if not deep_link_activities:
            return []
        assert root is not None
        scanned = 0
        boolean_flags: set[str] = set()
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _STATE_FLAG_RE.finditer(text):
                boolean_flags.add(m.group(1))
        if not boolean_flags:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.70,
            recommendation=(
                f"{len(boolean_flags)} privileged-state boolean extras read "
                f"by deep-link handlers — {sorted(boolean_flags)[:5]}. "
                "The Frida hook will rapid-fire each deep link with "
                "extras={flag: true} and snapshot the app's state "
                "afterwards (via SharedPreferences read). Never trust "
                "Intent extras for state; server-issued tokens only."
            ),
            evidence={
                "deep_link_activity_count": len(deep_link_activities),
                "privileged_boolean_flags": sorted(boolean_flags),
                "dynamic_target": True,
                "frida_payload": {
                    "deep_link_activities": [
                        a.get("name", "") for a in deep_link_activities
                    ],
                    "poison_flags": sorted(boolean_flags),
                    "post_action_check": "SharedPreferences.getBoolean",
                    "safety_budget": {
                        "max_actions_total": 30,
                        "max_actions_per_sec": 3,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["StatePoisonerAgent"]
