"""D_053 — CPU / battery side-channel for hidden native crypto."""
from __future__ import annotations
import logging
from pathlib import Path
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class SideChannelAgent(BaseAgent):
    AGENT_ID = "D_053"
    VULN_CLASS = "Hidden Native Crypto via Side-Channel (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.app_profile.get("native_libs_info", {}).get("count", 0))

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        native_info = ctx.app_profile.get("native_libs_info") or {}
        libs = native_info.get("libs") or []
        if not libs:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.55,
            recommendation=(
                f"App ships {native_info.get('count', 0)} native .so libraries. "
                "The Frida hook will sample /proc/stat (CPU time per second) "
                "and BatteryManager.BATTERY_PROPERTY_CURRENT_NOW during an "
                "interaction window. Sustained CPU spikes correlated with "
                "no visible Java crypto API call indicate hidden native "
                "crypto — a common shape for obfuscated DRM or runtime "
                "key derivation. Audit any spiking library."
            ),
            evidence={
                "native_lib_count": native_info.get("count", 0),
                "libs": libs[:20],
                "dynamic_target": True,
                "frida_payload": {
                    "monitor_endpoints": ["/proc/stat", "/proc/self/status"],
                    "battery_property": "BATTERY_PROPERTY_CURRENT_NOW",
                    "sample_interval_ms": 200,
                    "window_seconds": 30,
                    "spike_threshold_pct": 70,
                    "safety_budget": {
                        "max_actions_total": 1,
                        "max_actions_per_sec": 0.1,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 1,
                    },
                },
            },
        )]


__all__ = ["SideChannelAgent"]
