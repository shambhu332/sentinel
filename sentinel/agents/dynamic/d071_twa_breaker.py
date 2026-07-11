"""D_071 — Trusted Web Activity session hijack (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_TWA_RE = re.compile(
    r"\bTrustedWebActivityIntentBuilder\b|\bandroid\.support\.customtabs\b"
    r"|\bandroidx\.browser\.customtabs\b|\bCustomTabsIntent\b"
)
_DIGITAL_ASSET_RE = re.compile(
    r'assetlinks\.json|asset_statements'
)


class TwaBreakerAgent(BaseAgent):
    AGENT_ID = "D_071"
    VULN_CLASS = "TWA Session Hijack (Dynamic Testing Target)"
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
        twa_files: set[str] = set()
        asset_link_files: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _TWA_RE.search(text):
                twa_files.add(str(path.relative_to(root)))
            if _DIGITAL_ASSET_RE.search(text):
                asset_link_files.add(str(path.relative_to(root)))
        # Asset-links string in resources?
        has_assetlinks_res = False
        if self._context.resources_dir:
            for cand in (
                self._context.resources_dir / "res" / "values" / "strings.xml",
                self._context.resources_dir / "assets" / "assetlinks.json",
            ):
                if cand.is_file():
                    try:
                        if "asset_statements" in cand.read_text(
                            encoding="utf-8", errors="replace",
                        ):
                            has_assetlinks_res = True
                            break
                    except OSError:
                        continue
        if not twa_files:
            return []
        weak_posture = not (asset_link_files or has_assetlinks_res)
        severity = Severity.HIGH if weak_posture else Severity.LOW
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"{len(twa_files)} Trusted Web Activity / Custom Tabs site(s). "
                f"asset_statements declared: "
                f"{bool(asset_link_files or has_assetlinks_res)}. "
                "Without asset_statements (Digital Asset Links) the TWA "
                "isn't actually verifying the origin, and any installable "
                "app can hijack the same intent. The Frida hook will "
                "drop in a malicious CustomTabsIntent for the TWA's "
                "declared URL and observe whether session cookies leak."
            ),
            evidence={
                "twa_files": sorted(twa_files)[:10],
                "asset_link_refs": sorted(asset_link_files)[:5],
                "assetlinks_in_resources": has_assetlinks_res,
                "dynamic_target": True,
                "frida_payload": {
                    "hook_target": "androidx.browser.customtabs.CustomTabsIntent.launchUrl",
                    "session_capture": True,
                    "safety_budget": {
                        "max_actions_total": 5,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["TwaBreakerAgent"]
