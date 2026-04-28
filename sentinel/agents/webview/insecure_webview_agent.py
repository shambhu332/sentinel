"""C_004 — Insecure WebView Agent.

Detects Android WebView configurations that expose Java methods to JavaScript
running in the WebView, especially when combined with JavaScript-enabled
loading of remote content.

Why this matters: addJavascriptInterface bridges Java and JavaScript. If a
WebView loads remote content (or content that can be intercepted via
cleartext traffic / vulnerable to XSS), an attacker can call into the Java
side from JavaScript and potentially achieve remote code execution. Pre-API
17 this was unconditionally exploitable; post-API 17 only @JavascriptInterface
methods are exposed but the attack surface remains. Bug bounty programs pay
$500-$3000 for confirmed JS interface exploitation, with $5000+ if RCE is
demonstrated.

Detection pipeline:
1. Walk decompiled .java files
2. Find addJavascriptInterface calls and adjacent setJavaScriptEnabled
3. Look for setAllowFileAccess(true), setAllowUniversalAccessFromFileURLs(true)
4. Severity scales: addJavascriptInterface + JS enabled = High;
   plus universal access = Critical
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_ADD_JS_INTERFACE_RE = re.compile(
    r"\.addJavascriptInterface\s*\(",
    re.IGNORECASE,
)

_JS_ENABLED_RE = re.compile(
    r"\.setJavaScriptEnabled\s*\(\s*true\s*\)",
    re.IGNORECASE,
)

_FILE_ACCESS_RE = re.compile(
    r"\.setAllow(?:FileAccess|UniversalAccessFromFileURLs|FileAccessFromFileURLs)\s*\(\s*true\s*\)",
    re.IGNORECASE,
)

_LOAD_URL_HTTP_RE = re.compile(
    r"\.loadUrl\s*\(\s*\"http://",
    re.IGNORECASE,
)

_MAX_FILES_TO_SCAN = 3000


class InsecureWebViewAgent(BaseAgent):
    """C_004: detects insecure WebView configurations."""

    AGENT_ID = "C_004"
    VULN_CLASS = "Insecure WebView"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[C_004] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context

        # Per-file analysis: count signals
        per_file: dict[str, dict[str, int]] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[C_004] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            counts = {
                "add_js_interface": len(_ADD_JS_INTERFACE_RE.findall(text)),
                "js_enabled": len(_JS_ENABLED_RE.findall(text)),
                "file_access": len(_FILE_ACCESS_RE.findall(text)),
                "load_http": len(_LOAD_URL_HTTP_RE.findall(text)),
            }

            if any(counts.values()):
                rel = str(path.relative_to(ctx.decompiled_dir))
                per_file[rel] = counts

        if not per_file:
            logger.info("[C_004] No insecure WebView configurations detected")
            return []

        # Aggregate signals across all files
        total = {k: sum(f[k] for f in per_file.values())
                 for k in ("add_js_interface", "js_enabled", "file_access", "load_http")}

        # Severity logic
        if total["add_js_interface"] > 0 and total["js_enabled"] > 0 and total["file_access"] > 0:
            severity = Severity.CRITICAL
            confidence = 0.90
            summary = (
                "addJavascriptInterface + JS enabled + file access enabled — "
                "potential RCE chain if WebView loads attacker-controlled content"
            )
        elif total["add_js_interface"] > 0 and total["js_enabled"] > 0:
            severity = Severity.HIGH
            confidence = 0.85
            summary = (
                "addJavascriptInterface + JS enabled — Java methods exposed to "
                "JavaScript; exploitable if WebView ever loads untrusted content"
            )
        elif total["add_js_interface"] > 0:
            severity = Severity.MEDIUM
            confidence = 0.70
            summary = "addJavascriptInterface present but JS-enabled flag not detected"
        elif total["file_access"] > 0:
            severity = Severity.MEDIUM
            confidence = 0.70
            summary = (
                "WebView allows file:// URLs or universal access from file URLs "
                "— enables file-protocol-based exfiltration attacks"
            )
        else:
            severity = Severity.LOW
            confidence = 0.60
            summary = "WebView loads HTTP URLs — vulnerable to MitM injection"

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(total),
            evidence={
                "title": "Insecure WebView Configuration",
                "summary": summary,
                "package": (ctx.manifest or {}).get("package", "?"),
                "totals": total,
                "per_file": per_file,
                "files_with_signals": list(per_file.keys())[:20],
                "vector": (
                    "If the WebView loads any attacker-controllable content "
                    "(via XSS, MitM on HTTP, malicious deep link, or compromised "
                    "ad SDK), the attacker can invoke Java methods from "
                    "JavaScript and pivot from web context to native app context."
                ),
            },
        )]

    @staticmethod
    def _build_recommendation(totals: dict[str, int]) -> str:
        steps: list[str] = []

        if totals["add_js_interface"] > 0:
            steps.append(
                "Audit every addJavascriptInterface call. Remove the bridge if "
                "it isn't strictly necessary. If it is necessary, ensure the "
                "@JavascriptInterface annotation is on every exposed method "
                "(required since API 17). Consider replacing the JS bridge with "
                "WebView.evaluateJavascript() callbacks or postMessage() for "
                "safer cross-context communication."
            )

        if totals["file_access"] > 0:
            steps.append(
                "Remove setAllowFileAccess(true), "
                "setAllowUniversalAccessFromFileURLs(true), and "
                "setAllowFileAccessFromFileURLs(true). These have been "
                "deprecated since Android API 16 and are disabled by default in "
                "modern WebView implementations for good reason."
            )

        if totals["load_http"] > 0:
            steps.append(
                "Replace loadUrl(\"http://...\") with HTTPS. WebView traffic "
                "loaded over HTTP is interceptable and modifiable by any "
                "attacker on the user's network."
            )

        steps.append(
            "Use Network Security Configuration to restrict the WebView's "
            "domain whitelist to specific HTTPS origins only."
        )

        return " ".join(steps)
