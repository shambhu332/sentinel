"""D_084 — WebView Universal XSS (file-origin bypass).

Companion to D_048 (generic WebView XSS injection target). D_048
flags any WebView with JS enabled + a load call; D_084 narrows to
the *universal XSS* shape — a JS-enabled WebView where the file
origin is explicitly elevated:

    settings.setJavaScriptEnabled(true);
    settings.setAllowFileAccess(true);                     // pre-Pie default OK,
    settings.setAllowFileAccessFromFileURLs(true);         //   <-- attacker-set
    settings.setAllowUniversalAccessFromFileURLs(true);    //   <-- code execution

With the universal-access flag enabled, JavaScript loaded from a
`file://` URI can `XMLHttpRequest` any origin (including
`file:///data/data/...`), reading the app's databases and shared
prefs. The Frida hook fires `loadDataWithBaseURL(file:///, '<script
src="file:///data/data/com.app/databases/secret.db">')` and watches
WebChromeClient.onConsoleMessage to confirm the script executed.

Safety: payload is `console.log('SENTINEL_XSS_PROBE_<token>')` —
non-destructive, single-line, easy to grep in logcat.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_JS_ENABLED_RE = re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)")
_ALLOW_FILE_RE = re.compile(r"\.setAllowFileAccess\s*\(\s*true\s*\)")
_ALLOW_FILE_FROM_FILES_RE = re.compile(
    r"\.setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)"
)
_ALLOW_UNIVERSAL_RE = re.compile(
    r"\.setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"
)
_LOAD_FILE_RE = re.compile(
    r"\.loadUrl\s*\(\s*[\"']file://"
    r"|\.loadDataWithBaseURL\s*\(\s*[\"']file://"
)
# Webview INSTANCE marker — at least one of these has to appear
# alongside the JS-enabled flag, otherwise we're looking at a
# settings-of-something-else false match.
_WEBVIEW_MARKERS_RE = re.compile(
    r"\bWebView\b|\bWebSettings\b|\bandroid\.webkit\.WebView\b"
)

_MAX_FILES = 2500


class WebViewUniversalXssAgent(BaseAgent):
    """D_084: file-origin-bypass universal XSS target identifier."""

    AGENT_ID = "D_084"
    VULN_CLASS = "WebView Universal XSS (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _WEBVIEW_MARKERS_RE.search(text):
                continue
            if not _JS_ENABLED_RE.search(text):
                continue

            # Score the file-origin policy. We care about the
            # combination — JS+universal is the catastrophic case.
            allow_file = bool(_ALLOW_FILE_RE.search(text))
            allow_file_from_files = bool(_ALLOW_FILE_FROM_FILES_RE.search(text))
            allow_universal = bool(_ALLOW_UNIVERSAL_RE.search(text))
            loads_file_uri = bool(_LOAD_FILE_RE.search(text))

            # If none of the file-origin flags is set explicitly, this
            # is the generic XSS shape D_048 already covers — skip.
            if not (allow_file or allow_file_from_files or allow_universal):
                continue

            severity = (
                Severity.CRITICAL if allow_universal
                else Severity.HIGH if allow_file_from_files
                else Severity.MEDIUM
            )
            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.75,
                recommendation=(
                    f"`{class_name}` configures a WebView with "
                    "JavaScript enabled AND elevated file-origin "
                    "access. With "
                    "setAllowUniversalAccessFromFileURLs(true), any "
                    "JS loaded from a file:// URI can XHR every "
                    "origin including file:///data/data/<pkg>/, "
                    "reading the app's databases and shared prefs. "
                    "The Frida hook will fire a non-destructive "
                    "console.log probe via loadDataWithBaseURL and "
                    "confirm execution via WebChromeClient."
                    "onConsoleMessage. Set "
                    "setAllowFileAccessFromFileURLs(false) and "
                    "setAllowUniversalAccessFromFileURLs(false) "
                    "unless you genuinely need to load app-bundled "
                    "HTML — and even then, host it via a "
                    "WebViewAssetLoader instead."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "javascript_enabled": True,
                    "allow_file_access": allow_file,
                    "allow_file_access_from_file_urls": allow_file_from_files,
                    "allow_universal_access_from_file_urls": allow_universal,
                    "loads_file_uri": loads_file_uri,
                    "dynamic_target": True,
                    "frida_payload": self._build_payload(
                        class_name, allow_universal,
                    ),
                },
            ))
        return findings

    @staticmethod
    def _build_payload(
        target_class: str, has_universal: bool,
    ) -> dict[str, Any]:
        token = "d084_" + "".join(
            chr(ord("a") + (i * 7) % 26) for i in range(8)
        )
        probes = [
            # Non-destructive console.log probe — the agent watches for
            # the literal token in onConsoleMessage.
            (f"<script>console.log('SENTINEL_XSS_PROBE_{token}');"
             "</script>"),
            # Same probe in a data: URL shape so the hook can exercise
            # both loadDataWithBaseURL and the data: fast path.
            (f"data:text/html,<script>console.log("
             f"'SENTINEL_XSS_PROBE_{token}_D')</script>"),
        ]
        if has_universal:
            # Universal-access bypass probe: reach back to a file URI
            # the SCRIPT itself can read. We never exfiltrate — we
            # only console.log whether the cross-origin XHR succeeded.
            probes.append(
                f"<script>"
                f"const xhr=new XMLHttpRequest();"
                f"xhr.open('GET','file:///data/data/' + "
                f"location.host.replace(/[^a-z0-9.]/gi,'')+ "
                f"'/shared_prefs/',false);"
                f"try{{xhr.send();console.log('SENTINEL_UXSS_OK_"
                f"{token}');}}catch(e){{console.log('SENTINEL_UXSS_"
                f"BLOCKED_{token}');}}"
                f"</script>",
            )
        return {
            "target_class": target_class,
            "expect_console_token": f"SENTINEL_XSS_PROBE_{token}",
            "expect_uxss_token": f"SENTINEL_UXSS_OK_{token}",
            "probes": probes,
            "base_url": "file:///android_asset/",
            "safety_budget": {
                "max_actions_total": 4,
                "max_actions_per_sec": 1,
                "wall_clock_budget_s": 20,
                "max_consecutive_crashes": 2,
            },
            "frida_script_hint":
                "// D_084 — fire console.log probe via "
                "loadDataWithBaseURL\n"
                "// rpc.exports.webviewxssuniversal(payload) is the entry\n",
        }


__all__ = ["WebViewUniversalXssAgent"]
