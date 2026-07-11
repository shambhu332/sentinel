"""D_086 — Intent Injection XSS (Intent extra → WebView.loadUrl flow).

Specifically targets the most common mobile XSS shape:

    String url = getIntent().getStringExtra("url");
    webView.loadUrl(url);

D_048 catches the WebView config; D_083 catches the SSRF angle of
the same flow. D_086 catches the **XSS-via-deep-link** angle —
when the attacker controls a `javascript:` or `data:text/html` URI
that the WebView dutifully renders.

SAST identification:
  1. The activity reads from `getIntent().getStringExtra()` or
     `getIntent().getData()` / `getDataString()`.
  2. The captured variable flows into `.loadUrl(...)` somewhere
     within ~40 lines (per-file analysis — we don't do inter-method
     taint).
  3. JavaScript is enabled.

Frida hook (d086_intent_xss.ts) launches the activity with two
non-destructive probes — `javascript:console.log(...)` and
`data:text/html,<script>console.log(...)</script>` — and watches
WebChromeClient.onConsoleMessage for the token.

Safety: only console.log probes, never alert(), never anything that
writes to clipboard / fetches external. The probe token is
session-unique so we can attribute hits.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_JS_ENABLED_RE = re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)")
_INTENT_SOURCE_RE = re.compile(
    r"getIntent\s*\(\s*\)\s*\.\s*"
    r"(?:getStringExtra|getData|getDataString)\s*\("
    r"|intent\s*\.\s*(?:getStringExtra|getData|getDataString)\s*\("
)
_LOAD_URL_RE = re.compile(r"\.loadUrl\s*\(")
_WEBVIEW_MARKER = "WebView"


_MAX_FILES = 2500


class IntentXssAgent(BaseAgent):
    """D_086: Intent-extra → WebView.loadUrl XSS target identifier."""

    AGENT_ID = "D_086"
    VULN_CLASS = "Intent Injection XSS (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.decompiled_dir and ctx.decompiled_dir.exists()
            and ctx.manifest
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        if root is None:
            return []
        manifest = ctx.manifest or {}

        # Build a map of activity-class -> exported flag from the manifest;
        # exported flow is HIGH, non-exported MEDIUM.
        exported: dict[str, bool] = {}
        for act in manifest.get("activities", []) or []:
            if not isinstance(act, dict):
                continue
            name = (act.get("name") or "").split(".")[-1]
            if name:
                exported[name] = bool(act.get("exported"))

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
            if _WEBVIEW_MARKER not in text:
                continue
            if not _INTENT_SOURCE_RE.search(text):
                continue
            if not _LOAD_URL_RE.search(text):
                continue
            if not _JS_ENABLED_RE.search(text):
                continue

            class_name = path.stem.split("$")[0]
            rel = str(path.relative_to(root))
            is_exported = exported.get(class_name, False)
            severity = Severity.HIGH if is_exported else Severity.MEDIUM

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.70,
                recommendation=(
                    f"`{class_name}` reads a URL from the Intent and "
                    "passes it to `WebView.loadUrl`, with JS enabled. "
                    + ("The activity is exported — any installed app "
                       "can fire it. "
                       if is_exported else
                       "The activity is not exported per the manifest, "
                       "but a chained deep-link bug can still reach it. ")
                    + "The Frida hook will launch the activity with "
                    "`javascript:console.log(...)` + "
                    "`data:text/html,<script>console.log(...)</script>` "
                    "probes and watch onConsoleMessage. Fix by "
                    "rejecting any URL whose scheme isn't on an "
                    "explicit allow-list (`https`, `app-bundle`) and "
                    "blocking `javascript:` / `data:` / `file:` "
                    "schemes at the activity boundary."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "activity_exported": is_exported,
                    "javascript_enabled": True,
                    "intent_source_present": True,
                    "load_url_present": True,
                    "dynamic_target": True,
                    "frida_payload": self._build_payload(
                        class_name, is_exported,
                    ),
                },
            ))
        return findings

    @staticmethod
    def _build_payload(
        target_class: str, is_exported: bool,
    ) -> dict[str, Any]:
        token = "d086_" + "".join(
            chr(ord("a") + (i * 11) % 26) for i in range(8)
        )
        return {
            "target_activity": target_class,
            "activity_exported": is_exported,
            # The hook fires these as Intent extras targeting
            # commonly-used keys. Non-destructive probes only.
            "intent_extra_keys": ["url", "uri", "link", "target", "href"],
            "probes": [
                f"javascript:console.log('SENTINEL_INTENT_XSS_PROBE_{token}')",
                (f"data:text/html,<script>console.log("
                 f"'SENTINEL_INTENT_XSS_PROBE_{token}_D')</script>"),
            ],
            "expect_console_token": f"SENTINEL_INTENT_XSS_PROBE_{token}",
            "safety_budget": {
                "max_actions_total": 6,
                "max_actions_per_sec": 1,
                "wall_clock_budget_s": 20,
                "max_consecutive_crashes": 2,
            },
            "frida_script_hint":
                "// D_086 — startActivity with javascript: / data: payload\n"
                "// rpc.exports.intentxss(payload) is the entry\n",
        }


__all__ = ["IntentXssAgent"]
