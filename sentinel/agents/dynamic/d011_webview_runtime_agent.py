"""D_011 — WebView Runtime Configuration Observer.

Android ``WebView`` is one of the longest-running mobile RCE surfaces.
The combinations that matter at runtime:

* ``addJavascriptInterface(obj, name)`` registers a Java object whose
  ``@JavascriptInterface`` methods are callable from any JavaScript
  loaded in the WebView. If the WebView ever loads attacker-controlled
  HTML (an HTTP URL, a redirect, a postMessage from an iframe, an
  XSS in the legitimate origin), every exposed method runs in the
  app's identity.

* ``WebSettings.setAllowFileAccessFromFileURLs(true)`` and
  ``setAllowUniversalAccessFromFileURLs(true)`` let a ``file://``
  page read other files on the device and make cross-origin
  requests. Combined with a file:// load, this is the same-origin-
  policy bypass that has shipped CVEs across multiple OEMs.

* ``setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`` (value 0) lets
  an HTTPS page load HTTP subresources, undoing the WebView's
  baseline TLS guarantee.

* ``setWebContentsDebuggingEnabled(true)`` exposes the WebView to
  Chrome DevTools over USB even on release builds — a rooted /
  rooted-adjacent attacker can attach a remote debugger.

* ``loadUrl("javascript:…")`` invoked on an attacker-controlled
  string lets a Java caller forge the bridge call instead of going
  through the legitimate JS path.

Detection
---------

We consume Frida events of kind:

* ``webview.js_interface_added`` — ``{name, object_class, exposed_methods}``
* ``webview.settings`` — ``{setting, value}`` for each security-
  relevant setter (one event per call)
* ``webview.load`` — ``{url, scheme}`` per loadUrl / loadDataWithBaseURL
* ``webview.debugging`` — ``{enabled}`` from setWebContentsDebuggingEnabled

Findings:

* **CRITICAL** — JS interface registered AND the WebView loaded any
  URL whose scheme is ``http`` OR whose host is not under the app's
  own package (heuristic: third-party origin) — the bridge is
  reachable from attacker-controlled JS.
* **HIGH** — ``setAllowFileAccessFromFileURLs(true)`` OR
  ``setAllowUniversalAccessFromFileURLs(true)`` observed.
* **HIGH** — ``setWebContentsDebuggingEnabled(true)`` observed (the
  app is presumably released, not a debug build — debug builds are
  the developer's choice and aren't shipped to users).
* **MEDIUM** — ``setMixedContentMode(0)`` observed.
* **MEDIUM** — ``loadUrl("javascript:…")`` invoked from the app's own
  code (sink for SSRF-style JS injection).
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_MIXED_CONTENT_ALWAYS_ALLOW = 0


class WebViewRuntimeAgent(BaseAgent):
    """D_011: classify WebView runtime configuration findings."""

    AGENT_ID = "D_011"
    VULN_CLASS = "Insecure WebView Runtime Configuration"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_011] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        bridges: list[dict[str, Any]] = []
        loads: list[dict[str, Any]] = []
        file_access: list[dict[str, Any]] = []
        debugging: list[dict[str, Any]] = []
        mixed: list[dict[str, Any]] = []
        js_loads: list[dict[str, Any]] = []

        package = (self._context.manifest or {}).get("package") or ""
        own_host_root = _root_domain_from_package(package)

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "webview.js_interface_added":
                bridges.append({
                    "name": payload.get("name"),
                    "object_class": payload.get("object_class"),
                    "exposed_methods": payload.get("exposed_methods") or [],
                })
            elif ev.kind == "webview.load":
                url = str(payload.get("url") or "")
                scheme = str(payload.get("scheme") or "").lower()
                if not scheme and url:
                    parsed = urlparse(url)
                    scheme = parsed.scheme.lower()
                if scheme == "javascript":
                    js_loads.append({"url": url[:200]})
                else:
                    loads.append({
                        "url": url[:200], "scheme": scheme,
                    })
            elif ev.kind == "webview.settings":
                setting = str(payload.get("setting") or "")
                value = payload.get("value")
                if setting in (
                    "setAllowFileAccessFromFileURLs",
                    "setAllowUniversalAccessFromFileURLs",
                ) and value is True:
                    file_access.append({"setting": setting})
                elif setting == "setMixedContentMode" and \
                        value == _MIXED_CONTENT_ALWAYS_ALLOW:
                    mixed.append({"setting": setting, "value": value})
            elif ev.kind == "webview.debugging":
                if bool(payload.get("enabled")):
                    debugging.append({"enabled": True})

        findings: list[Finding] = []
        if bridges and _any_untrusted_load(loads, own_host_root):
            findings.append(self._bridge_finding(bridges, loads))
        if file_access:
            findings.append(self._file_access_finding(file_access))
        if debugging:
            findings.append(self._debugging_finding(debugging))
        if mixed:
            findings.append(self._mixed_content_finding(mixed))
        if js_loads:
            findings.append(self._js_load_finding(js_loads))
        return findings

    # ---------- finding builders ----------

    def _bridge_finding(
        self,
        bridges: list[dict[str, Any]],
        loads: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="WebView JS Bridge + Untrusted Origin",
            severity=Severity.CRITICAL,
            confidence=0.90,
            evidence={
                "issue": (
                    "The WebView registers a JavaScript bridge via "
                    "addJavascriptInterface and loads at least one "
                    "URL whose scheme is HTTP, javascript:, or whose "
                    "host is not under the application's own root "
                    "domain. Any JavaScript that runs in the WebView "
                    "context — including XSS on the legitimate "
                    "origin, an iframe, a redirect, or a "
                    "postMessage — can invoke every method annotated "
                    "@JavascriptInterface on the bridge object, "
                    "running with the application's full Android "
                    "permissions."
                ),
                "bridges": bridges,
                "loaded_urls": loads[:8],
                "vector": (
                    "Frida hook on WebView.addJavascriptInterface "
                    "captured every bridge registration. WebView."
                    "loadUrl / loadDataWithBaseURL captured every "
                    "navigation; bridges + non-first-party URL = "
                    "reachable attacker surface."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If you must expose Java methods to web content, "
                "load only content you fully control (your own "
                "first-party HTTPS domain with a Network Security "
                "Config pin), validate every URL navigation against "
                "an allow-list before loadUrl, and pass user-supplied "
                "input through the bridge using a typed JSON envelope "
                "you parse and validate Java-side. Better: replace "
                "JavascriptInterface with the WebMessageListener API "
                "(Android 8+) which scopes the bridge to a single "
                "JS origin you specify."
            ),
            owasp="M7: Client Code Quality",
            masvs="MSTG-PLATFORM-7",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        )

    def _file_access_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        settings = sorted({i["setting"] for i in items})
        return self._make_finding(
            vuln_class="WebView File-Access Allowed",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The WebView was configured with "
                    f"{settings}(true). A page loaded with the "
                    "file:// scheme can now read other files on the "
                    "device and make cross-origin requests to "
                    "arbitrary servers, bypassing the same-origin "
                    "policy."
                ),
                "samples": items[:5],
                "vector": (
                    "Frida hook on WebSettings setters captured the "
                    "configuration change at runtime."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Both setAllowFileAccessFromFileURLs and "
                "setAllowUniversalAccessFromFileURLs default to "
                "false on API 30+ — leave them at the default. If "
                "the app must load file:// content, host it on "
                "androidplatform.net WebViewAssetLoader (the modern "
                "replacement) which gives the file a virtual https:// "
                "origin without disabling the same-origin policy."
            ),
            owasp="M7: Client Code Quality",
            masvs="MSTG-PLATFORM-7",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        )

    def _debugging_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="WebView Contents Debugging Enabled",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "setWebContentsDebuggingEnabled(true) was observed "
                    "at runtime. Any attacker with USB / ADB access "
                    "(rooted device, evil maid, supply-chain) can "
                    "attach Chrome DevTools to the WebView and read "
                    "DOM state, intercept JS bridge calls, and "
                    "exfiltrate session tokens stored in localStorage."
                ),
                "samples": items[:3],
                "vector": (
                    "Frida hook on WebView.setWebContentsDebuggingEnabled."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Gate the call on BuildConfig.DEBUG so it only "
                "applies in debuggable builds: "
                "``if (BuildConfig.DEBUG) "
                "WebView.setWebContentsDebuggingEnabled(true);``. "
                "Release builds should never enable it."
            ),
            owasp="M10: Extraneous Functionality",
            masvs="MSTG-CODE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _mixed_content_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="WebView Mixed Content Allowed",
            severity=Severity.MEDIUM,
            confidence=0.85,
            evidence={
                "issue": (
                    "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) "
                    "lets an HTTPS-loaded page pull HTTP "
                    "subresources. A network attacker can MITM the "
                    "HTTP load and inject script that runs in the "
                    "outer HTTPS origin, undoing the WebView's "
                    "transport guarantee."
                ),
                "samples": items[:3],
                "vector": (
                    "Frida hook on WebSettings.setMixedContentMode."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Set MIXED_CONTENT_NEVER_ALLOW (1). If a legacy "
                "endpoint forces HTTP, gate behind an explicit "
                "user prompt and audit the resource."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-2",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        )

    def _js_load_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="WebView javascript: URL Loaded",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application invokes WebView.loadUrl with a "
                    "``javascript:`` URL. If any part of that URL is "
                    "user-controlled, the caller has direct JS "
                    "injection into the WebView, which combined with "
                    "any registered bridge becomes RCE."
                ),
                "samples": items[:5],
                "vector": "Frida hook on WebView.loadUrl filtered for the javascript: scheme.",
                "sources": ["frida"],
            },
            recommendation=(
                "Use evaluateJavascript(script, callback) with a "
                "static script string, never string-concatenated "
                "user input. If user content must reach the page, "
                "pass it through the bridge as a typed JSON payload "
                "and have JS render it via "
                "``element.textContent`` — never ``innerHTML``."
            ),
            owasp="M7: Client Code Quality",
            masvs="MSTG-PLATFORM-7",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",
        )


# ---------- helpers ----------


def _root_domain_from_package(package: str) -> str:
    """Best-effort: com.example.app -> example.com. Used as a heuristic
    for "first-party host"; never authoritative."""
    if not package:
        return ""
    parts = package.split(".")
    if len(parts) < 2:
        return package
    return f"{parts[1]}.{parts[0]}".lower()


def _any_untrusted_load(
    loads: list[dict[str, Any]], own_root: str,
) -> bool:
    if not loads:
        return False
    own_root = (own_root or "").lower()
    for entry in loads:
        scheme = (entry.get("scheme") or "").lower()
        if scheme == "http":
            return True
        url = entry.get("url") or ""
        host = ""
        try:
            host = urlparse(url).hostname or ""
        except (TypeError, ValueError):
            host = ""
        host = host.lower()
        if not host:
            continue
        if own_root and host.endswith(own_root):
            continue
        # Anything that isn't first-party + isn't a benign about:blank
        # / blob: load.
        if scheme in ("https", "http"):
            return True
    return False
