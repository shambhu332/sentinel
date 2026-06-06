"""N_009: WebView Remote Debugging Flag Detection.

``WebView.setWebContentsDebuggingEnabled(true)`` lets any USB-connected
device (or any process on the device with adb access) attach Chrome's
``chrome://inspect/#devices`` to the running WebView. The debugger has
full DOM and JS-context access — it can read DOM-stored auth tokens,
inject JavaScript into the live page, sniff requests, and bypass any
in-WebView JS sandboxing the app set up.

Google's own documentation says this flag MUST be wrapped in a
``BuildConfig.DEBUG`` (or equivalent) check so it's stripped from
release builds. In practice it ships unguarded in a *lot* of apps — the
Mozilla MDN and AOSP guides both call this out as one of the highest
single-method-call mistakes in Android security.

Detection
---------
Find every call to ``WebView.setWebContentsDebuggingEnabled(true)`` (or
``setWebContentsDebuggingEnabled(true)`` on a WebView-typed expression).
For each, look at the enclosing method body for one of the canonical
release-stripped guards:

* ``BuildConfig.DEBUG``
* ``ApplicationInfo.FLAG_DEBUGGABLE``
* ``Debug.isDebuggerConnected()``
* ``getApplicationInfo().flags`` with a debuggable mask

If none is present in the same source file, the call ships to release
and earns a HIGH finding. When the guard exists, we drop to INFO (the
flag is correctly gated; we surface it for audit completeness).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_DEBUG_CALL = re.compile(
    r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
)
_GUARD_PATTERNS = (
    re.compile(r"\bBuildConfig\.DEBUG\b"),
    re.compile(r"FLAG_DEBUGGABLE"),
    re.compile(r"Debug\.isDebuggerConnected\s*\("),
    re.compile(r"getApplicationInfo\s*\(\s*\)\.flags"),
)


class WebViewDebugFlagAgent(BaseAgent):
    """Detect ungated WebView remote debugging in release builds."""

    AGENT_ID = "N_009"
    VULN_CLASS = "WebView Remote Debugging Enabled"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            if not _DEBUG_CALL.search(source):
                continue

            guarded = any(p.search(source) for p in _GUARD_PATTERNS)
            rel = str(java_file.relative_to(decompiled))

            if guarded:
                findings.append(self._make_finding(
                    vuln_class="WebView Debugging (Guarded)",
                    severity=Severity.INFO,
                    confidence=0.60,
                    evidence={
                        "file": rel,
                        "guard_detected": True,
                        "issue": (
                            "setWebContentsDebuggingEnabled(true) is "
                            "present but appears wrapped in a "
                            "BuildConfig.DEBUG / FLAG_DEBUGGABLE check"
                        ),
                    },
                    recommendation=(
                        "Verify R8 / ProGuard strips the debug branch "
                        "from release builds. A common regression is the "
                        "guard becoming a constant-true at compile time "
                        "due to a stale BuildConfig.DEBUG variant — run "
                        "``adb shell setprop debug.assist on`` on a "
                        "release build and try to attach chrome://inspect "
                        "to confirm."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-RESILIENCE-2",
                ))
            else:
                findings.append(self._make_finding(
                    vuln_class="WebView Remote Debugging Enabled",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    evidence={
                        "file": rel,
                        "guard_detected": False,
                        "issue": (
                            "setWebContentsDebuggingEnabled(true) "
                            "without a BuildConfig.DEBUG / debuggable "
                            "guard — ships chrome://inspect access in "
                            "release"
                        ),
                    },
                    recommendation=(
                        "Wrap the call in ``if (BuildConfig.DEBUG)`` "
                        "or remove it entirely. While the WebView is "
                        "debugger-attachable, any process with adb "
                        "access can read DOM-stored secrets and inject "
                        "JavaScript into the page. The fix is one line."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-RESILIENCE-2",
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                ))
        return findings
