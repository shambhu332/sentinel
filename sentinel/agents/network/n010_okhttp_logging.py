"""N_010: OkHttp HttpLoggingInterceptor BODY/HEADERS Detection.

OkHttp's ``HttpLoggingInterceptor`` writes request and response data
to a logger (logcat by default). The interceptor has four levels:

* ``Level.NONE`` — nothing logged (the default)
* ``Level.BASIC`` — request method / URL / response code only
* ``Level.HEADERS`` — request + response headers (includes
  ``Authorization``, ``Cookie``, ``Set-Cookie``)
* ``Level.BODY`` — headers + request and response bodies

``Level.HEADERS`` and ``Level.BODY`` shipped to a release build are
serious bugs:

* ``Authorization: Bearer …`` and ``Cookie:`` headers land in logcat
  where any app with ``READ_LOGS`` (granted automatically on rooted
  / debuggable devices, and via accessibility-service abuse paths)
  can scrape them.
* Body logging additionally dumps form POSTs, JSON bodies containing
  PII, and refresh-token rotation payloads.

The standard guard is to wrap the ``setLevel(Level.BODY)`` /
``setLevel(Level.HEADERS)`` call in ``if (BuildConfig.DEBUG)`` so R8
strips it from release. The same guard idea as N_009.

Detection
=========

Find every ``setLevel(HttpLoggingInterceptor.Level.BODY)`` /
``setLevel(HttpLoggingInterceptor.Level.HEADERS)`` /
``setLevel(Level.BODY)`` / ``setLevel(Level.HEADERS)`` call in
decompiled Java. For each call, look at the enclosing file for one
of the canonical release-stripped guards (same set N_009 uses).

* Guard absent → HIGH (BODY) / MEDIUM (HEADERS only)
* Guard present → INFO (audit completeness — surface so a reviewer
  can confirm R8 actually strips the branch)
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_BODY_CALL = re.compile(
    r"setLevel\s*\(\s*(?:HttpLoggingInterceptor\.)?Level\.BODY\s*\)",
)
_HEADERS_CALL = re.compile(
    r"setLevel\s*\(\s*(?:HttpLoggingInterceptor\.)?Level\.HEADERS\s*\)",
)
_GUARD_PATTERNS = (
    re.compile(r"\bBuildConfig\.DEBUG\b"),
    re.compile(r"FLAG_DEBUGGABLE"),
    re.compile(r"Debug\.isDebuggerConnected\s*\("),
    re.compile(r"getApplicationInfo\s*\(\s*\)\.flags"),
)


class OkHttpLoggingAgent(BaseAgent):
    """Detect ungated HttpLoggingInterceptor BODY/HEADERS shipped to release."""

    AGENT_ID = "N_010"
    VULN_CLASS = "OkHttp Body / Header Logging"
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
            body_hit = bool(_BODY_CALL.search(source))
            headers_hit = bool(_HEADERS_CALL.search(source))
            if not (body_hit or headers_hit):
                continue

            guarded = any(p.search(source) for p in _GUARD_PATTERNS)
            rel = str(java_file.relative_to(decompiled))

            if guarded:
                findings.append(self._make_finding(
                    vuln_class="OkHttp Body / Header Logging (Guarded)",
                    severity=Severity.INFO,
                    confidence=0.60,
                    evidence={
                        "file": rel,
                        "level_body": body_hit,
                        "level_headers": headers_hit,
                        "guard_detected": True,
                        "issue": (
                            "HttpLoggingInterceptor.Level.BODY/HEADERS "
                            "is present but appears wrapped in a "
                            "BuildConfig.DEBUG / FLAG_DEBUGGABLE check"
                        ),
                    },
                    recommendation=(
                        "Confirm R8 / ProGuard strips the debug branch "
                        "from release builds. Run `aapt dump strings "
                        "<release.apk> | grep HttpLoggingInterceptor` "
                        "to be sure the interceptor class itself does "
                        "not survive — if it does, the BODY level "
                        "constant may also remain reachable via "
                        "reflection."
                    ),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-STORAGE-3",
                ))
                continue

            severity = Severity.HIGH if body_hit else Severity.MEDIUM
            confidence = 0.90 if body_hit else 0.80
            level_name = "BODY" if body_hit else "HEADERS"

            findings.append(self._make_finding(
                vuln_class="OkHttp Body / Header Logging",
                severity=severity,
                confidence=confidence,
                evidence={
                    "file": rel,
                    "level_body": body_hit,
                    "level_headers": headers_hit,
                    "guard_detected": False,
                    "issue": (
                        f"HttpLoggingInterceptor.Level.{level_name} is "
                        "set without a BuildConfig.DEBUG guard. "
                        + (
                            "Request and response bodies are written "
                            "to logcat in release builds — PII, "
                            "Authorization headers, refresh-token "
                            "payloads all leak."
                            if body_hit else
                            "Request and response headers (including "
                            "Authorization / Cookie) are written to "
                            "logcat in release builds."
                        )
                    ),
                },
                recommendation=(
                    "Wrap the setLevel(...) call in `if (BuildConfig."
                    "DEBUG)` or remove the interceptor entirely from "
                    "release builds. Better still, use a redacting "
                    "logger that masks Authorization / Cookie / "
                    "Set-Cookie headers regardless of build type, so "
                    "BODY-level diagnostics remain safe to ship."
                ),
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MSTG-STORAGE-3",
                cvss_vector=(
                    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                ),
            ))
        return findings
