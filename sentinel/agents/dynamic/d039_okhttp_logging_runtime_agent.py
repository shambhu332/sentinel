"""D_039 — OkHttp HttpLoggingInterceptor Logs Body / Headers in Release.

OkHttp's ``HttpLoggingInterceptor`` ships four levels — ``NONE``,
``BASIC``, ``HEADERS``, ``BODY``. The latter two leak the entire
HTTP exchange (request + response) into ``adb logcat``, which is
fine for debugging but disastrous in release builds: bearer tokens,
session cookies, OTP responses, and full PII payloads end up in
logcat buffers that third-party crash reporters ship off-device.

Static SAST (N_010) catches the obvious ``new HttpLoggingInterceptor"
"().setLevel(BODY)`` pattern. This agent picks up the reflection-
built / DI-injected variants that hide from the static scan.

Detection
---------

We consume one Frida event kind:

* ``okhttp.logging_level_observed`` — emitted from every
  ``HttpLoggingInterceptor.intercept`` call. Payload:
  ``{level, interceptor_class, caller_class, stack}``.

Severity matrix:

* **HIGH** — ``level`` is ``BODY`` (full request + response body
  logging).
* **MEDIUM** — ``level`` is ``HEADERS`` (headers — including
  Authorization / Cookie — logged).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class OkHttpLoggingRuntimeAgent(BaseAgent):
    """D_039: catch HttpLoggingInterceptor levels at runtime."""

    AGENT_ID = "D_039"
    VULN_CLASS = "OkHttp HttpLoggingInterceptor Logs Body / Headers"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_039] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        body_hits: dict[str, dict[str, Any]] = {}
        headers_hits: dict[str, dict[str, Any]] = {}

        for ev in capture.events:
            if ev.kind != "okhttp.logging_level_observed":
                continue
            payload = ev.payload or {}
            level = str(payload.get("level") or "").upper()
            interceptor = str(payload.get("interceptor_class") or "")
            sample = {
                "level": level,
                "interceptor_class": interceptor[:200],
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "stack": payload.get("stack"),
            }
            # Deduplicate per interceptor instance (most apps install
            # one interceptor and run thousands of requests through it).
            key = interceptor or "<anonymous>"
            if level == "BODY":
                body_hits.setdefault(key, sample)
            elif level == "HEADERS":
                headers_hits.setdefault(key, sample)

        findings: list[Finding] = []
        if body_hits:
            findings.append(self._body_finding(list(body_hits.values())))
        if headers_hits:
            findings.append(self._headers_finding(list(headers_hits.values())))
        return findings

    def _body_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.92,
            evidence={
                "issue": (
                    "HttpLoggingInterceptor.intercept was invoked with "
                    "Level.BODY — every request and response body the "
                    "interceptor sees is written to logcat. In a "
                    "release build any third-party crash reporter "
                    "(Bugsnag, Crashlytics, Sentry's native bridge) "
                    "that snapshots logcat lifts the entire HTTP "
                    "exchange off-device."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on HttpLoggingInterceptor.intercept "
                    "read the Level enum value at call time."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Build the interceptor only in debug builds, e.g. "
                "``if (BuildConfig.DEBUG) client.addInterceptor(...)`` "
                "or gate Level on ``BuildConfig.DEBUG``. Never ship a "
                "release with BODY or HEADERS enabled."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )

    def _headers_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="OkHttp HttpLoggingInterceptor Logs Headers",
            severity=Severity.MEDIUM,
            confidence=0.85,
            evidence={
                "issue": (
                    "HttpLoggingInterceptor.intercept was invoked with "
                    "Level.HEADERS — Authorization and Cookie headers "
                    "are written to logcat. Less catastrophic than "
                    "BODY but still leaks every session token and "
                    "bearer credential."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook read the Level enum value at intercept "
                    "time and matched HEADERS."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop HEADERS in release builds. If headers must be "
                "logged for diagnostics, redact Authorization and "
                "Cookie via redactHeader before installing the "
                "interceptor."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )
