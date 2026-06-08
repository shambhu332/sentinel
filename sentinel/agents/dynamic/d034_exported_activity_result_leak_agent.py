"""D_034 — Exported Activity setResult Leaks Sensitive Data.

When an Activity is launched via ``startActivityForResult`` (or its
modern AndroidX equivalent), the called Activity returns data to
the caller via ``setResult(resultCode, Intent)``. If the called
Activity is exported (or the calling package is different from the
target package), the returned Intent crosses an app boundary. Apps
routinely smuggle access tokens, account identifiers, file URIs
that point into the private data dir, and OTPs through this path
without realising the caller is unrelated.

Detection
---------

We consume one Frida event kind:

* ``activity.set_result`` — emitted from ``Activity.setResult(int)``
  and ``Activity.setResult(int, Intent)``. Payload:
  ``{activity_class, result_code, extras_keys, extras_sensitive,
  calling_package, own_package, stack}``.

``extras_sensitive`` is a list of extras keys whose name matches
the sensitive-keyword set (``token``, ``secret``, ``password``,
``cookie``, ``auth``, ``bearer``, ``otp``, ``account``, ``email``,
``phone``, ``ssn``). ``calling_package`` is the package name from
``Activity.getCallingPackage()`` — non-null only when the caller
launched via ``startActivityForResult``.

Severity matrix:

* **HIGH** — ``calling_package`` is set and differs from
  ``own_package``, ``extras_sensitive`` is non-empty.
* **MEDIUM** — cross-app return with extras keys present but no
  sensitive-keyword match (large or unknown payload; warrants
  review).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class ExportedActivityResultLeakAgent(BaseAgent):
    """D_034: classify cross-app setResult returns at runtime."""

    AGENT_ID = "D_034"
    VULN_CLASS = "Exported Activity Returns Sensitive Data Cross-App"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_034] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        sensitive_hits: list[dict[str, Any]] = []
        cross_app_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "activity.set_result":
                continue
            payload = ev.payload or {}
            calling = str(payload.get("calling_package") or "")
            own = str(payload.get("own_package") or "")
            if not calling or calling == own:
                # Same-app launch — no cross-boundary return.
                continue
            sensitive = payload.get("extras_sensitive") or []
            extras = payload.get("extras_keys") or []
            sample = {
                "activity_class": str(payload.get("activity_class") or "")[:200],
                "result_code": payload.get("result_code"),
                "extras_keys": list(extras)[:10],
                "extras_sensitive": list(sensitive)[:10],
                "calling_package": calling[:120],
                "own_package": own[:120],
                "stack": payload.get("stack"),
            }
            if sensitive:
                sensitive_hits.append(sample)
            elif extras:
                cross_app_hits.append(sample)

        findings: list[Finding] = []
        if sensitive_hits:
            findings.append(self._sensitive_finding(sensitive_hits))
        if cross_app_hits:
            findings.append(self._cross_app_finding(cross_app_hits))
        return findings

    def _sensitive_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.88,
            evidence={
                "issue": (
                    "Activity.setResult returned an Intent whose extras "
                    "include keys matching the sensitive-keyword set "
                    "(token / secret / password / cookie / auth / "
                    "bearer / OTP / account / email / phone / SSN) "
                    "to a *different* calling package. Any installed "
                    "app that knows the Activity's component name + "
                    "filter can launch it for-result and read the "
                    "returned data."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Activity.setResult inspected the "
                    "Intent extras' key names and compared "
                    "getCallingPackage() against the app's own "
                    "package."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop the sensitive extras from the result Intent "
                "and signal success via the resultCode alone. If the "
                "caller legitimately needs the value, gate the "
                "Activity behind a signature-level permission and "
                "validate ``getCallingPackage()`` inside ``onCreate``."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        )

    def _cross_app_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Activity setResult Returns Data Cross-App",
            severity=Severity.MEDIUM,
            confidence=0.60,
            evidence={
                "issue": (
                    "Activity.setResult returned an Intent with extras "
                    "to a different calling package. None of the key "
                    "names match the sensitive-keyword set, but the "
                    "shape — non-empty payload crossing an app "
                    "boundary — warrants review."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Activity.setResult observed "
                    "cross-package returns with non-empty extras."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Audit the data payload. Anything tied to the user's "
                "session or device state should be omitted from the "
                "cross-app return."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )
