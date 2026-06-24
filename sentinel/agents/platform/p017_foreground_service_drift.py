"""P_017 — Foreground-service privilege drift.

Android 14 (API 34) made ``foregroundServiceType`` mandatory for any
service that calls ``startForeground``. The declared type also gates
the runtime permission requirements (e.g. ``location`` ⇒
``ACCESS_FINE_LOCATION`` + ``FOREGROUND_SERVICE_LOCATION``;
``camera`` ⇒ ``CAMERA`` + ``FOREGROUND_SERVICE_CAMERA``).

Findings are emitted when any of these holds:

* Service declared in manifest with no ``foregroundServiceType`` —
  any ``startForeground`` call at runtime will throw on Android 14+.
* Service exposes a privileged ``foregroundServiceType``
  (``location|camera|microphone|connectedDevice``) AND is
  ``exported=true``.
* Service declares a privileged type but the matching
  ``FOREGROUND_SERVICE_<TYPE>`` permission is missing from the
  ``<uses-permission>`` list.
"""
from __future__ import annotations

from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity


# foregroundServiceType → required FOREGROUND_SERVICE_<TYPE> permission.
_PRIVILEGED_TYPES: dict[str, str] = {
    "location":         "android.permission.FOREGROUND_SERVICE_LOCATION",
    "camera":           "android.permission.FOREGROUND_SERVICE_CAMERA",
    "microphone":       "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "connectedDevice":  "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
    "mediaProjection":  "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
    "phoneCall":        "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
    "health":           "android.permission.FOREGROUND_SERVICE_HEALTH",
}


class ForegroundServiceDriftAgent(BaseAgent):
    AGENT_ID = "P_017"
    VULN_CLASS = "Foreground-Service Privilege Drift"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        return bool((self._context.manifest or {}).get("services"))

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        permissions = set(self._context.permissions or manifest.get(
            "uses_permissions", []) or [])
        findings: list[Finding] = []

        for service in manifest.get("services", []) or []:
            if not isinstance(service, dict):
                continue
            name = service.get("name", "?")
            exported = bool(service.get("exported"))
            fg_type = service.get("foregroundServiceType")
            issues: list[str] = []

            # Multiple types can be ORed in the manifest as `|`-separated.
            type_tokens: list[str] = []
            if isinstance(fg_type, str) and fg_type:
                type_tokens = [t.strip() for t in fg_type.split("|") if t.strip()]
            elif isinstance(fg_type, list):
                type_tokens = [str(t) for t in fg_type]

            if not type_tokens:
                # Android 14+ throws SecurityException on startForeground
                # without a type. Likely-fatal at runtime on modern OS.
                issues.append(
                    "foregroundServiceType missing — Android 14+ requires it",
                )

            for token in type_tokens:
                required = _PRIVILEGED_TYPES.get(token)
                if required and required not in permissions:
                    issues.append(
                        f"foregroundServiceType={token!r} but "
                        f"{required} not declared",
                    )
                if required and exported:
                    issues.append(
                        f"privileged foregroundServiceType={token!r} on "
                        "exported service — any app can invoke it",
                    )

            if not issues:
                continue

            severity = (
                Severity.HIGH if exported and any(
                    t in _PRIVILEGED_TYPES for t in type_tokens
                )
                else Severity.MEDIUM
            )
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.78,
                recommendation=(
                    f"Service `{name}` has foreground-service privilege "
                    f"drift: {'; '.join(issues)}. Set "
                    "`android:foregroundServiceType` to the narrowest "
                    "type your service actually uses, declare the "
                    "matching `FOREGROUND_SERVICE_<TYPE>` permission, "
                    "and set `exported=false` unless an external caller "
                    "genuinely needs to bind to this service."
                ),
                evidence={
                    "service": name,
                    "exported": exported,
                    "foreground_service_type": fg_type,
                    "type_tokens": type_tokens,
                    "issues": issues,
                },
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-1",
            ))
        return findings
