"""P_005: Excessive Manifest Permission Audit.

Iterates the manifest's ``uses-permission`` list and flags entries
from a curated table of sensitive permissions. The intent is *not* to
say "this permission is always wrong" — many apps legitimately need
``READ_SMS`` or ``CAMERA``. The intent is to give a reviewer a
focused list of permissions that historically correlate with data
exfiltration, privilege abuse, or accessibility-based UI hijack, so
they can quickly check whether each one matches a real feature.

Permission categories
---------------------

* **HIGH** — privacy- and integrity-impacting permissions that should
  only ship when a documented feature requires them: SMS, contacts,
  call logs, location, accessibility service, system overlay,
  device-admin, install-other-packages, biometric-as-fallback.
* **MEDIUM** — moderate-impact: external storage write, camera,
  microphone, body sensors, calendar, accounts, ignore-battery-opt.
* **INFO** — diagnostic surfacing of broadly-granted permissions:
  internet, network state, wake lock — these aren't bugs but reviewers
  often want to see the full footprint in one place.

The agent does not double-flag permissions when ``IPC_001`` or
``F_001`` already raised them in another context — those are
component / cloud-config bugs, not "the manifest asked for too much".
"""
from __future__ import annotations

from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

# (permission name, severity, rationale)
_PERMISSION_TABLE: list[tuple[str, Severity, str]] = [
    # HIGH ----------------------------------------------------------
    ("android.permission.READ_SMS", Severity.HIGH,
     "Reads SMS inbox — commonly abused for OTP interception"),
    ("android.permission.RECEIVE_SMS", Severity.HIGH,
     "Receives incoming SMS broadcasts — OTP / 2FA interception risk"),
    ("android.permission.SEND_SMS", Severity.HIGH,
     "Sends SMS at app's expense — premium-rate abuse risk"),
    ("android.permission.READ_CALL_LOG", Severity.HIGH,
     "Reads call history — privacy-sensitive metadata"),
    ("android.permission.WRITE_CALL_LOG", Severity.HIGH,
     "Modifies call history — used to hide attacker calls"),
    ("android.permission.READ_CONTACTS", Severity.HIGH,
     "Reads address book — commonly exfiltrated"),
    ("android.permission.WRITE_CONTACTS", Severity.HIGH,
     "Modifies address book — phishing-contact injection"),
    ("android.permission.ACCESS_FINE_LOCATION", Severity.HIGH,
     "GPS-level location access — high-precision tracking"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", Severity.HIGH,
     "Location while app is backgrounded — surveillance risk"),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", Severity.HIGH,
     "Accessibility service binding — full UI control, classic banker-trojan vector"),
    ("android.permission.SYSTEM_ALERT_WINDOW", Severity.HIGH,
     "Draw-on-top overlay — used for tapjacking and credential overlays"),
    ("android.permission.BIND_DEVICE_ADMIN", Severity.HIGH,
     "Device admin policy — wipe / lock / disable-camera capability"),
    ("android.permission.REQUEST_INSTALL_PACKAGES", Severity.HIGH,
     "Side-load APKs — second-stage malware install vector"),
    ("android.permission.PACKAGE_USAGE_STATS", Severity.HIGH,
     "App-usage telemetry — privacy-sensitive history"),
    ("android.permission.QUERY_ALL_PACKAGES", Severity.HIGH,
     "Enumerates installed apps — fingerprinting / banking-target enumeration"),
    # MEDIUM --------------------------------------------------------
    ("android.permission.WRITE_EXTERNAL_STORAGE", Severity.MEDIUM,
     "Writes to shared external storage — world-readable risk"),
    ("android.permission.MANAGE_EXTERNAL_STORAGE", Severity.MEDIUM,
     "Scoped-storage bypass on Android 11+"),
    ("android.permission.CAMERA", Severity.MEDIUM,
     "Camera access — covert capture risk"),
    ("android.permission.RECORD_AUDIO", Severity.MEDIUM,
     "Microphone — covert recording risk"),
    ("android.permission.BODY_SENSORS", Severity.MEDIUM,
     "Body sensors — health-data privacy"),
    ("android.permission.READ_CALENDAR", Severity.MEDIUM,
     "Calendar entries — meeting / contact harvesting"),
    ("android.permission.WRITE_CALENDAR", Severity.MEDIUM,
     "Inject events — phishing / spam vector"),
    ("android.permission.GET_ACCOUNTS", Severity.MEDIUM,
     "Lists OS accounts — email / username enumeration"),
    ("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", Severity.MEDIUM,
     "Skip Doze restrictions — persistence enabler"),
    # INFO ----------------------------------------------------------
    ("android.permission.INTERNET", Severity.INFO,
     "Network access — needed by most apps, surfaced for footprint"),
    ("android.permission.ACCESS_NETWORK_STATE", Severity.INFO,
     "Network connectivity inspection — common, low risk"),
    ("android.permission.WAKE_LOCK", Severity.INFO,
     "Keeps CPU on — common, low risk"),
]


class ExcessivePermissionsAgent(BaseAgent):
    """Audit manifest permissions against a sensitive-permission table."""

    AGENT_ID = "P_005"
    VULN_CLASS = "Excessive Manifest Permission"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        manifest = self._context.manifest or {}
        return bool(manifest.get("permissions"))

    async def analyze(self) -> list[Finding]:
        manifest: dict[str, Any] = self._context.manifest or {}
        declared: set[str] = set(manifest.get("permissions") or [])
        if not declared:
            return []

        findings: list[Finding] = []
        for perm, severity, rationale in _PERMISSION_TABLE:
            if perm not in declared:
                continue
            short = perm.rsplit(".", 1)[-1]
            findings.append(self._make_finding(
                vuln_class=f"Sensitive Permission: {short}",
                severity=severity,
                confidence=0.85 if severity != Severity.INFO else 0.65,
                evidence={
                    "permission": perm,
                    "category": severity.value,
                    "rationale": rationale,
                    "permission_count_declared": len(declared),
                    "static_summary": (
                        f"Manifest declares sensitive permission '{perm}': "
                        f"{rationale}"
                    ),
                },
                dynamic_target={
                    "type": "permission_check",
                    "permission": perm,
                },
                source_tags=[
                    "Android Manifest Permission",
                    "Sensitive Permission",
                ],
                context_factors={
                    "exposure": "Installed-app permission footprint",
                    "controls": "Platform permission dialog or policy review",
                    "impact": rationale,
                    "likelihood": "Medium" if severity != Severity.INFO else "Low",
                },
                severity_rationale=(
                    f"{severity.value.upper()} because the manifest declares "
                    f"{perm}, which expands the runtime privilege footprint: "
                    f"{rationale}. Dynamic verification must confirm the "
                    "permission is present on the installed package before "
                    "the report treats it as runtime evidence."
                ),
                recommendation=(
                    f"Confirm a documented feature requires '{perm}'. "
                    "If the permission was added speculatively or for a "
                    "removed feature, drop it from AndroidManifest.xml — "
                    "every sensitive permission widens the attack surface "
                    "and weakens Play Store / App Store review signals. "
                    "Where possible, switch to a narrower or runtime-"
                    "consent-only equivalent (e.g. ACCESS_COARSE_LOCATION "
                    "in place of FINE)."
                ),
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-1",
            ))
        return findings
