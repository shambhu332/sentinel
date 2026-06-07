"""D_016 — Accessibility / NotificationListener Self-Abuse Observer.

Two of the most dangerous permissions on Android are
``BIND_ACCESSIBILITY_SERVICE`` and ``BIND_NOTIFICATION_LISTENER_SERVICE``.
Both grant the holder a system-wide read (and in the accessibility case
also write) channel over every other application:

* ``AccessibilityService`` receives every window state change, every
  text edit, every click on any application the user has granted it
  access to. It can also *perform* gestures, click buttons, type
  text, and dismiss the system UI. This is the threat model behind
  banking Trojans (Anatsa, Octo, Cerberus) and the canonical
  malware-grade primitive.
* ``NotificationListenerService`` receives every notification posted
  by every other app, with full payload — including the SMS-OTP
  notifications a 2FA flow relies on. This is the canonical OTP
  exfiltration primitive.

The legitimate use cases are real (TalkBack, password managers,
SMS-autofill helpers, accessibility-grade keyboards), but the
runtime *behaviour* tells us which side of the line the app sits on.

Detection
---------

We consume Frida events of kind:

* ``a11y.event_observed`` — emitted whenever the app's own
  ``AccessibilityService.onAccessibilityEvent`` fires. Payload:
  ``{event_type, source_package, source_text_redacted}``.
* ``a11y.action_performed`` — emitted whenever the app's
  ``AccessibilityService.performGlobalAction`` /
  ``AccessibilityNodeInfo.performAction`` fires. Payload:
  ``{action, source_package}``.
* ``notif_listener.notification_received`` — emitted when the
  app's own ``NotificationListenerService.onNotificationPosted``
  fires. Payload: ``{source_package, channel_id, title_redacted,
  text_redacted, has_otp_shape}``.

Findings:

* **CRITICAL** — accessibility ``action_performed`` events targeting
  apps other than the host (input synthesis on a third-party app:
  the canonical banker-trojan primitive).
* **HIGH** — accessibility ``event_observed`` events for source
  packages outside a documented allow-list AND with content text
  observed (passive credential capture).
* **HIGH** — notification-listener events for an SMS / banking
  source package AND the title/text matches OTP / financial
  keywords.
* **MEDIUM** — broad-spectrum a11y observation (event_types covering
  the full ``TYPE_WINDOW_CONTENT_CHANGED`` bitmask).
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Common system / launcher packages we should not count as "third
# party". An accessibility service may legitimately observe its host
# UI and the system UI.
_SYSTEM_PKGS = (
    "android", "com.android.systemui",
    "com.android.settings", "com.google.android.gms",
    "com.android.launcher", "com.google.android.apps.nexuslauncher",
    "com.android.inputmethod", "com.google.android.inputmethod.latin",
)

_OTP_HINT = re.compile(
    r"(?:otp|verification|verif\b|code|2fa|"
    r"login|sign[\- ]?in|reset)",
    re.IGNORECASE,
)
_FINANCIAL_HINT = re.compile(
    r"(?:debited|credited|debit|credit|"
    r"balance|transfer|payment|withdraw)",
    re.IGNORECASE,
)
_SMS_PKGS = (
    "com.android.mms", "com.android.messaging",
    "com.google.android.apps.messaging",
    "com.samsung.android.messaging",
)


def _is_system(pkg: str) -> bool:
    pkg = (pkg or "").lower()
    return any(pkg == s or pkg.startswith(s + ".") for s in _SYSTEM_PKGS)


class AccessibilityAbuseAgent(BaseAgent):
    """D_016: classify accessibility / notification-listener behaviour."""

    AGENT_ID = "D_016"
    VULN_CLASS = "Accessibility / NotificationListener Abuse Pattern"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_016] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        own_pkg = (self._context.manifest or {}).get("package") or ""

        a11y_observe: dict[str, list[dict[str, Any]]] = defaultdict(list)
        a11y_actions: list[dict[str, Any]] = []
        notif_otp_hits: list[dict[str, Any]] = []
        notif_finance_hits: list[dict[str, Any]] = []
        broad_event_types: set[int] = set()

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "a11y.event_observed":
                src = str(payload.get("source_package") or "").lower()
                if not src or src == own_pkg.lower() or _is_system(src):
                    continue
                a11y_observe[src].append({
                    "event_type": payload.get("event_type"),
                    "text": payload.get("source_text_redacted"),
                    "timestamp": ev.timestamp,
                })
                et = payload.get("event_type")
                if isinstance(et, int):
                    broad_event_types.add(et)
            elif ev.kind == "a11y.action_performed":
                src = str(payload.get("source_package") or "").lower()
                if not src or src == own_pkg.lower() or _is_system(src):
                    continue
                a11y_actions.append({
                    "action": payload.get("action"),
                    "source_package": src,
                    "timestamp": ev.timestamp,
                })
            elif ev.kind == "notif_listener.notification_received":
                src = str(payload.get("source_package") or "").lower()
                if not src or src == own_pkg.lower():
                    continue
                title = str(payload.get("title_redacted") or "")
                text = str(payload.get("text_redacted") or "")
                blob = f"{title} {text}"
                has_otp = bool(payload.get("has_otp_shape"))
                if (any(s in src for s in _SMS_PKGS) and
                        (has_otp or _OTP_HINT.search(blob))):
                    notif_otp_hits.append({
                        "source_package": src,
                        "title": title, "text_preview": text,
                        "timestamp": ev.timestamp,
                    })
                if _FINANCIAL_HINT.search(blob):
                    notif_finance_hits.append({
                        "source_package": src,
                        "title": title, "text_preview": text,
                        "timestamp": ev.timestamp,
                    })

        findings: list[Finding] = []
        if a11y_actions:
            findings.append(self._a11y_action_finding(a11y_actions))
        if a11y_observe:
            findings.append(self._a11y_observe_finding(a11y_observe))
        if notif_otp_hits:
            findings.append(self._notif_otp_finding(notif_otp_hits))
        if notif_finance_hits:
            findings.append(self._notif_finance_finding(notif_finance_hits))
        if len(broad_event_types) >= 6:
            findings.append(self._broad_spectrum_finding(
                sorted(broad_event_types),
            ))
        return findings

    def _a11y_action_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Accessibility Input Synthesis Against Third Party",
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "The application's AccessibilityService synthesised "
                    "input events targeting other applications during "
                    "the session. This is the canonical banking-Trojan "
                    "primitive: an attacker overlay couples observation "
                    "with input synthesis to drain another app's "
                    "balance, copy a secret, or dismiss a confirmation."
                ),
                "occurrence_count": len(items),
                "targets": sorted({i["source_package"] for i in items}),
                "samples": items[:5],
                "vector": (
                    "Frida hook on AccessibilityService."
                    "performGlobalAction and AccessibilityNodeInfo."
                    "performAction captured the source package on "
                    "every input synthesis."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If the legitimate feature is solely host-app "
                "automation, restrict the AccessibilityService "
                "filter to ``com.your.package`` in the configuration "
                "XML and never call performAction on a node whose "
                "packageName differs. If the feature genuinely needs "
                "cross-app input (password manager, screen reader), "
                "ship a Play Store privacy disclosure declaring the "
                "behaviour and require an explicit per-target user "
                "grant gate."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        )

    def _a11y_observe_finding(
        self,
        groups: dict[str, list[dict[str, Any]]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Accessibility Observation Across Third-Party Apps",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application's AccessibilityService received "
                    "events from packages other than its own and the "
                    "system UI during the session. Every observed "
                    "AccessibilityEvent surfaces the visible text "
                    "and the focused field of the third-party app — "
                    "passive credential capture is trivial."
                ),
                "observed_packages": sorted(groups.keys()),
                "occurrence_count": sum(len(v) for v in groups.values()),
                "samples_by_package": {
                    p: events[:3] for p, events in groups.items()
                },
                "vector": (
                    "Frida hook on AccessibilityService."
                    "onAccessibilityEvent captured every event with "
                    "the source package; system and host packages "
                    "are filtered out."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Set the ``android:packageNames`` attribute on the "
                "<accessibility-service> configuration XML to a "
                "single-element allow-list (your own package) so "
                "the service does not receive events from any other "
                "app. If you genuinely need cross-app observation, "
                "minimise the captured fields (use "
                "FLAG_REQUEST_FILTER_KEY_EVENTS, not "
                "FLAG_RETRIEVE_INTERACTIVE_WINDOWS) and audit every "
                "captured value against your privacy policy."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        )

    def _notif_otp_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="NotificationListener OTP Exfiltration Surface",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application's NotificationListenerService "
                    "received notifications from the SMS / messaging "
                    "package whose content matched OTP / verification "
                    "keywords. This is the canonical SMS-OTP "
                    "exfiltration primitive used by banking Trojans "
                    "to silently capture 2FA codes."
                ),
                "occurrence_count": len(items),
                "samples": items[:5],
                "vector": (
                    "Frida hook on NotificationListenerService."
                    "onNotificationPosted filtered for SMS package "
                    "source with OTP-shaped or keyword content."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Filter the listener to the host package's own "
                "notifications. Never persist or forward SMS-source "
                "notification content. If the legitimate use case is "
                "SMS-autofill, migrate to the SMS Retriever API "
                "(android.gms.auth.api.phone) which delivers a single "
                "scoped OTP without granting broad notification-"
                "listener access."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _notif_finance_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="NotificationListener Captures Financial Activity",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "The NotificationListenerService captured "
                    "notifications whose content matched financial "
                    "keywords (debited / credited / balance / "
                    "transfer / payment / withdraw). The app now has "
                    "visibility into the user's transaction stream "
                    "across other banking apps."
                ),
                "occurrence_count": len(items),
                "samples": items[:5],
                "vector": (
                    "Frida hook on NotificationListenerService."
                    "onNotificationPosted; non-host notifications "
                    "scanned against the financial keyword regex."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Filter the listener to the host package or drop "
                "the use-case entirely. If the feature really needs "
                "transaction visibility (an aggregator app), confirm "
                "the privacy policy discloses the scope and require "
                "an explicit per-source-app user grant."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )

    def _broad_spectrum_finding(
        self, types: list[int],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Broad-Spectrum AccessibilityService Event Mask",
            severity=Severity.MEDIUM,
            confidence=0.70,
            evidence={
                "issue": (
                    "The AccessibilityService observed at least six "
                    "distinct AccessibilityEvent types during the "
                    "session, indicating an unconstrained "
                    "``eventTypes`` configuration. Narrower masks are "
                    "preferred — a service that only needs window-"
                    "title changes should not receive view-text-"
                    "selection events."
                ),
                "event_types_observed": types,
                "vector": (
                    "Frida hook on AccessibilityService."
                    "onAccessibilityEvent collected unique "
                    "event-type integers."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "In the <accessibility-service> configuration XML, "
                "set ``android:accessibilityEventTypes`` to only the "
                "specific bits the feature needs (e.g. "
                "``typeWindowStateChanged|typeViewClicked``) rather "
                "than ``typeAllMask``. Document each bit in a "
                "comment so the next reviewer understands the "
                "intent."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        )
