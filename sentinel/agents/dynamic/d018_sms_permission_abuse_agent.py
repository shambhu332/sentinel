"""D_018 — SMS Permission / Retriever-API Abuse.

Android has three escalating ways to receive SMS contents:

1. **SMS Retriever API** (``com.google.android.gms.auth.api.phone``)
   — the modern, scoped path. The sender computes an 11-character app
   hash and includes it in the message; only the matching APK
   receives the SMS body, and only the one matching message. No
   user permission, no broad read.

2. **SMS User Consent API** — middle path. Shows the user a
   per-message consent prompt; the app receives a single SMS body
   for a limited window.

3. **READ_SMS / RECEIVE_SMS broad permissions** — the historical
   path. The app receives *every* SMS on the device, including
   the user's bank OTPs, their family's messages, two-factor codes
   for *other* applications, password-reset links, etc. Google Play
   policy restricts this permission to apps whose core function
   is SMS (messaging apps, OTP backup tools); other use cases are
   policy violations and a privacy breach class.

Detection
---------

We consume Frida events:

* ``sms.broadcast_received`` — emitted whenever a
  ``BroadcastReceiver`` of action ``android.provider.Telephony.
  SMS_RECEIVED`` or ``WAP_PUSH_RECEIVED`` fires inside the app.
  Payload: ``{sender, body_redacted, has_otp_shape, source_method}``.
* ``sms.content_provider_query`` — emitted on
  ``ContentResolver.query`` against ``content://sms/*``.
* ``sms.retriever_started`` — emitted on
  ``SmsRetrieverClient.startSmsRetriever`` /
  ``SmsRetrieverClient.startSmsUserConsent``.

Findings:

* **HIGH** — broadcast receiver fires for an SMS message that
  *doesn't* match the app's own SMS-Retriever hash AND the app
  also never called ``startSmsRetriever`` — the app is using the
  broad permission instead of the scoped API. If we observe both
  retriever calls AND broadcast receives, the broadcast intake is
  redundant and still receives every other app's traffic.
* **HIGH** — ``ContentResolver.query`` against ``content://sms/*``
  observed (deep scan of the SMS inbox).
* **MEDIUM** — broadcast receiver fires but the app *did* invoke
  the retriever API. Coverage is overlapping; the broadcast path
  should be removed.
* **INFO-class skipped** — the app uses only the SMS Retriever
  API: no finding.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_OTP_SHAPE = re.compile(r"(?<!\d)\d{4,8}(?!\d)")


class SmsPermissionAbuseAgent(BaseAgent):
    """D_018: classify SMS-read pattern usage at runtime."""

    AGENT_ID = "D_018"
    VULN_CLASS = "SMS Permission / Retriever-API Abuse"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_018] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        broadcasts: list[dict[str, Any]] = []
        provider_queries: list[dict[str, Any]] = []
        retriever_calls: list[dict[str, Any]] = []

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "sms.broadcast_received":
                broadcasts.append({
                    "sender": payload.get("sender"),
                    "body": payload.get("body_redacted"),
                    "has_otp": bool(payload.get("has_otp_shape")),
                    "source_method": payload.get("source_method"),
                    "timestamp": ev.timestamp,
                })
            elif ev.kind == "sms.content_provider_query":
                provider_queries.append({
                    "uri": payload.get("uri"),
                    "stack": payload.get("stack"),
                    "timestamp": ev.timestamp,
                })
            elif ev.kind == "sms.retriever_started":
                retriever_calls.append({
                    "api": payload.get("api"),
                    "timestamp": ev.timestamp,
                })

        findings: list[Finding] = []

        if provider_queries:
            findings.append(self._inbox_scan_finding(provider_queries))

        if broadcasts:
            if not retriever_calls:
                findings.append(self._broad_perm_finding(broadcasts))
            else:
                findings.append(self._overlapping_finding(
                    broadcasts, retriever_calls,
                ))

        return findings

    def _inbox_scan_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="SMS Inbox Deep Scan via ContentResolver",
            severity=Severity.HIGH,
            confidence=0.95,
            evidence={
                "issue": (
                    "The application queried ``content://sms/*`` at "
                    "runtime — a deep scan of the device's SMS inbox. "
                    "This goes far beyond receiving a single OTP: "
                    "every message ever stored, including bank "
                    "alerts, two-factor codes for OTHER apps, and "
                    "personal correspondence, is now machine-readable "
                    "to the application."
                ),
                "occurrence_count": len(items),
                "samples": items[:5],
                "vector": (
                    "Frida hook on ContentResolver.query captured "
                    "the URI when it pointed at content://sms / "
                    "content://sms/inbox / content://mms-sms."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Migrate to the SMS Retriever API "
                "(``SmsRetrieverClient.startSmsRetriever``) — it "
                "delivers a single, scoped, app-hash-bound OTP "
                "without any user-visible permission grant. Drop "
                "``READ_SMS`` from the manifest. If the legitimate "
                "use case is genuinely a messaging app, declare it "
                "as the default SMS handler so Google Play policy "
                "review accepts the permission."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _broad_perm_finding(
        self, broadcasts: list[dict[str, Any]],
    ) -> Finding:
        otp_count = sum(1 for b in broadcasts if b["has_otp"])
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application receives the SMS_RECEIVED "
                    "broadcast at runtime AND never invoked the SMS "
                    "Retriever / User-Consent API during the "
                    "session. The app is on the broad-permission "
                    "(``RECEIVE_SMS`` / ``READ_SMS``) path — it "
                    "receives every SMS on the device, including "
                    "OTPs for other apps and the user's personal "
                    "messages."
                ),
                "broadcast_count": len(broadcasts),
                "otp_shaped_count": otp_count,
                "samples": broadcasts[:5],
                "vector": (
                    "Frida hook on BroadcastReceiver.onReceive "
                    "filtered for the SMS_RECEIVED action; no "
                    "SmsRetrieverClient call observed in the same "
                    "session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Migrate to the SMS Retriever API: "
                "(1) compute the app's 11-character hash with "
                "``AppSignatureHelper`` and include it in the OTP "
                "SMS template, (2) call "
                "``SmsRetriever.getClient(this).startSmsRetriever()`` "
                "to register for one scoped delivery, (3) remove "
                "``RECEIVE_SMS`` / ``READ_SMS`` from the manifest. "
                "The Retriever API works on all Google-Play devices "
                "since 2017 and is the only path Google Play policy "
                "approves for non-default-SMS apps."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _overlapping_finding(
        self,
        broadcasts: list[dict[str, Any]],
        retrievers: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Overlapping SMS Intake (Retriever + Broadcast)",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application uses the SMS Retriever API "
                    "AND also receives the SMS_RECEIVED broadcast. "
                    "The broadcast path is redundant once the "
                    "Retriever is in place, and it carries the "
                    "broad-permission cost (every SMS on the device, "
                    "regardless of sender). Remove the broadcast "
                    "intake and the ``RECEIVE_SMS`` permission."
                ),
                "broadcast_count": len(broadcasts),
                "retriever_count": len(retrievers),
                "retriever_apis": sorted({
                    r["api"] for r in retrievers if r.get("api")
                }),
                "samples": broadcasts[:5],
                "vector": (
                    "Frida hooks observed both BroadcastReceiver."
                    "onReceive for SMS_RECEIVED and "
                    "SmsRetrieverClient.startSmsRetriever in the "
                    "same session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Delete the BroadcastReceiver intended for SMS "
                "intake. Remove ``RECEIVE_SMS`` and ``READ_SMS`` "
                "from the manifest. Rely solely on the Retriever "
                "delivery; the user-visible permission grant "
                "disappears with it."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )
