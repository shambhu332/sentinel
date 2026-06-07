"""D_012 — Sensitive Notification Content on the Lockscreen.

Android notifications are visible on the lockscreen by default. The
default visibility is ``VISIBILITY_PUBLIC`` for notifications posted
on a channel of importance ≥ ``IMPORTANCE_DEFAULT``, and the heads-up
preview shows the full ``setContentText`` / ``setBigText`` value
above the keyguard with zero user authentication.

The bug class: banking, auth, and messaging apps push the user's
verification code, balance, transfer summary, or message preview
directly into the notification text. Anyone with sight of the locked
device — over-the-shoulder, an evil maid, a roommate, a passing
gaze in transit — reads the secret without unlocking the device.

Per Android documentation:
* ``NotificationCompat.Builder.setVisibility(VISIBILITY_PRIVATE)``
  hides the content text on the lockscreen until the user unlocks,
  showing only the app name and a public stand-in line provided via
  ``setPublicVersion``.
* ``VISIBILITY_SECRET`` hides the notification entirely on the
  lockscreen.

Detection
---------

We consume Frida events of kind ``notification.posted``. Each payload
captures one ``NotificationManager.notify`` invocation with:

* ``channel_id`` / ``channel_importance``
* ``visibility``    — the int passed to ``setVisibility`` (or default)
* ``has_public_version`` — bool, whether ``setPublicVersion`` was
  attached
* ``title`` / ``text`` — the strings observed; truncated and
  redacted before logging
* ``stack`` — caller stack

Findings:

* **HIGH** — visibility is ``VISIBILITY_PUBLIC`` (1) or the default
  for default+ importance, AND the title / text matches a credential
  keyword (``otp``, ``code``, ``verification``, ``transfer``,
  ``balance``, ``debited``, ``credited``, ``credit``, ``debit``,
  ``passcode``, ``pin``).
* **MEDIUM** — visibility is ``VISIBILITY_PUBLIC`` AND the title /
  text contains a numeric run 4–8 digits long (OTP-shaped) even
  without the keyword match.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_VISIBILITY_PUBLIC = 1
_VISIBILITY_PRIVATE = 0
_VISIBILITY_SECRET = -1
_IMPORTANCE_DEFAULT = 3

_CREDENTIAL_HINT = re.compile(
    r"\b(?:otp|code|verification|verify|transfer|balance|debited|"
    r"credited|credit|debit|passcode|pin|reset|"
    r"login|signin|2fa)\b",
    re.IGNORECASE,
)
_OTP_SHAPED = re.compile(r"(?<!\d)\d{4,8}(?!\d)")


class NotificationLeakAgent(BaseAgent):
    """D_012: detect lockscreen-visible notifications carrying secrets."""

    AGENT_ID = "D_012"
    VULN_CLASS = "Sensitive Lockscreen Notification"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_012] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        credential_hits: list[dict[str, Any]] = []
        otp_shaped_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "notification.posted":
                continue
            payload = ev.payload or {}
            if not self._is_lockscreen_visible(payload):
                continue

            title = str(payload.get("title") or "")
            text = str(payload.get("text") or "")
            combined = f"{title}\n{text}"

            sample = {
                "channel_id": payload.get("channel_id"),
                "channel_importance": payload.get("channel_importance"),
                "visibility": payload.get("visibility"),
                "has_public_version": bool(payload.get("has_public_version")),
                "title_preview": _redact(title),
                "text_preview": _redact(text),
                "stack": payload.get("stack"),
                "timestamp": ev.timestamp,
            }

            if _CREDENTIAL_HINT.search(combined):
                credential_hits.append(sample)
            elif _OTP_SHAPED.search(text):
                otp_shaped_hits.append(sample)

        findings: list[Finding] = []
        if credential_hits:
            findings.append(self._credential_finding(credential_hits))
        if otp_shaped_hits:
            findings.append(self._otp_shaped_finding(otp_shaped_hits))
        return findings

    @staticmethod
    def _is_lockscreen_visible(payload: dict[str, Any]) -> bool:
        visibility = payload.get("visibility")
        # Explicit non-public visibility is the safe path.
        if visibility in (_VISIBILITY_PRIVATE, _VISIBILITY_SECRET):
            return False
        # VISIBILITY_PUBLIC (1) or absent + importance ≥ DEFAULT.
        if visibility == _VISIBILITY_PUBLIC:
            return True
        importance = payload.get("channel_importance")
        if isinstance(importance, int) and importance >= _IMPORTANCE_DEFAULT:
            return True
        return False

    def _credential_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application posted a notification whose "
                    "title or body contains credential / financial "
                    "keywords (OTP, verification code, balance, "
                    "transfer summary, etc.) while the notification "
                    "is visible on the lockscreen. Anyone with sight "
                    "of the locked device reads the value without "
                    "unlocking — including over-the-shoulder views "
                    "and the long-running heads-up preview."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on NotificationManager.notify and "
                    "NotificationCompat.Builder.build captured the "
                    "posted Notification with its visibility and "
                    "extracted content text. Channel importance "
                    "pulled via NotificationManager.getNotificationChannel."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Call setVisibility(NotificationCompat.VISIBILITY_PRIVATE) "
                "on the Builder and provide a generic public stand-in "
                "via setPublicVersion(..) — e.g. 'You have a new "
                "message' / 'Verification code ready'. For high-"
                "sensitivity content (banking transactions, security "
                "alerts) use VISIBILITY_SECRET so the notification "
                "is suppressed on the lockscreen entirely. Never "
                "embed an OTP, balance, or full message preview into "
                "the content text of a default-visibility "
                "notification."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-9",
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _otp_shaped_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Numeric OTP-Shaped Notification Content",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence={
                "issue": (
                    "A lockscreen-visible notification contains a "
                    "4-to-8-digit numeric run without an associated "
                    "credential keyword. The shape matches an OTP / "
                    "one-time code; manual review should confirm "
                    "whether the value is sensitive."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on NotificationManager.notify "
                    "captured the posted Notification; body regex "
                    "match against the canonical OTP shape."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If the numeric value is a delivery / order / "
                "tracking number, it is fine — leave the notification "
                "as-is. If it is an OTP, security code, or numeric "
                "passcode, move to setVisibility(VISIBILITY_PRIVATE) "
                "with a generic public stand-in."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-9",
            cvss_vector="CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )


def _redact(value: Any) -> str:
    """Show at most the first 4 and last 2 characters of any value
    we propagate into the finding evidence."""
    s = str(value or "")
    if not s:
        return ""
    if len(s) <= 8:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-2:]} (len={len(s)})"
