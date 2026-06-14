"""D_002 — Missing FLAG_SECURE on Sensitive Screens.

Activities that display passwords, OTPs, PINs, recovery phrases, or
PII should call ``Window.setFlags(FLAG_SECURE, FLAG_SECURE)`` (or use
``android:windowFlagSecure`` on Android 13+). The flag does three
things:

* Blocks the screen from appearing in the system Recents thumbnail.
* Blocks accessibility services from screen-recording the contents.
* Blocks ``MediaProjection`` (third-party screen recorders).

Without it, any accessibility service the user has enabled (or any
foreground screen recorder), and the system Recents preview itself,
can leak the credential. This is the canonical mobile-banking finding.

Detection
---------

We consume two Frida event kinds:

* ``ui.sensitive_input_seen`` — emitted by the hook when an
  ``EditText`` with input type
  ``TYPE_TEXT_VARIATION_PASSWORD`` / ``TYPE_NUMBER_VARIATION_PASSWORD``
  / ``TYPE_TEXT_VARIATION_VISIBLE_PASSWORD`` is added to a Window.
  Payload: ``{"activity": "fqcn", "field": "id_or_hint"}``.

* ``ui.window_flags`` — emitted whenever ``Window.setFlags`` /
  ``addFlags`` / ``clearFlags`` runs, with the resulting flag set.
  Payload: ``{"activity": "fqcn", "flags": int, "secure": bool}``.

Logic: for every activity that emitted a ``ui.sensitive_input_seen``
event but never an accompanying ``ui.window_flags`` with
``secure == True``, raise a HIGH finding. If the same activity later
shows ``secure == True`` we suppress.
"""
from __future__ import annotations

import logging

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class FlagSecureMissingAgent(BaseAgent):
    """D_002: flag activities that show secrets without FLAG_SECURE."""

    AGENT_ID = "D_002"
    VULN_CLASS = "Missing FLAG_SECURE on Sensitive Screen"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_002] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # Map activity FQCN → set of sensitive field hints seen.
        sensitive_inputs: dict[str, set[str]] = {}
        # Map activity FQCN → True if FLAG_SECURE ever set.
        secured: dict[str, bool] = {}

        for ev in capture.events:
            payload = ev.payload or {}
            activity = str(payload.get("activity") or "").strip()
            if not activity:
                continue
            if ev.kind == "ui.sensitive_input_seen":
                field = str(payload.get("field") or "<unnamed>")
                sensitive_inputs.setdefault(activity, set()).add(field)
            elif ev.kind == "ui.window_flags":
                if bool(payload.get("secure")):
                    secured[activity] = True
                else:
                    # An explicit setFlags without FLAG_SECURE is not
                    # in itself a "secured" signal — only set the flag
                    # when we observe FLAG_SECURE present.
                    secured.setdefault(activity, False)

        offenders = [
            (act, sorted(fields))
            for act, fields in sensitive_inputs.items()
            if not secured.get(act)
        ]
        if not offenders:
            return []

        findings: list[Finding] = []
        for activity, fields in offenders:
            findings.append(self._finding(activity, fields))
        return findings

    def _finding(self, activity: str, fields: list[str]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The activity displays password / PIN / OTP-style "
                    "input but did not set "
                    "WindowManager.LayoutParams.FLAG_SECURE on its "
                    "Window. The credential is visible to the system "
                    "Recents preview, MediaProjection-based screen "
                    "recorders, and accessibility services."
                ),
                "activity": activity,
                "sensitive_fields": fields,
                "vector": (
                    "Frida hooks on EditText input-type changes and on "
                    "Window.setFlags / addFlags captured the activity "
                    "exposing sensitive input without ever asserting "
                    "FLAG_SECURE during the session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Call getWindow().setFlags("
                "WindowManager.LayoutParams.FLAG_SECURE, "
                "WindowManager.LayoutParams.FLAG_SECURE) in onCreate() "
                "before setContentView(), or set "
                "android:windowFlagSecure=\"true\" in the activity theme "
                "(Android 13+). Verify with `adb shell dumpsys window "
                "windows | grep -i secure` that the active window "
                "reports FLAG_SECURE."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-STORAGE-9",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        )
