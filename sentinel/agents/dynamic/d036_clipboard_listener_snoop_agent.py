"""D_036 — Clipboard Snooping via PrimaryClipChangedListener.

Android 10+ restricts ``ClipboardManager.getPrimaryClip`` /
``hasPrimaryClipDescription`` to processes that have *current input
method focus* or hold the keyboard. The runtime check is enforced
inside the system clipboard service, but apps still get away with
silent clipboard reads in two ways:

1. Registering ``addPrimaryClipChangedListener`` from a Service
   that briefly becomes foreground (the listener fires later from
   the background).
2. Calling ``getPrimaryClip`` from an accessibility/keyboard
   service whose foreground status is granted by virtue of the
   service type itself.

Detection
---------

We consume one Frida event kind:

* ``clipboard.read_observed`` — emitted from
  ``ClipboardManager.getPrimaryClip`` /
  ``getPrimaryClipDescription`` /
  ``addPrimaryClipChangedListener``. Payload:
  ``{api, caller_class, importance, content_shape, stack}``.

``importance`` is ``ActivityManager.RunningAppProcessInfo
.importance`` at call time. ``content_shape`` is a coarse label
(``empty``, ``short``, ``otp_like``, ``url``, ``credit_card``,
``arbitrary``) computed from the clip data.

Severity matrix:

* **HIGH** — ``api`` is ``getPrimaryClip`` and ``importance`` is
  >= ``IMPORTANCE_SERVICE`` (300). Background clipboard read,
  forbidden in spirit by Android 10+.
* **HIGH** — ``api`` is ``addPrimaryClipChangedListener`` from a
  background caller — the listener will fire from background
  state and the caller knows it.
* **MEDIUM** — ``getPrimaryClip`` returned an ``otp_like`` or
  ``credit_card`` shape at any importance.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


IMPORTANCE_SERVICE = 300
_SENSITIVE_SHAPES = frozenset({"otp_like", "credit_card"})


class ClipboardListenerSnoopAgent(BaseAgent):
    """D_036: catch background clipboard reads / listener snoops."""

    AGENT_ID = "D_036"
    VULN_CLASS = "Background Clipboard Read"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_036] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        background_read_hits: list[dict[str, Any]] = []
        background_listener_hits: list[dict[str, Any]] = []
        sensitive_shape_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "clipboard.read_observed":
                continue
            payload = ev.payload or {}
            api = str(payload.get("api") or "")
            importance = _coerce_int(payload.get("importance"))
            shape = str(payload.get("content_shape") or "")
            sample = {
                "api": api,
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "importance": importance,
                "content_shape": shape,
                "stack": payload.get("stack"),
            }

            if api == "getPrimaryClip" \
                    and importance is not None \
                    and importance >= IMPORTANCE_SERVICE:
                background_read_hits.append(sample)
                continue
            if api == "addPrimaryClipChangedListener" \
                    and importance is not None \
                    and importance >= IMPORTANCE_SERVICE:
                background_listener_hits.append(sample)
                continue
            if shape in _SENSITIVE_SHAPES:
                sensitive_shape_hits.append(sample)

        findings: list[Finding] = []
        if background_read_hits:
            findings.append(self._background_read_finding(background_read_hits))
        if background_listener_hits:
            findings.append(
                self._background_listener_finding(background_listener_hits),
            )
        if sensitive_shape_hits:
            findings.append(self._sensitive_shape_finding(sensitive_shape_hits))
        return findings

    def _background_read_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "ClipboardManager.getPrimaryClip returned a non-"
                    "empty payload while the process importance was "
                    "below IMPORTANCE_FOREGROUND_SERVICE. The user "
                    "had no UI affordance tying the read to their "
                    "action — the textbook clipboard-snoop "
                    "primitive."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on ClipboardManager.getPrimaryClip "
                    "captured ActivityManager.RunningAppProcessInfo."
                    "importance at the moment of the read."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Restrict clipboard reads to code paths driven by a "
                "user gesture in a foreground Activity. Reject the "
                "read from any Service or BroadcastReceiver code "
                "path."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _background_listener_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Clipboard Listener Registered from Background",
            severity=Severity.HIGH,
            confidence=0.78,
            evidence={
                "issue": (
                    "addPrimaryClipChangedListener was called from a "
                    "code path whose process importance was at "
                    "IMPORTANCE_SERVICE or below. The listener will "
                    "subsequently fire while the app is in the "
                    "background, defeating the OS foreground-only "
                    "clipboard contract."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on addPrimaryClipChangedListener "
                    "captured the calling-process importance."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Tie listener registration to an Activity lifecycle "
                "and call removePrimaryClipChangedListener on stop."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _sensitive_shape_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Clipboard Read Returned Sensitive-Shape Content",
            severity=Severity.MEDIUM,
            confidence=0.60,
            evidence={
                "issue": (
                    "getPrimaryClip returned content whose shape "
                    "matches an OTP or PAN. Even if the read itself "
                    "is foreground-gated, the value should not be "
                    "logged or persisted by the receiving code path."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook regex-classified the clip-data "
                    "content."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Mask sensitive shapes inside the listener / handler "
                "and clear the clipboard after consumption with "
                "ClipboardManager.clearPrimaryClip (API 28+)."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
