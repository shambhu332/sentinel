"""D_037 — Receiver Wiretaps Sensitive System Broadcasts.

D_020 catches whether the app's *own* dynamic receivers are exposed
across UIDs. This agent looks at the same event stream from the
opposite angle: a receiver listening for sensitive *system*
broadcasts that reveal device-state changes the user has not opted
into surfacing.

The Android broadcast surface still ships several "noisy" actions
that are reachable without a permission gate: ``PHONE_STATE``,
``NEW_OUTGOING_CALL``, ``MEDIA_*``, ``CONNECTIVITY_CHANGE``,
``SCREEN_ON/OFF``, ``USER_PRESENT``, ``ACTION_HEADSET_PLUG``. An
app whose receiver subscribes to a sensitive subset is wiretapping
the device state — useful for ad-attribution / fingerprinting and
sometimes for OTP harvesting (``PHONE_STATE`` plus number).

Detection
---------

We re-consume the ``receiver.dynamic_registered`` event already
emitted by the D_020 / D_021 / D_022 registration hook. No new
Frida hook required. Payload fields used:

* ``receiver_class`` — the calling subclass.
* ``actions`` — the IntentFilter's action list.
* ``permission`` — the permission String passed to registerReceiver
  (empty when unset).

Severity matrix:

* **HIGH** — ``actions`` includes any of the
  ``_SURVEILLANCE_ACTIONS`` set (PHONE_STATE, NEW_OUTGOING_CALL,
  ACTION_HEADSET_PLUG, USER_PRESENT, ACTION_DREAMING_STARTED) AND
  ``permission`` is empty.
* **MEDIUM** — three or more distinct broad-system actions on a
  single receiver class with no permission gate (broad
  device-state telemetry shape).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_SURVEILLANCE_ACTIONS = frozenset({
    "android.intent.action.PHONE_STATE",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.HEADSET_PLUG",
    "android.intent.action.USER_PRESENT",
    "android.service.dreams.DreamService.DREAMING_STARTED",
    "android.intent.action.DREAMING_STARTED",
    "android.intent.action.ANSWER",
    "android.intent.action.CALL_BUTTON",
})

_BROAD_SYSTEM_PREFIXES = (
    "android.intent.action.",
    "android.net.conn.",
    "android.media.",
    "android.os.action.",
    "android.bluetooth.",
)

_BROAD_THRESHOLD = 3


class BroadcastWiretapAgent(BaseAgent):
    """D_037: catch receivers listening to surveillance-grade broadcasts."""

    AGENT_ID = "D_037"
    VULN_CLASS = "Receiver Wiretaps Sensitive System Broadcasts"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_037] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        surveillance_hits: list[dict[str, Any]] = []
        broad_actions: dict[str, set[str]] = defaultdict(set)
        broad_samples: dict[str, dict[str, Any]] = {}

        for ev in capture.events:
            if ev.kind != "receiver.dynamic_registered":
                continue
            payload = ev.payload or {}
            actions = list(payload.get("actions") or [])
            permission = str(payload.get("permission") or "")
            receiver = str(payload.get("receiver_class") or "")
            if permission:
                # The dev gated reception — out of scope for D_037.
                continue

            matched_surveillance = [
                a for a in actions if a in _SURVEILLANCE_ACTIONS
            ]
            if matched_surveillance:
                surveillance_hits.append({
                    "receiver_class": receiver[:200],
                    "actions": matched_surveillance,
                    "all_actions": actions[:20],
                    "stack": payload.get("stack"),
                })
                continue

            for action in actions:
                if any(action.startswith(p) for p in _BROAD_SYSTEM_PREFIXES):
                    broad_actions[receiver].add(action)
                    broad_samples.setdefault(receiver, {
                        "receiver_class": receiver[:200],
                        "stack": payload.get("stack"),
                    })

        findings: list[Finding] = []
        if surveillance_hits:
            findings.append(self._surveillance_finding(surveillance_hits))

        broad_hits = [
            {
                **broad_samples[receiver],
                "actions": sorted(broad_actions[receiver])[:10],
            }
            for receiver, acts in broad_actions.items()
            if len(acts) >= _BROAD_THRESHOLD
        ]
        if broad_hits:
            findings.append(self._broad_finding(broad_hits))
        return findings

    def _surveillance_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "A dynamically-registered receiver subscribes to "
                    "system actions that reveal the user's device "
                    "state (PHONE_STATE, NEW_OUTGOING_CALL, "
                    "HEADSET_PLUG, USER_PRESENT, DREAMING_STARTED). "
                    "No permission gate was provided at register "
                    "time, so the registration succeeded silently. "
                    "PHONE_STATE in particular exposes the user's "
                    "current call state and, on older OS levels, "
                    "the incoming number."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Re-consumed receiver.dynamic_registered events "
                    "from the D_020 hook and matched the action "
                    "list against the surveillance set."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop the surveillance subscriptions or move them "
                "into the foreground service that genuinely needs "
                "the signal. Tie the registration to an Activity "
                "lifecycle so the wiretap window is bounded by user "
                "interaction."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _broad_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Broad System-Action Telemetry Receiver",
            severity=Severity.MEDIUM,
            confidence=0.60,
            evidence={
                "issue": (
                    "A receiver subscribes to three or more broad "
                    "system actions without any permission gate. "
                    "That is the shape of a device-state telemetry "
                    "consumer (ad attribution, fingerprinting). "
                    "Each individual action may be benign; the "
                    "aggregate is observable behaviour the user did "
                    "not opt into."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Aggregated receiver.dynamic_registered actions "
                    "per receiver class and counted matches against "
                    "android.intent.* / android.net.conn.* / "
                    "android.media.* / android.os.action.* / "
                    "android.bluetooth.* prefixes."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Audit which actions the receiver actually consumes. "
                "Drop the unused ones, and document the retained "
                "set with a comment that names the SDK or feature "
                "depending on each action."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )
