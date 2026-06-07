"""D_020 — Dynamically-Registered Receiver Exported By Default.

Android 14 (API 34) introduced a security gate on
``Context.registerReceiver``: any app targeting SDK 34+ must explicitly
pass ``RECEIVER_EXPORTED`` or ``RECEIVER_NOT_EXPORTED`` for any filter
that includes an unprotected action. The historical *implicit* default
behaviour — "exported when the app targets API 33 or lower" — silently
exposes every dynamically-registered receiver to every other app on
the device, with the receiver's intent extras becoming attacker-
controllable.

Static AndroidManifest.xml audits don't catch this — the receiver is
registered at runtime via Java code, often inside a factory or a
delegated service binder. Frida is the only reliable detector.

Detection
---------

We consume Frida events of kind ``receiver.dynamic_registered``. Each
payload describes one ``registerReceiver`` call:

* ``receiver_class`` — FQCN of the receiver instance.
* ``actions`` — list of action strings on the IntentFilter.
* ``flags`` — int flag-set passed to the API (``RECEIVER_EXPORTED``
  = 0x2, ``RECEIVER_NOT_EXPORTED`` = 0x4).
* ``has_explicit_export`` — bool, True if either flag is set.
* ``permission`` — optional receiver-side permission string.
* ``stack`` — caller stack.

Classification:

* **HIGH** — no explicit export flag (``has_explicit_export=False``)
  AND no permission gate. Implicit-export path on Android <14; on
  Android 14+ the OS throws SecurityException at runtime — but we
  still flag because a downgrade to a lower targetSdk re-exposes
  the surface.
* **MEDIUM** — explicit ``RECEIVER_EXPORTED`` AND no permission AND
  the action set is a custom (non-system) action — the developer
  deliberately exported a custom-action receiver to every app.
* **No finding** — ``RECEIVER_NOT_EXPORTED``, OR a permission gate
  was set, OR every action is a system-protected one (sticky
  battery / connectivity broadcasts the OS gates separately).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_SYSTEM_PROTECTED_ACTIONS = (
    "android.intent.action.BATTERY_CHANGED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.TIME_TICK",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.CONFIGURATION_CHANGED",
)
_RECEIVER_EXPORTED = 0x2
_RECEIVER_NOT_EXPORTED = 0x4


class DynamicReceiverExportAgent(BaseAgent):
    """D_020: detect runtime receiver registrations without export flag."""

    AGENT_ID = "D_020"
    VULN_CLASS = "Dynamically-Registered Receiver Implicit Export"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_020] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        implicit_hits: list[dict[str, Any]] = []
        custom_exported_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "receiver.dynamic_registered":
                continue
            payload = ev.payload or {}
            verdict = self._classify(payload)
            if verdict == "implicit":
                implicit_hits.append(_sample(payload))
            elif verdict == "custom_exported":
                custom_exported_hits.append(_sample(payload))

        findings: list[Finding] = []
        if implicit_hits:
            findings.append(self._implicit_finding(implicit_hits))
        if custom_exported_hits:
            findings.append(self._custom_exported_finding(
                custom_exported_hits,
            ))
        return findings

    @staticmethod
    def _classify(payload: dict[str, Any]) -> str | None:
        actions = list(payload.get("actions") or [])
        # All-system-protected filter → not interesting.
        if actions and all(a in _SYSTEM_PROTECTED_ACTIONS for a in actions):
            return None
        flags = int(payload.get("flags") or 0)
        has_explicit = bool(payload.get("has_explicit_export"))
        permission = str(payload.get("permission") or "").strip()

        if flags & _RECEIVER_NOT_EXPORTED:
            return None
        if permission:
            return None
        if not has_explicit:
            return "implicit"
        # has_explicit AND no permission AND not all-system actions
        return "custom_exported"

    def _implicit_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application calls "
                    "``Context.registerReceiver`` at runtime without "
                    "passing ``RECEIVER_EXPORTED`` or "
                    "``RECEIVER_NOT_EXPORTED``, and without setting a "
                    "permission gate. On Android < 14 the receiver is "
                    "silently exported to every other app — its intent "
                    "extras become attacker-controllable, and any "
                    "downstream parsing of those extras runs on "
                    "attacker input. On Android 14+ the OS throws "
                    "SecurityException at runtime; if the build's "
                    "targetSdk is downgraded for any reason, the "
                    "implicit-export path re-opens."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Context.registerReceiver captured "
                    "the call without either RECEIVER_EXPORTED "
                    "(0x2) or RECEIVER_NOT_EXPORTED (0x4) and "
                    "without a permission argument."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Pass ``ContextCompat.RECEIVER_NOT_EXPORTED`` "
                "(or the platform constant on API 33+) as the "
                "``flags`` argument when the receiver is purely for "
                "intra-app use. If the receiver needs to be reachable "
                "from another app, pass ``RECEIVER_EXPORTED`` AND "
                "supply a signature-level permission so only your own "
                "apps can send to it."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        )

    def _custom_exported_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Exported Dynamic Receiver Without Permission",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application explicitly passes "
                    "``RECEIVER_EXPORTED`` to ``registerReceiver`` "
                    "for a custom-action IntentFilter AND does not "
                    "set a permission gate. Any installed app can "
                    "send the action and reach the receiver's "
                    "onReceive — which then runs on whatever Intent "
                    "extras the caller chose."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Context.registerReceiver captured "
                    "RECEIVER_EXPORTED with no permission argument "
                    "on a non-system-protected action."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Add a signature-level permission as the third "
                "argument to ``registerReceiver``. Or — if the "
                "receiver only needs to fire from your own process "
                "— switch to ``RECEIVER_NOT_EXPORTED`` so the "
                "registration becomes purely intra-app."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )


def _sample(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "receiver_class": payload.get("receiver_class"),
        "actions": list(payload.get("actions") or [])[:5],
        "flags": payload.get("flags"),
        "permission": payload.get("permission"),
        "stack": payload.get("stack"),
    }
