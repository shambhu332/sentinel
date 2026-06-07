"""D_021 — PendingIntent Mutable at Runtime.

A ``PendingIntent`` is a capability token: it lets another app fire an
Intent *as your app*. If the inner Intent is mutable, the recipient can
rewrite its component, action, data, or extras before the system
dispatches it. The classic consequence is *Intent redirection* — the
attacker app fills in the previously-blank component and points it at
one of your private (`exported=false`) components, exfiltrating
private state.

Android 12 (API 31) added a hard runtime check: any
``PendingIntent.getActivity / getBroadcast / getService`` call without
either ``FLAG_IMMUTABLE`` or ``FLAG_MUTABLE`` throws
``IllegalArgumentException``. Apps targeting earlier SDKs are still
allowed to omit the flag, in which case the system defaults to
*mutable* on Android 6–11 and *immutable* on Android 12+. Apps that
explicitly set ``FLAG_MUTABLE`` (often added by lint-fixing tools that
"just made the compile-error go away") expose the same surface on
modern Android.

Static analysis catches the obvious ``PendingIntent.getActivity(..,
FLAG_MUTABLE)`` call. Frida is the only way to catch the cases hidden
inside libraries (notification builders, work-manager jobs, dynamic
shortcut builders) and the cases where the constant is computed from
runtime state.

Detection
---------

We consume Frida events of kind ``pending_intent.created``. Each
payload describes one PendingIntent factory invocation:

* ``factory`` — getActivity / getBroadcast / getService / getActivities
* ``flags`` — int flag-set passed to the API.
* ``intent_has_component`` — bool, True if the inner Intent has an
  explicit component name.
* ``intent_action`` — action string, if any.
* ``stack`` — caller stack.

Classification:

* **CRITICAL** — ``FLAG_MUTABLE`` set AND the inner Intent does not
  carry an explicit component (the component is blank, so the
  recipient can fill it in and redirect to anything). This is the
  textbook Intent-redirection setup.
* **HIGH** — ``FLAG_MUTABLE`` set but the Intent has a component.
  The recipient can still rewrite ``extras`` (often credentials),
  ``data`` (URI), and ``action``.
* **MEDIUM** — neither ``FLAG_IMMUTABLE`` nor ``FLAG_MUTABLE`` set.
  On API < 31 the OS defaults to mutable; on API 31+ a runtime
  exception fires. Either way the developer hasn't asserted the
  intent.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_FLAG_IMMUTABLE = 0x04000000
_FLAG_MUTABLE = 0x02000000


class PendingIntentMutableAgent(BaseAgent):
    """D_021: detect runtime PendingIntent factory calls with FLAG_MUTABLE."""

    AGENT_ID = "D_021"
    VULN_CLASS = "PendingIntent Mutable at Runtime"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_021] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        mutable_no_component: list[dict[str, Any]] = []
        mutable_with_component: list[dict[str, Any]] = []
        unspecified: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "pending_intent.created":
                continue
            payload = ev.payload or {}
            flags = int(payload.get("flags") or 0)
            sample = _sample(payload)
            if flags & _FLAG_MUTABLE:
                if bool(payload.get("intent_has_component")):
                    mutable_with_component.append(sample)
                else:
                    mutable_no_component.append(sample)
            elif not (flags & _FLAG_IMMUTABLE):
                unspecified.append(sample)

        findings: list[Finding] = []
        if mutable_no_component:
            findings.append(self._redirect_finding(mutable_no_component))
        if mutable_with_component:
            findings.append(self._mutable_finding(mutable_with_component))
        if unspecified:
            findings.append(self._unspecified_finding(unspecified))
        return findings

    def _redirect_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="PendingIntent Redirection (Mutable + No Component)",
            severity=Severity.CRITICAL,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application creates a PendingIntent with "
                    "``FLAG_MUTABLE`` set AND the inner Intent has no "
                    "explicit component name. The recipient of this "
                    "token can fill in the component before the "
                    "system dispatches it, re-targeting it at any of "
                    "the app's private (``exported=false``) "
                    "components. This is the canonical Intent-"
                    "redirection setup (CVE-2020-0096 family)."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on PendingIntent.getActivity / "
                    "getBroadcast / getService captured FLAG_MUTABLE "
                    "on an Intent whose getComponent() was null."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Pass ``PendingIntent.FLAG_IMMUTABLE`` instead. Where "
                "Android 6+ requires updateable extras (notification "
                "actions, replyable RemoteInputs), wrap the inner "
                "Intent with an explicit component first: "
                "``intent.setClass(this, MyReceiver.class)``."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        )

    def _mutable_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="PendingIntent Mutable With Component",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application creates a PendingIntent with "
                    "``FLAG_MUTABLE`` set. The recipient can rewrite "
                    "the inner Intent's ``extras``, ``data``, and "
                    "``action`` before dispatch — useful for the "
                    "RemoteInput / Notification reply UX, but a "
                    "leak surface when the receiver is in your app "
                    "and trusts those fields."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on PendingIntent.* factories captured "
                    "FLAG_MUTABLE on an Intent with an explicit "
                    "component."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Use FLAG_IMMUTABLE unless the legitimate UX strictly "
                "requires mutability (RemoteInput, "
                "Notification.Action). For RemoteInput use the "
                "narrowest mutable surface: keep the action and "
                "component fixed and validate every extra key the "
                "receiver consumes."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _unspecified_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="PendingIntent Mutability Unspecified",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence={
                "issue": (
                    "The application creates a PendingIntent without "
                    "either ``FLAG_IMMUTABLE`` or ``FLAG_MUTABLE``. "
                    "On Android 6–11 this defaults to mutable; on "
                    "Android 12+ the runtime throws "
                    "IllegalArgumentException at any factory call. "
                    "Either way the developer hasn't asserted the "
                    "intent, leaving the surface fragile to future "
                    "SDK changes."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on PendingIntent.* factories captured "
                    "neither flag set."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Always pass ``PendingIntent.FLAG_IMMUTABLE`` "
                "explicitly. Add a CI lint rule "
                "(``UnspecifiedImmutableFlag`` is built into "
                "Android Lint) to fail any factory call that omits "
                "the flag."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )


def _sample(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "factory": payload.get("factory"),
        "flags_hex": (
            hex(int(payload.get("flags") or 0)) if payload.get("flags")
            is not None else None
        ),
        "intent_action": payload.get("intent_action"),
        "intent_has_component": bool(payload.get("intent_has_component")),
        "stack": payload.get("stack"),
    }
