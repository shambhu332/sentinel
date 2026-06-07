"""D_015 — Implicit-Intent Sensitive Extras Leak.

When the app calls ``startActivity(intent)``, ``sendBroadcast``,
``bindService``, or ``startService`` with an Intent whose target
component is *implicit* (the resolution is left to Android's intent
filter system), the OS may surface a chooser, a system broadcast, or
silently route it to any matching app. If the Intent's extras carry
credential-shaped data, every app that registered a matching filter —
including a malicious co-resident app — receives the secret.

This is the runtime mirror of CWE-927 (Use of Implicit Intent for
Sensitive Communication). Static analysis catches the
``new Intent("ACTION_SOMETHING")`` builder, but runtime construction
through reflection, factory helpers, or Kotlin extension functions
typically defeats the pattern.

Detection
---------

We consume Frida events of kind ``intent.dispatched``. The hook
captures every call to ``Context.startActivity / sendBroadcast /
bindService / startService`` and reports the Intent's:

* ``action``        — the action string (``android.intent.action.SEND``,
                      etc.)
* ``has_component`` — bool, True if ``Intent.setComponent`` /
                      ``setClass`` / explicit constructor was used.
* ``package``       — the explicit package on the Intent, if any.
* ``extras``        — the set of extras keys (not their values).
* ``method``        — startActivity / sendBroadcast / bindService /
                      startService.

Flag when:

1. ``has_component`` is False AND ``package`` is empty (Intent is
   truly implicit), AND
2. Any extras key matches the credential keyword set
   (``token``, ``auth``, ``password``, ``otp``, ``secret``, ``key``,
   ``credential``, ``pin``, ``jwt``, ``code``, ``bearer``,
   ``account``, ``ssn``, ``card``).

Severity:

* **CRITICAL** — method is ``sendBroadcast`` (the broadcast goes to
  *every* registered receiver, no chooser, no user gesture).
* **HIGH** — method is ``startActivity`` / ``bindService`` /
  ``startService`` (the system may surface a chooser; user must
  pick — but a malicious app can register the same filter and
  appear in the chooser).
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_CREDENTIAL_HINT = re.compile(
    r"(?:token|auth|password|passwd|pwd|otp|pin|secret|key|"
    r"credential|jwt|bearer|account|ssn|card|cvv|seed|mnemonic|"
    r"recovery|code)",
    re.IGNORECASE,
)


class ImplicitIntentLeakAgent(BaseAgent):
    """D_015: detect implicit-Intent dispatches carrying credentials."""

    AGENT_ID = "D_015"
    VULN_CLASS = "Implicit Intent Sensitive Extras Leak"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_015] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        broadcast_hits: list[dict[str, Any]] = []
        other_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "intent.dispatched":
                continue
            payload = ev.payload or {}
            if not self._is_implicit(payload):
                continue
            sensitive_keys = self._sensitive_extras(payload)
            if not sensitive_keys:
                continue
            method = str(payload.get("method") or "startActivity")
            sample = {
                "method": method,
                "action": payload.get("action"),
                "extras": sensitive_keys,
                "stack": payload.get("stack"),
                "timestamp": ev.timestamp,
            }
            if method == "sendBroadcast":
                broadcast_hits.append(sample)
            else:
                other_hits.append(sample)

        findings: list[Finding] = []
        if broadcast_hits:
            findings.append(self._broadcast_finding(broadcast_hits))
        if other_hits:
            findings.append(self._other_finding(other_hits))
        return findings

    @staticmethod
    def _is_implicit(payload: dict[str, Any]) -> bool:
        has_component = bool(payload.get("has_component"))
        pkg = str(payload.get("package") or "").strip()
        if has_component:
            return False
        if pkg:
            return False
        return True

    @staticmethod
    def _sensitive_extras(payload: dict[str, Any]) -> list[str]:
        extras = payload.get("extras") or []
        if isinstance(extras, str):
            extras = [extras]
        out: list[str] = []
        for k in extras:
            if isinstance(k, str) and _CREDENTIAL_HINT.search(k):
                out.append(k)
        return sorted(set(out))

    def _broadcast_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application invoked ``Context.sendBroadcast`` "
                    "with an Intent that has no explicit target "
                    "component AND carries an extras key whose name "
                    "matches credential / financial keywords. Implicit "
                    "broadcasts go to every receiver registered for "
                    "the action — including any co-resident attacker "
                    "app that declared a matching filter. No chooser "
                    "is shown."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hooks on Context.sendBroadcast captured "
                    "the Intent without a component or package; "
                    "extras keys scanned against the credential "
                    "keyword set."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Use an explicit Intent — call "
                "``intent.setComponent(new ComponentName(this, "
                "Receiver.class))`` or use a constructor that names "
                "the target class. For broadcast inside the app's "
                "own process use LocalBroadcastManager (deprecated "
                "but functional) or LiveData / Flow. For cross-app "
                "broadcasts protect the receiver with a "
                "signature-level permission and pass the permission "
                "name to sendBroadcast(intent, permission)."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _other_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application started an Activity / Service "
                    "with an implicit Intent (no explicit component or "
                    "package) that carries credential-named extras. "
                    "Android resolves the Intent through the registered "
                    "filter set; a malicious co-resident app can "
                    "register the same filter and appear in the "
                    "chooser, or silently receive the dispatch when "
                    "no chooser is offered."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hooks on Context.startActivity / "
                    "bindService / startService captured Intents "
                    "without a component; extras keys scanned for "
                    "credential keywords."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Set an explicit component on the Intent — "
                "``intent.setClass(this, MyService.class)`` or "
                "``intent.setPackage(getPackageName())``. If you "
                "specifically need an OS-resolved share (e.g. "
                "``ACTION_SEND``), do not include credentials in "
                "the extras — only the payload the user intends "
                "to share."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        )
