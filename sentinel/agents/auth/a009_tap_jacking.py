"""A_009: Tap-Jacking / Overlay Touch Filtering Audit.

Tap-jacking is the Android equivalent of UI redress / click-jacking: a
malicious app draws a translucent overlay on top of the victim app's
window so the user sees one button (e.g. "Cancel") while taps actually
land on the underlying button (e.g. "Approve transfer").

The platform offers two opt-in mitigations:

* ``android:filterTouchesWhenObscured="true"`` on the View in XML
* ``View.setFilterTouchesWhenObscured(true)`` at runtime

Either one drops touch events whose ``MotionEvent.FLAG_WINDOW_IS_OBSCURED``
bit is set, defeating the overlay attack. **Neither is the default** —
the app has to opt in per sensitive view. Banking and 2FA prompts that
miss this control are a recurring source of CVE-grade bugs and have
shipped on apps including Google Pay, Stripe Terminal, and several
crypto wallets.

Detection
=========

We focus on activities whose name *or* source body indicates a
sensitive operation — login, biometric prompt, payment, transfer,
authorisation, password reset — and look for the touch-filter opt-in
in either the Java source or any XML layout reachable from
``res/layout/``.

The agent emits HIGH severity when an activity's name matches the
sensitive-name table and *no* filterTouchesWhenObscured signal is found
anywhere in its decompiled source or the layout files. When the
opt-in is observed, no finding is emitted — the activity is doing
the right thing.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

# Activity-name keywords that suggest sensitive UI.
_SENSITIVE_NAME_HINTS = (
    "login", "signin", "sign_in", "auth", "biometric", "fingerprint",
    "payment", "pay", "checkout", "transfer", "send", "withdraw",
    "approve", "authorize", "authorise", "consent",
    "password", "reset", "otp", "twofactor", "two_factor", "2fa",
    "pin", "kyc",
)

_FILTER_TOUCHES_JAVA = re.compile(
    r"setFilterTouchesWhenObscured\s*\(\s*true\s*\)",
)
_FILTER_TOUCHES_XML = re.compile(
    r'android:filterTouchesWhenObscured\s*=\s*"true"',
)

# Body keywords that strongly suggest the activity hosts a sensitive
# flow even when the class name is generic (Main, Activity1, etc.).
_SENSITIVE_BODY_HINTS = re.compile(
    r"\b(BiometricPrompt|FingerprintManager|androidx\.biometric|"
    r"PaymentMethodCreateParams|GooglePay|StripeIntent|"
    r"authorize|authorise|verifyOtp|verifyPassword)\b",
    re.IGNORECASE,
)


class TapJackingAgent(BaseAgent):
    """Flag sensitive activities missing tap-jacking opt-in."""

    AGENT_ID = "A_009"
    VULN_CLASS = "Tap-Jacking Exposure"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        # Need at least decompiled source to look for opt-in / sensitive
        # activity names.
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        # XML-side opt-in catalogue: any layout file that opts in,
        # captured as a coarse "the app knows about this control"
        # signal. We don't try to link layout to activity precisely.
        xml_opt_in = self._xml_opt_in_any()

        manifest: dict[str, Any] = self._context.manifest or {}
        activities: list[str] = list(manifest.get("activities") or [])

        findings: list[Finding] = []
        seen: set[str] = set()

        for activity_fqcn in activities:
            if not activity_fqcn or activity_fqcn in seen:
                continue
            seen.add(activity_fqcn)

            class_name = activity_fqcn.rsplit(".", 1)[-1]
            lower_name = class_name.lower()
            name_hit = any(h in lower_name for h in _SENSITIVE_NAME_HINTS)

            source = self._read_class_source(class_name)
            body_hit = bool(source and _SENSITIVE_BODY_HINTS.search(source))

            if not (name_hit or body_hit):
                continue

            java_opt_in = bool(source and _FILTER_TOUCHES_JAVA.search(source))
            if java_opt_in:
                continue

            # XML opt-in anywhere is a partial mitigation but we can't
            # bind it to *this* activity reliably — still warn but
            # demote to MEDIUM and document the partial signal.
            severity = Severity.MEDIUM if xml_opt_in else Severity.HIGH
            confidence = 0.70 if xml_opt_in else 0.85

            findings.append(self._make_finding(
                vuln_class="Tap-Jacking Exposure",
                severity=severity,
                confidence=confidence,
                evidence={
                    "activity": activity_fqcn,
                    "matched_via": (
                        "name_hint" if name_hit else "body_signal"
                    ),
                    "xml_opt_in_anywhere": xml_opt_in,
                    "java_opt_in_in_class": False,
                    "issue": (
                        "Activity hosts a sensitive UI but no "
                        "setFilterTouchesWhenObscured(true) call was "
                        "found in its decompiled source. Without that "
                        "opt-in the activity processes touches even "
                        "while another app's overlay is showing — "
                        "classic tap-jacking primitive."
                    ),
                },
                recommendation=(
                    "Add android:filterTouchesWhenObscured=\"true\" to "
                    "the root layout of this activity (and any "
                    "transaction-confirmation dialog), or call "
                    "view.setFilterTouchesWhenObscured(true) on the "
                    "sensitive buttons in onCreate. The platform check "
                    "drops touch events whose MotionEvent flag includes "
                    "FLAG_WINDOW_IS_OBSCURED, defeating overlay-based "
                    "UI redress."
                ),
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-9",
                cvss_vector=(
                    "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N"
                ),
            ))
        return findings

    def _xml_opt_in_any(self) -> bool:
        res = self._context.resources_dir
        if not res:
            return False
        layout_dirs = [res / "res" / "layout", res / "layout"]
        for d in layout_dirs:
            if not d.exists():
                continue
            for xml_file in d.rglob("*.xml"):
                try:
                    text = xml_file.read_text(errors="replace")
                except OSError:
                    continue
                if _FILTER_TOUCHES_XML.search(text):
                    return True
        return False

    def _read_class_source(self, class_name: str) -> str | None:
        if not class_name:
            return None
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return None
        for java_file in decompiled.rglob(f"{class_name}.java"):
            try:
                return java_file.read_text(errors="replace")
            except OSError:
                continue
        return None
