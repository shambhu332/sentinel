"""D_004 — Anti-Tamper / Root-Detection Coverage Observer.

Mobile applications handling money, credentials, or DRM are expected
to detect a compromised runtime — rooted device, emulator, debugger
attached, and self-tampering. Common Android coverage:

* **Root check**         — ``File.exists("/system/bin/su")``,
                           ``Runtime.exec("su")``, RootBeer.
* **Emulator check**     — ``Build.FINGERPRINT`` / ``Build.MODEL`` /
                           ``Build.HARDWARE`` reads.
* **Integrity check**    — ``PackageManager.getPackageInfo(..., GET_SIGNATURES)``
                           comparison against an embedded hash.
* **Debugger check**     — ``Debug.isDebuggerConnected()`` /
                           ``ApplicationInfo.FLAG_DEBUGGABLE``.

We don't *attempt* a bypass in this observer (that's the exploit
engine's job). We classify the app's coverage *posture* based on what
Frida observed during the session:

* Zero categories seen on a sensitive-app target → MEDIUM finding
  ("no anti-tamper coverage observed").
* 1–3 of 4 categories seen → LOW finding ("partial coverage"), naming
  which categories are missing.
* All 4 categories seen → no finding (defence-in-depth in place).

This intentionally treats coverage gaps as evidence of weak hardening,
not as a confirmed exploit. The exploit engine can promote a finding
to HIGH by forcing every check to return "device-is-clean" and
re-running the user flow.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_ALL_CATEGORIES = ("root", "emulator", "integrity", "debugger")

# Hint keywords that suggest the target app handles value: if any of
# these tokens appear in the package or app name we treat zero
# coverage as MEDIUM. Otherwise zero coverage is LOW (still worth
# noting, but the impact is lower).
_SENSITIVE_TOKENS = (
    "bank", "wallet", "pay", "money", "crypto", "broker", "trad",
    "card", "vault", "secure", "auth", "login", "credit", "lend",
    "invest", "kyc", "id-",
)


class AntiTamperCoverageAgent(BaseAgent):
    """D_004: classifies the app's anti-tamper coverage posture."""

    AGENT_ID = "D_004"
    VULN_CLASS = "Missing Anti-Tamper Coverage"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_004] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        seen: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in capture.events:
            if ev.kind == "tamper.root_check":
                seen["root"].append(ev.payload or {})
            elif ev.kind == "tamper.emulator_check":
                seen["emulator"].append(ev.payload or {})
            elif ev.kind == "tamper.integrity_check":
                seen["integrity"].append(ev.payload or {})
            elif ev.kind == "tamper.debugger_check":
                seen["debugger"].append(ev.payload or {})

        covered = {c for c, items in seen.items() if items}
        missing = [c for c in _ALL_CATEGORIES if c not in covered]
        if not missing:
            return []

        return [self._finding(covered, missing, seen)]

    def _finding(
        self,
        covered: set[str],
        missing: list[str],
        seen: dict[str, list[dict[str, Any]]],
    ) -> Finding:
        package = (self._context.manifest or {}).get("package") or ""
        is_sensitive = any(tok in package.lower() for tok in _SENSITIVE_TOKENS)

        if not covered:
            severity = Severity.MEDIUM if is_sensitive else Severity.LOW
            issue = (
                "The Frida session observed no anti-tamper checks of "
                "any category (root / emulator / integrity / debugger). "
                "A compromised device or modified APK runs the "
                "application unimpeded."
            )
            confidence = 0.80
        else:
            severity = Severity.LOW
            issue = (
                "The application performs partial anti-tamper coverage. "
                f"Observed: {sorted(covered)}. Missing categories: "
                f"{missing}. A skilled attacker who can defeat the "
                "categories that *are* checked has no defence-in-depth "
                "to defeat next."
            )
            confidence = 0.70

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            evidence={
                "issue": issue,
                "covered_categories": sorted(covered),
                "missing_categories": missing,
                "package_is_sensitive_class": is_sensitive,
                "samples": {
                    cat: items[:3] for cat, items in seen.items() if items
                },
                "vector": (
                    "Frida hooks instrumented File.exists for root-binary "
                    "paths, Build.* getters, PackageManager.getPackageInfo "
                    "with GET_SIGNATURES, and Debug.isDebuggerConnected. "
                    "Counted per-category invocations across the session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Implement defence-in-depth: a sensitive app should "
                "check (a) common root paths and RootBeer-style indicators, "
                "(b) emulator fingerprints, (c) APK signature against an "
                "embedded reference hash on every launch, and (d) "
                "debugger attachment before any sensitive flow. None of "
                "these alone is sufficient — the goal is to make a "
                "Frida-grade bypass require N independent hooks rather "
                "than one. Consider Google Play Integrity API for the "
                "server-side check that does not depend on client code "
                "an attacker has already modified."
            ),
            owasp="M9: Reverse Engineering",
            masvs="MSTG-RESILIENCE-1",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )
