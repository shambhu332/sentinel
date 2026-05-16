"""N_005 — Certificate Pinning Bypass Agent.

Detects whether an app's certificate pinning can be bypassed at runtime
via Frida, and which pinning libraries (if any) resist generic bypass.

How it works:
- During Phase 4.5, the Frida sub-phase injects CERT_PINNING_BYPASS_HOOK.
- The script attempts to hook every major Android pinning library and
  replace its check method with a no-op. For each library:
  - Library not in app    -> silently skipped
  - Library hooked + fired -> tls.bypass event (= bug)
  - Library hooked + setup threw -> tls.bypass_failed (= survived)

Detection model (Frida-only this sprint; mitmproxy correlation later):
- bypassed:  tls.bypass events emitted    -> HIGH/MEDIUM severity finding
- survived:  tls.bypass_failed emitted    -> INFO positive observation
- absent:    neither                       -> no finding

Why this is better than SAST for pinning:
- Static analysis flags presence of pinning code regardless of whether
  it executes or is actually effective at runtime.
- Runtime bypass attempts produce direct, exploitable evidence: "we
  bypassed this pin and the app didn't notice."

Bug bounty value: $500-$5,000 depending on the data being protected.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Per-library severity weight for bypass findings. Major frameworks =
# HIGH (canonical pinning sites, widely deployed). Less-known/generic
# hooks = MEDIUM (still concerning, less evidence the developer treated
# pinning as their primary defense layer).
_LIBRARY_SEVERITY: dict[str, str] = {
    "okhttp.CertificatePinner":         "high",
    "X509TrustManager":                 "high",
    "WebViewClient.onReceivedSslError": "high",
    "TrustKit":                         "high",
    "Conscrypt.Platform":               "medium",
    "HostnameVerifier":                 "medium",
}


class CertPinningBypassAgent(BaseAgent):
    """N_005: detects whether cert pinning can be bypassed at runtime."""

    AGENT_ID = "N_005"
    VULN_CLASS = "Certificate Pinning Bypass"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        """Applicable when Phase 4.5 produced a Frida capture."""
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[N_005] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Inspect the Frida capture for pinning bypass events."""
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # Only TLS-related events
        tls_events = [e for e in capture.events if e.kind.startswith("tls.")]
        if not tls_events:
            logger.info("[N_005] No TLS events captured")
            return []

        # Two buckets: bypassed (= bug) and survived (= positive observation),
        # both keyed by library name.
        bypassed: dict[str, list[dict[str, Any]]] = defaultdict(list)
        survived: dict[str, list[dict[str, Any]]] = defaultdict(list)
        hooks_installed: list[str] = []

        for event in tls_events:
            payload = event.payload or {}
            library = payload.get("library", "unknown")

            if event.kind == "tls.bypass":
                bypassed[library].append({
                    "library": library,
                    "method": payload.get("method", "?"),
                    "host": payload.get("host", ""),
                    "timestamp": event.timestamp,
                })
            elif event.kind == "tls.bypass_failed":
                survived[library].append({
                    "library": library,
                    "error": str(payload.get("error", "?"))[:300],
                    "timestamp": event.timestamp,
                })
            elif event.kind == "tls.hooks_installed":
                installed = payload.get("libraries", [])
                if isinstance(installed, list):
                    hooks_installed = [str(x) for x in installed]

        findings: list[Finding] = []

        if bypassed:
            findings.append(self._make_bypass_finding(bypassed, hooks_installed))
        if survived:
            findings.append(self._make_survived_finding(survived, hooks_installed))

        return findings

    # ---------- Finding builders ----------

    def _make_bypass_finding(
        self,
        bypassed: dict[str, list[dict[str, Any]]],
        hooks_installed: list[str],
    ) -> Finding:
        """Build the HIGH/MEDIUM severity bypass (= bug) finding."""
        # Highest-tier library wins
        weights = {_LIBRARY_SEVERITY.get(lib, "medium") for lib in bypassed}
        severity = Severity.HIGH if "high" in weights else Severity.MEDIUM

        total_events = sum(len(events) for events in bypassed.values())
        libraries_summary = sorted(bypassed.keys())

        # Unique hosts seen across all bypass events
        hosts: set[str] = set()
        for events in bypassed.values():
            for ev in events:
                if ev.get("host"):
                    hosts.add(ev["host"])

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.9,  # runtime observation
            recommendation=self._build_bypass_recommendation(),
            evidence={
                "title": (
                    f"Certificate pinning bypassed at runtime "
                    f"({len(bypassed)} libraries, {total_events} events)"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "bypassed_libraries": libraries_summary,
                "per_library_counts": {
                    lib: len(events) for lib, events in bypassed.items()
                },
                "sample_bypasses": [
                    {
                        "library": ev["library"],
                        "method": ev["method"],
                        "host": ev["host"],
                    }
                    for events in bypassed.values()
                    for ev in events[:3]
                ][:15],
                "hosts_observed": sorted(hosts)[:20],
                "hooks_installed": hooks_installed,
                "vector": (
                    "Frida injected a runtime hook replacing each major "
                    "pinning library's check method with a no-op. The "
                    "application continued accepting TLS connections that "
                    "would have failed pinning validation. Steps to "
                    "reproduce: 1) Install zygiskfrida on a rooted device, "
                    "2) Launch the target app, 3) Inject SENTINEL's "
                    "CERT_PINNING_BYPASS_HOOK script via Frida, "
                    "4) Route the device through a mitmproxy with a "
                    "self-signed CA, 5) Observe traffic flowing through "
                    "the proxy that pinning would normally have rejected."
                ),
                "sources": ["frida"],
            },
        )

    def _make_survived_finding(
        self,
        survived: dict[str, list[dict[str, Any]]],
        hooks_installed: list[str],
    ) -> Finding:
        """Build the INFO 'pinning survived bypass' positive observation."""
        libraries = sorted(survived.keys())

        return self._make_finding(
            vuln_class="Certificate Pinning Resistance",
            severity=Severity.INFO,
            confidence=0.7,
            recommendation=(
                "No action required — this is a positive observation. The "
                "app's pinning paths could not be bypassed by SENTINEL's "
                "generic Frida hooks. Possible reasons: (a) non-standard "
                "pinning patterns not covered by our generic bypass, "
                "(b) anti-Frida defenses, (c) the bypass attempt crashed "
                "due to obfuscation. For higher assurance, supplement this "
                "automated result with manual analysis."
            ),
            evidence={
                "title": (
                    f"Pinning resisted runtime bypass in "
                    f"{len(survived)} libraries"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "resistant_libraries": libraries,
                "per_library_counts": {
                    lib: len(events) for lib, events in survived.items()
                },
                "sample_failures": [
                    {"library": ev["library"], "error": ev["error"]}
                    for events in survived.values()
                    for ev in events[:2]
                ][:10],
                "hooks_installed": hooks_installed,
                "vector": (
                    "SENTINEL attempted to install bypass hooks against "
                    "every major Android pinning library. For the libraries "
                    "listed above, hook installation reported errors "
                    "(overload mismatch, anti-Frida interception, "
                    "obfuscation, or similar) — meaning a generic "
                    "Frida-based attacker would NOT trivially bypass pinning "
                    "in this app. Manual analysis recommended to confirm "
                    "pinning is genuinely robust vs merely opaque."
                ),
                "sources": ["frida"],
            },
        )

    @staticmethod
    def _build_bypass_recommendation() -> str:
        return (
            "Apply defense-in-depth for certificate pinning. Pinning alone "
            "is insufficient when an attacker has runtime access (Frida, "
            "Xposed, rooted device). Layer with: "
            "(1) Play Integrity API or Apple App Attest to detect modified "
            "runtime environments and refuse to operate. "
            "(2) RASP techniques: anti-debugger checks, native-code SSL "
            "implementations that Frida cannot easily replace at the Java "
            "layer, integrity self-checks. "
            "(3) Detect Frida specifically by scanning /proc/self/maps for "
            "'frida-agent' and 'gum-js-loop' and aborting if found. "
            "(4) Server-side request signing using keys held in "
            "StrongBox/Secure Element so a bypassed channel still cannot "
            "produce valid requests. "
            "References: OWASP MASVS-RESILIENCE-2, MSTG-RESILIENCE-3."
        )
