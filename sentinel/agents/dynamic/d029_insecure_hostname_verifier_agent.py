"""D_029 — HostnameVerifier Accepts Mismatched Cert at Runtime.

A custom ``HostnameVerifier.verify(String hostname, SSLSession
session)`` returning ``true`` for a hostname that does *not* match
the certificate's CN / SAN is the textbook TLS-validation bypass.
Static SAST catches the obvious ``return true`` overrides; this
agent picks up the obfuscated, conditional, and dependency-injected
bypasses that ship in release builds.

Detection
---------

We consume one Frida event kind:

* ``tls.hostname_verifier_invoked`` — emitted from every custom
  ``HostnameVerifier.verify`` call. Payload:
  ``{verifier_class, hostname, accepted, default_would_accept,
  stack}``.

``default_would_accept`` is the result of the Frida hook running the
*platform default* verifier against the same hostname + session, in
parallel. The bypass is the boolean asymmetry: ``accepted=True`` and
``default_would_accept=False``.

Severity matrix:

* **CRITICAL** — ``accepted=True`` and ``default_would_accept=False``
  for at least one observed call. Confirmed bypass.
* **HIGH** — same asymmetry but limited to one specific host, AND
  the verifier class name suggests a deliberate allow-list (``Allow``
  / ``Trust`` / ``Pinned`` substrings). Reviewer should confirm the
  allow-list is intentional.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_DELIBERATE_HINTS = ("allow", "trust", "pinned", "internal", "dev")


class InsecureHostnameVerifierAgent(BaseAgent):
    """D_029: classify HostnameVerifier bypass observations."""

    AGENT_ID = "D_029"
    VULN_CLASS = "Custom HostnameVerifier Accepts Mismatched Cert"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_029] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        global_bypass: list[dict[str, Any]] = []
        deliberate_allow: list[dict[str, Any]] = []

        unique_hosts: dict[str, set] = {}

        for ev in capture.events:
            if ev.kind != "tls.hostname_verifier_invoked":
                continue
            payload = ev.payload or {}
            accepted = bool(payload.get("accepted"))
            default_ok = bool(payload.get("default_would_accept"))
            if not accepted or default_ok:
                continue

            verifier_class = str(payload.get("verifier_class") or "")
            host = str(payload.get("hostname") or "")
            sample = {
                "verifier_class": verifier_class[:200],
                "hostname": host[:200],
                "stack": payload.get("stack"),
            }
            unique_hosts.setdefault(verifier_class, set()).add(host)

            lower_class = verifier_class.lower()
            looks_deliberate = (
                any(h in lower_class for h in _DELIBERATE_HINTS)
                and len(unique_hosts[verifier_class]) <= 1
            )
            if looks_deliberate:
                deliberate_allow.append(sample)
            else:
                global_bypass.append(sample)

        findings: list[Finding] = []
        if global_bypass:
            findings.append(self._global_finding(global_bypass))
        if deliberate_allow:
            findings.append(self._deliberate_finding(deliberate_allow))
        return findings

    def _global_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "A custom HostnameVerifier returned true for a "
                    "hostname that the platform default verifier "
                    "rejects against the same SSLSession. Any "
                    "attacker who can MITM the connection (rogue Wi-"
                    "Fi, network-level adversary, malicious CA) can "
                    "swap in their own certificate and the app will "
                    "accept it."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook ran the platform default "
                    "HostnameVerifier against the same hostname + "
                    "SSLSession in parallel with the custom "
                    "implementation and compared results."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Delete the custom HostnameVerifier and let OkHttp / "
                "HttpsURLConnection use their platform defaults. If "
                "the legitimate use-case is pinning, pin the "
                "certificate or its SPKI hash via CertificatePinner / "
                "NetworkSecurityConfig — never weaken hostname "
                "verification."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-NETWORK-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _deliberate_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="HostnameVerifier Allow-List Pattern",
            severity=Severity.HIGH,
            confidence=0.70,
            evidence={
                "issue": (
                    "A custom HostnameVerifier accepted a single host "
                    "the platform default would reject, and the "
                    "verifier class name suggests a deliberate allow-"
                    "list (\"Allow\" / \"Trust\" / \"Pinned\" / "
                    "\"Internal\" / \"Dev\"). Review whether the "
                    "exception is intentional and whether the host "
                    "list is hard-coded vs. caller-supplied."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Same comparison as the global case, scoped to "
                    "verifiers with deliberate-looking class names."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If the allow-list is genuinely required, replace it "
                "with a CertificatePinner against the specific host. "
                "Otherwise delete the override."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-NETWORK-3",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        )
