"""D_038 — Custom X509TrustManager Accepts Invalid Certificate Chain.

D_029 catches HostnameVerifier bypasses. This agent covers the
sibling primitive at the TrustManager layer: a custom
``X509TrustManager`` whose ``checkServerTrusted`` accepts a chain
the platform default verifier would reject. Static SAST catches the
obvious empty-body overrides; this agent picks up obfuscated,
conditional, and dependency-injected variants that ship in release.

Detection
---------

We consume one Frida event kind:

* ``tls.trust_manager_invoked`` — emitted from every concrete
  ``X509TrustManager.checkServerTrusted`` call. Payload:
  ``{tm_class, chain_subject, auth_type, accepted,
  default_would_accept, stack}``.

``accepted`` is whether the custom impl returned without throwing
``CertificateException``. ``default_would_accept`` is the result of
the Frida hook running the platform default TrustManager (via
``TrustManagerFactory.init(null)`` and the first
``X509TrustManager`` it returns) against the same chain in parallel.

Severity matrix:

* **CRITICAL** — ``accepted=True`` and ``default_would_accept=False``.
  Confirmed bypass.
* **HIGH** — ``accepted=True`` and ``default_would_accept=False``,
  but ``tm_class`` name suggests a deliberate allow-list (``Allow``
  / ``Pinned`` / ``Internal`` / ``Dev``) AND the chain count seen
  through this verifier is <= 2 (single-host exception, plausibly
  pinning).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_DELIBERATE_HINTS = ("allow", "pinned", "internal", "dev", "trust")


class InsecureTrustManagerRuntimeAgent(BaseAgent):
    """D_038: classify X509TrustManager bypass observations."""

    AGENT_ID = "D_038"
    VULN_CLASS = "Custom X509TrustManager Accepts Invalid Chain"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_038] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        global_hits: list[dict[str, Any]] = []
        deliberate_hits: list[dict[str, Any]] = []
        chains_per_tm: dict[str, set[str]] = defaultdict(set)

        # First pass — collect chain hashes per TM class so we can
        # decide single-host vs. multi-host bypass.
        for ev in capture.events:
            if ev.kind != "tls.trust_manager_invoked":
                continue
            payload = ev.payload or {}
            if not payload.get("accepted") or payload.get("default_would_accept"):
                continue
            tm = str(payload.get("tm_class") or "")
            subject = str(payload.get("chain_subject") or "")
            if tm and subject:
                chains_per_tm[tm].add(subject)

        # Second pass — classify.
        for ev in capture.events:
            if ev.kind != "tls.trust_manager_invoked":
                continue
            payload = ev.payload or {}
            if not payload.get("accepted") or payload.get("default_would_accept"):
                continue
            tm = str(payload.get("tm_class") or "")
            sample = {
                "tm_class": tm[:200],
                "chain_subject": str(payload.get("chain_subject") or "")[:200],
                "auth_type": str(payload.get("auth_type") or "")[:32],
                "stack": payload.get("stack"),
            }
            looks_deliberate = (
                any(h in tm.lower() for h in _DELIBERATE_HINTS)
                and len(chains_per_tm[tm]) <= 1
            )
            if looks_deliberate:
                deliberate_hits.append(sample)
            else:
                global_hits.append(sample)

        findings: list[Finding] = []
        if global_hits:
            findings.append(self._global_finding(global_hits))
        if deliberate_hits:
            findings.append(self._deliberate_finding(deliberate_hits))
        return findings

    def _global_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "A custom X509TrustManager accepted a certificate "
                    "chain that the platform default TrustManager "
                    "rejected with the same arguments. Any attacker "
                    "who can MITM the TLS connection (rogue Wi-Fi, "
                    "captive portal, downstream-of-CDN compromise) "
                    "can substitute their own self-signed cert and "
                    "the app will trust it. This is the TLS-bypass "
                    "primitive that static SAST often misses when the "
                    "trust manager is obfuscated or built via DI."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook ran the platform default "
                    "X509TrustManager (via TrustManagerFactory.init"
                    "(null)) against the same chain + authType in "
                    "parallel with the custom implementation."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Delete the custom TrustManager and let OkHttp / "
                "HttpsURLConnection use their platform defaults. For "
                "pinning, prefer CertificatePinner (OkHttp) or "
                "<pin-set> in NetworkSecurityConfig — never weaken "
                "the chain verifier itself."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-NETWORK-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _deliberate_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="TrustManager Allow-List Pattern",
            severity=Severity.HIGH,
            confidence=0.70,
            evidence={
                "issue": (
                    "A custom TrustManager accepted a chain the "
                    "platform default rejected, but the class name "
                    "suggests a deliberate allow-list (``Allow`` / "
                    "``Pinned`` / ``Internal`` / ``Dev`` / "
                    "``Trust``) and only one host's chain was "
                    "observed through it. Review whether the "
                    "exception is intentional and gated."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Same comparison as the CRITICAL case, scoped to "
                    "TMs with deliberate-looking class names and a "
                    "single observed host."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If the allow-list is genuinely required, replace it "
                "with CertificatePinner against the specific host. "
                "Otherwise delete the override."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-NETWORK-3",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        )
