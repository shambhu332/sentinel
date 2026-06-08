"""D_030 — In-App Update Installs Unverified APK.

Apps that ship their own updater (rather than relying on Play
Store / Play Core's update flow) call into ``PackageInstaller``.
The textbook bug is the updater fetching the APK over HTTP, or
fetching it over HTTPS but never verifying the signing certificate
of the downloaded package against the expected one before
``Session.commit``. The result is arbitrary-code-execution on the
device with the user's consent dialog as the only gate.

Detection
---------

We consume one Frida event kind:

* ``apk_install.committed`` — emitted when
  ``PackageInstaller$Session.commit`` is called. Payload:
  ``{session_id, source_scheme, source_url,
  signature_verified, signature_class_seen, stack}``.

``source_scheme`` is the URL scheme of the last network read that
fed bytes into the session's ``openWrite`` stream during this
process. ``signature_verified`` is true only if the Frida hook
observed a call to ``PackageManager.getPackageArchiveInfo``,
``PackageInfo.signingInfo``, ``Signature.equals``, or an APKsig-
verifier between ``openWrite`` and ``commit``.

Severity matrix:

* **CRITICAL** — ``source_scheme`` is ``http`` (cleartext APK
  download). MITM = arbitrary RCE.
* **HIGH** — ``signature_verified`` is false (download was HTTPS,
  but no signature compare was observed before commit).
* **MEDIUM** — ``source_scheme`` is unknown / not captured
  (warrants review, the updater may be off our hook surface).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_CLEARTEXT_SCHEMES = ("http", "ftp")


class InAppUpdateInsecureAgent(BaseAgent):
    """D_030: classify PackageInstaller commit observations."""

    AGENT_ID = "D_030"
    VULN_CLASS = "In-App Update Installs Unverified APK"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_030] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        cleartext_hits: list[dict[str, Any]] = []
        unverified_hits: list[dict[str, Any]] = []
        unknown_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "apk_install.committed":
                continue
            payload = ev.payload or {}
            scheme = str(payload.get("source_scheme") or "").lower()
            verified = bool(payload.get("signature_verified"))
            sample = {
                "session_id": payload.get("session_id"),
                "source_scheme": scheme,
                "source_url": str(payload.get("source_url") or "")[:300],
                "signature_verified": verified,
                "signature_class_seen": str(
                    payload.get("signature_class_seen") or "",
                )[:200],
                "stack": payload.get("stack"),
            }

            if scheme in _CLEARTEXT_SCHEMES:
                cleartext_hits.append(sample)
            elif not verified and scheme:
                unverified_hits.append(sample)
            elif not scheme:
                unknown_hits.append(sample)

        findings: list[Finding] = []
        if cleartext_hits:
            findings.append(self._cleartext_finding(cleartext_hits))
        if unverified_hits:
            findings.append(self._unverified_finding(unverified_hits))
        if unknown_hits:
            findings.append(self._unknown_finding(unknown_hits))
        return findings

    def _cleartext_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "PackageInstaller.Session.commit was called on an "
                    "APK fetched over a cleartext scheme (HTTP / FTP). "
                    "Any attacker who can MITM the network can swap "
                    "the payload for their own — arbitrary RCE with "
                    "the user's normal install consent dialog as the "
                    "only gate."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on PackageInstaller$Session.openWrite "
                    "tracked the source of the bytes piped in and "
                    "reported the scheme at commit time."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move the download to HTTPS with a pinned cert. "
                "Compare ``getPackageArchiveInfo(file).signingInfo`` "
                "against the expected certificate hash before commit. "
                "Prefer Play Core's in-app update API on supported "
                "devices — it handles delta updates + integrity "
                "natively."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-9",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        )

    def _unverified_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="In-App Update Skips Signature Verification",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "PackageInstaller.Session.commit was called "
                    "without any observed signature-comparison call "
                    "between openWrite and commit. The HTTPS channel "
                    "protects the download in transit, but if it is "
                    "compromised at the CDN or the URL was bound to "
                    "the wrong host, the user installs whatever the "
                    "updater fetched."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook tracked PackageManager."
                    "getPackageArchiveInfo / Signature.equals between "
                    "openWrite and commit; none were observed."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Before commit, load the downloaded APK with "
                "getPackageArchiveInfo(file, GET_SIGNING_CERTIFICATES) "
                "and compare every Signature against the expected "
                "fingerprint hard-coded into the app."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-9",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
        )

    def _unknown_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="In-App Update Source Unknown",
            severity=Severity.MEDIUM,
            confidence=0.55,
            evidence={
                "issue": (
                    "PackageInstaller.Session.commit was called but "
                    "the hook could not attribute the bytes to a "
                    "specific network scheme — the bytes may have "
                    "come from a native networking stack, an "
                    "assets-bundled file, or a stream we don't hook."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "sources": ["frida"],
            },
            recommendation=(
                "Confirm the source URL and signature-verification "
                "step manually."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-9",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        )
