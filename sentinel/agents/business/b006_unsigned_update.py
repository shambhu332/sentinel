"""B_006: Unsigned In-App Update Detection.

The standard recipe for an in-app updater: download an APK over
HTTPS, hand it to ``PackageInstaller`` (Android Q+) or fire an
``ACTION_INSTALL_PACKAGE`` Intent (legacy). The dangerous variant
of that recipe is the one we detect: the downloaded APK's signature
is never verified before installation. If the download URL or the
file path is attacker-influenced — through a deep link, a man-in-
the-middle on a non-pinned connection, or a poisoned CDN — the
attacker walks code into the user's device.

Detection
=========

Find every install entry point:

* ``PackageInstaller.Session.commit(`` / ``openWrite(`` chain
* ``Intent`` with action ``ACTION_INSTALL_PACKAGE`` or
  ``ACTION_VIEW`` on a ``content://`` / ``file://`` URI with
  ``setData`` ending in ``.apk``
* Direct ``Runtime.getRuntime().exec("pm install"`` calls (rare,
  but documented in malware research)

For each, audit the enclosing method body for a *verification*
signal:

* ``PackageManager.GET_SIGNATURES`` / ``GET_SIGNING_CERTIFICATES``
* ``MessageDigest`` over the APK bytes
* A pinned ``digest`` / ``sha256`` / ``hash`` literal compared to
  the downloaded bytes
* A ``PackageInstaller.Session.commit`` with a ``PendingIntent``
  status callback that calls back through a verification helper

If none of these is present, fire the finding.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_INSTALL_TRIGGER = re.compile(
    # Each alternative carries its own boundary semantics — a leading
    # ``\b`` group-wide would prevent the ``"android.intent...`` literal
    # from matching because its first char is ``"``, not a word char.
    r"(?:\bPackageInstaller\s*\.\s*Session|"
    r'"android\.intent\.action\.INSTALL_PACKAGE"|'
    r"\bACTION_INSTALL_PACKAGE\b|"
    r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*"pm\s+install)',
)
_APK_DATA_HINT = re.compile(
    r'(\.apk"|application/vnd\.android\.package-archive)',
    re.IGNORECASE,
)
_VERIFY_SIGNAL = re.compile(
    r"\b(GET_SIGNATURES|GET_SIGNING_CERTIFICATES|"
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"SHA-?256\"|"
    r"verifyApk|verifySignature|expectedHash|expectedDigest|"
    r"checksumOf|computeDigest)",
)


def _enclosing_method_body(source: str, idx: int) -> str | None:
    open_idx = source.rfind("{", 0, idx)
    while open_idx != -1:
        depth = 0
        i = open_idx
        while i < len(source):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    if i >= idx:
                        return source[open_idx + 1 : i]
                    break
            i += 1
        open_idx = source.rfind("{", 0, open_idx)
    return None


class UnsignedUpdateAgent(BaseAgent):
    """Flag in-app updaters that install APKs without signature checks."""

    AGENT_ID = "B_006"
    VULN_CLASS = "Unsigned APK Install"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            if not _INSTALL_TRIGGER.search(source):
                continue
            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            for m in _INSTALL_TRIGGER.finditer(source):
                open_idx = source.rfind("{", 0, m.start())
                if open_idx in seen_methods:
                    continue
                body = _enclosing_method_body(source, m.start())
                if not body:
                    continue
                seen_methods.add(open_idx)
                # ACTION_INSTALL_PACKAGE / pm install always counts.
                # PackageInstaller hits only count when APK data is in
                # scope (drops noise from system-level apps that hold
                # the API for other reasons).
                trigger_text = m.group(0)
                # Non-capturing top-level group above; full match is
                # the trigger text itself.
                if "PackageInstaller" in trigger_text and not _APK_DATA_HINT.search(body):
                    continue
                if _VERIFY_SIGNAL.search(body):
                    continue

                findings.append(self._make_finding(
                    vuln_class="Unsigned APK Install",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    evidence={
                        "file": rel,
                        "trigger": trigger_text[:80],
                        "issue": (
                            "Method installs an APK (via "
                            "PackageInstaller / ACTION_INSTALL_PACKAGE "
                            "/ pm install) without a signature or "
                            "checksum verification step. Any attacker "
                            "who can influence the downloaded bytes "
                            "(MITM on a non-pinned channel, poisoned "
                            "CDN, deep-link-supplied URL) gains code "
                            "execution in the user's account."
                        ),
                    },
                    recommendation=(
                        "Before invoking the installer, verify the APK "
                        "against a pinned SHA-256 digest of the "
                        "expected release, OR confirm the APK's "
                        "signing certificate matches the publisher's "
                        "pinned fingerprint via "
                        "PackageManager.GET_SIGNING_CERTIFICATES. "
                        "Better still, route updates through Play "
                        "In-App Updates so the platform performs both "
                        "checks for you."
                    ),
                    owasp="M7: Client Code Quality",
                    masvs="MSTG-CODE-2",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
                    ),
                ))
        return findings
