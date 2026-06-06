"""META_002: Debuggable Manifest Flag Detection.

``<application android:debuggable="true">`` in a shipping APK is a
CRITICAL bug: it lets any process on the device run debug commands
against the app's UID via ``run-as``. That includes:

* reading and writing the private data directory (databases,
  SharedPreferences, EncryptedSharedPreferences keys)
* attaching a JDWP debugger and dumping or modifying memory
* invoking the app's signed components without honouring permission
  checks

ManifestParser already extracts the flag into ``manifest['debuggable']``,
so this agent is a one-line manifest read. It's deliberately separate
from META_001 (obfuscation tooling) so the finding ID maps cleanly to
the discrete misconfiguration and chain detectors can reference it.
"""
from __future__ import annotations

from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity


class DebuggableManifestAgent(BaseAgent):
    """Flag android:debuggable="true" in the manifest."""

    AGENT_ID = "META_002"
    VULN_CLASS = "Debuggable Release Build"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.manifest)

    async def analyze(self) -> list[Finding]:
        manifest: dict[str, Any] = self._context.manifest or {}
        if not manifest.get("debuggable"):
            return []
        return [self._make_finding(
            vuln_class="Debuggable Release Build",
            severity=Severity.CRITICAL,
            confidence=0.99,
            evidence={
                "package": manifest.get("package", "?"),
                "issue": (
                    "AndroidManifest.xml's <application> element has "
                    "android:debuggable=\"true\". Any local process can "
                    "attach a JDWP debugger, run `run-as <package>` to "
                    "read the private data directory, and bypass "
                    "platform isolation."
                ),
            },
            recommendation=(
                "Remove android:debuggable=\"true\" from the "
                "<application> element before publishing. The flag is "
                "implicitly set by Gradle for debug build variants and "
                "must not appear in the release manifest. If a release "
                "APK is debuggable, Google Play and most enterprise MDMs "
                "will reject it — but bug-bounty programs still find "
                "this regularly in side-loaded or staging builds."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-CODE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )]
