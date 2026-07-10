"""C_001 — Insecure Backup Agent.

Detects Android applications that allow ADB-based device backup of their
private data. When `android:allowBackup="true"` is set in the manifest (or
left at its default which used to be true on older Android versions),
anyone with USB debugging access can extract the entire app's private
data directory using `adb backup`. This includes SharedPreferences,
SQLite databases, internal storage files, and any sensitive material
the app stores assuming it's protected.

Why this matters: this is a one-line manifest fix. Bug bounty programs
treat allowBackup=true as a Medium severity finding by default, escalating
to High when the app stores authentication tokens, credentials, or PII.
The reproduction is trivial — anyone can demo it with adb. Bounty
payouts are typically $300-$1,500, more if account takeover via stolen
backup is demonstrated.

Detection pipeline:
1. Read android:allowBackup from the parsed manifest
2. Read android:fullBackupContent (a more granular replacement)
3. Read android:dataExtractionRules (Android 12+ replacement)
4. If allowBackup is true and there's no granular control file, emit Medium
5. If allowBackup is true AND debuggable=true, escalate to High
   (a debuggable app is a much easier backup target)
"""
from __future__ import annotations

import logging

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class InsecureBackupAgent(BaseAgent):
    """C_001: detects Android apps that allow ADB-based backup of private data."""

    AGENT_ID = "BAK_001"
    VULN_CLASS = "Insecure Backup"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if not ctx.manifest:
            logger.info("[C_001] No manifest — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        manifest = ctx.manifest or {}

        allow_backup = manifest.get("allow_backup", False)
        debuggable = manifest.get("debuggable", False)
        package = manifest.get("package", "?")
        target_sdk = manifest.get("target_sdk", 0)

        # Android 12+ (target SDK 31+) defaults allowBackup=true but adds
        # dataExtractionRules. Without the rules file, the app is still
        # backupable.
        full_backup_content = manifest.get("full_backup_content")
        data_extraction_rules = manifest.get("data_extraction_rules")

        if not allow_backup:
            logger.info("[C_001] allowBackup not set — skipping")
            return []

        # Severity logic
        if debuggable:
            severity = Severity.HIGH
            confidence = 0.90
            summary = (
                "Application is both debuggable AND backup-enabled. An attacker "
                "with USB access can trivially dump all private data via "
                "`adb backup` — this is a one-command exfiltration."
            )
        elif full_backup_content or data_extraction_rules:
            # App has a granular backup control file — backup is allowed
            # but possibly limited. Treat as Low informational since proper
            # rules might exclude sensitive data.
            severity = Severity.LOW
            confidence = 0.60
            summary = (
                "Application allows backup but has declared a granular control "
                "file (fullBackupContent or dataExtractionRules). Manual review "
                "of the rules file is required to confirm sensitive data is "
                "excluded from backup archives."
            )
        else:
            severity = Severity.MEDIUM
            confidence = 0.85
            summary = (
                "Application allows full backup of private data via `adb backup`. "
                "Anyone with USB debugging access — or who can phish a user into "
                "enabling debugging — can extract the entire app's private "
                "directory including SharedPreferences, databases, and files."
            )

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(target_sdk, debuggable),
            evidence={
                "title": "Insecure Backup Configuration",
                "summary": summary,
                "package": package,
                "manifest_flags": {
                    "allowBackup": allow_backup,
                    "debuggable": debuggable,
                    "fullBackupContent": full_backup_content,
                    "dataExtractionRules": data_extraction_rules,
                    "targetSdk": target_sdk,
                },
                "vector": (
                    "Run on a device with USB debugging enabled:\n"
                    f"  adb backup -apk -shared -all -f backup.ab {package}\n"
                    "Then extract:\n"
                    "  dd if=backup.ab bs=1 skip=24 | openssl zlib -d | tar -xvf -\n"
                    "The resulting tar archive contains the app's private data."
                ),
            },
        )]

    @staticmethod
    def _build_recommendation(target_sdk: int, debuggable: bool) -> str:
        steps = [
            "Set `android:allowBackup=\"false\"` in the application tag of "
            "AndroidManifest.xml. This is the simplest mitigation and "
            "appropriate for any app that stores sensitive data.",
        ]

        if target_sdk >= 31:
            steps.append(
                "If backup must be allowed for user convenience (target SDK 31+), "
                "use `android:dataExtractionRules` pointing to an XML file that "
                "explicitly excludes sensitive paths such as databases, "
                "shared_prefs containing tokens, and credential caches."
            )
        else:
            steps.append(
                "If backup must be allowed for user convenience, use "
                "`android:fullBackupContent` pointing to an XML file that "
                "explicitly excludes sensitive paths such as databases and "
                "shared_prefs containing tokens."
            )

        if debuggable:
            steps.append(
                "URGENT: Also set `android:debuggable=\"false\"` for production "
                "release builds. The combination of debuggable + allowBackup is "
                "trivially exploitable by anyone with brief physical access to "
                "the device."
            )

        steps.append(
            "Test the fix by running `adb backup -apk <package>` on a device — "
            "it should report 'Backup not allowed' if the manifest is correct."
        )

        return " ".join(steps)

