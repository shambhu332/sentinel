"""C_011: Android Keystore Misuse Detection.

Detects improper use of Android Keystore (missing user auth, no hardware backing).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class KeystoreMisuseAgent(BaseAgent):
    """Detect Android Keystore misuse."""

    AGENT_ID = "C_011"
    VULN_CLASS = "Android Keystore Misuse"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Run if Keystore APIs are used."""
        if not self.context.decompiled_dir:
            return False

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            if 'KeyGenParameterSpec' in content or 'AndroidKeyStore' in content:
                return True
        return False

    async def analyze(self) -> list[Finding]:
        """Analyze Keystore usage for security issues."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            if 'KeyGenParameterSpec' not in content:
                continue

            # Check for missing user authentication requirement
            if 'KeyGenParameterSpec.Builder' in content:
                has_user_auth = 'setUserAuthenticationRequired(true)' in content
                has_biometric = 'setUserAuthenticationParameters' in content

                if not has_user_auth and not has_biometric:
                    findings.append(self._make_finding(
                        vuln_class="Keystore Key Without User Authentication",
                        severity=Severity.HIGH,
                        confidence=0.80,
                        evidence={
                            "file": rel_path,
                            "issue": "Keystore key created without user authentication requirement",
                            "description": "Key can be used without biometric/PIN verification",
                        },
                        recommendation=(
                            "For sensitive operations, require user authentication before key usage. "
                            "Call setUserAuthenticationRequired(true) or setUserAuthenticationParameters() "
                            "on KeyGenParameterSpec.Builder. This ensures keys are protected by device lock."
                        ),
                        owasp="M3: Insecure Authentication/Authorization",
                        masvs="MSTG-AUTH-8",
                    ))

            # Check for missing StrongBox backing
            if 'KeyGenParameterSpec.Builder' in content:
                has_strongbox = 'setIsStrongBoxBacked(true)' in content

                if not has_strongbox:
                    findings.append(self._make_finding(
                        vuln_class="Keystore Key Without Hardware Backing",
                        severity=Severity.MEDIUM,
                        confidence=0.70,
                        evidence={
                            "file": rel_path,
                            "issue": "Keystore key not configured for hardware backing",
                            "description": "Key may be stored in software TEE instead of hardware",
                        },
                        recommendation=(
                            "For maximum security, request StrongBox hardware backing with "
                            "setIsStrongBoxBacked(true). This stores keys in dedicated hardware "
                            "security module. Handle UnsupportedOperationException for devices "
                            "without StrongBox support."
                        ),
                        owasp="M10: Insufficient Cryptography",
                        masvs="MSTG-CRYPTO-5",
                    ))

            # Check for keys without encryption requirement
            if 'setEncryptionPaddings' in content or 'setBlockModes' in content:
                if 'setUserAuthenticationRequired' not in content:
                    findings.append(self._make_finding(
                        vuln_class="Encryption Key Without Auth Protection",
                        severity=Severity.HIGH,
                        confidence=0.75,
                        evidence={
                            "file": rel_path,
                            "issue": "Encryption key usable without user authentication",
                            "description": "Sensitive data can be decrypted without user verification",
                        },
                        recommendation=(
                            "Encryption keys for sensitive data should require user authentication. "
                            "This prevents unauthorized decryption if the device is compromised."
                        ),
                        owasp="M3: Insecure Authentication/Authorization",
                        masvs="MSTG-AUTH-8",
                    ))

        return findings
