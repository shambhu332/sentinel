"""A_008: Biometric Authentication Bypass Detection.

Uses Frida to detect runtime bypass vulnerabilities in biometric authentication.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class BiometricBypassAgent(BaseAgent):
    """Detect biometric authentication bypass vulnerabilities."""

    AGENT_ID = "A_008"
    VULN_CLASS = "Biometric Authentication Bypass"
    PHASE = "Phase 3"

    async def is_applicable(self) -> bool:
        """Run if biometric APIs are used."""
        if not self.context.decompiled_dir:
            return False

        # Check for biometric API usage
        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            if any(api in content for api in [
                "BiometricPrompt",
                "FingerprintManager",
                "androidx.biometric",
            ]):
                return True
        return False

    async def analyze(self) -> list[Finding]:
        """Analyze biometric implementation for bypass vulnerabilities."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        # Static analysis: Check for weak implementations
        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Check for missing crypto object
            if "BiometricPrompt" in content and "CryptoObject" not in content:
                findings.append(self._make_finding(
                    vuln_class="Biometric Authentication Without Crypto Binding",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    evidence={
                        "file": rel_path,
                        "issue": "BiometricPrompt used without CryptoObject binding",
                        "description": "Authentication success can be spoofed without cryptographic verification",
                    },
                    recommendation=(
                        "Always use BiometricPrompt with a CryptoObject to bind authentication "
                        "to cryptographic operations. This prevents Frida-based bypass attacks."
                    ),
                    owasp="M4: Insufficient Cryptography",
                    masvs="MSTG-AUTH-8",
                ))

            # Check for client-side only validation
            if "onAuthenticationSucceeded" in content and "setNegativeButtonText" in content:
                # Potential client-side only check
                if "server" not in content.lower() and "backend" not in content.lower():
                    findings.append(self._make_finding(
                        vuln_class="Client-Side Biometric Validation",
                        severity=Severity.CRITICAL,
                        confidence=0.65,
                        evidence={
                            "file": rel_path,
                            "issue": "Biometric authentication appears to be client-side only",
                            "description": "No server-side validation detected after biometric success",
                        },
                        recommendation=(
                            "Biometric authentication must be validated server-side. "
                            "Use the CryptoObject to sign a challenge that the server verifies."
                        ),
                        owasp="M4: Insufficient Cryptography",
                        masvs="MSTG-AUTH-8",
                    ))

        # Dynamic analysis: Check Frida bypass potential
        # Note: Actual Frida hooking happens in Phase 4 via A_003 agent
        # This is static detection of bypassable patterns

        return findings
