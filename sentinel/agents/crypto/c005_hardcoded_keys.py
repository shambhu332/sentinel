"""C_005: Hardcoded Cryptographic Keys Detection.

Detects AES/RSA keys embedded in source code.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class HardcodedCryptoKeysAgent(BaseAgent):
    """Detect hardcoded cryptographic keys."""

    AGENT_ID = "C_005"
    VULN_CLASS = "Hardcoded Cryptographic Keys"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Run if crypto APIs are used."""
        return self.context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        """Analyze code for hardcoded crypto keys."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Check for byte array keys in Cipher.init()
            cipher_init_pattern = r'Cipher\.getInstance\([^)]+\).*?\.init\([^,]+,\s*new\s+SecretKeySpec\(([^)]+)\)'
            matches = re.finditer(cipher_init_pattern, content, re.DOTALL)

            for match in matches:
                key_source = match.group(1)

                # Check if key is hardcoded (byte array or string)
                if 'new byte[]' in key_source or '"' in key_source:
                    findings.append(self._make_finding(
                        vuln_class="Hardcoded AES Key",
                        severity=Severity.CRITICAL,
                        confidence=0.90,
                        evidence={
                            "file": rel_path,
                            "issue": "AES key hardcoded in source code",
                            "code_snippet": match.group(0)[:200],
                            "key_source": key_source[:100],
                        },
                        recommendation=(
                            "Never hardcode cryptographic keys. Use Android Keystore to generate "
                            "and store keys securely. For user-specific encryption, derive keys "
                            "from user credentials using PBKDF2 with proper salt."
                        ),
                        owasp="M10: Insufficient Cryptography",
                        masvs="MSTG-CRYPTO-1",
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    ))

            # Check for Base64-encoded keys
            base64_key_pattern = r'(String\s+\w+\s*=\s*"[A-Za-z0-9+/]{32,}={0,2}".*?(key|secret|aes|rsa))'
            matches = re.finditer(base64_key_pattern, content, re.IGNORECASE)

            for match in matches:
                findings.append(self._make_finding(
                    vuln_class="Potential Base64-Encoded Key",
                    severity=Severity.HIGH,
                    confidence=0.70,
                    evidence={
                        "file": rel_path,
                        "issue": "Suspicious Base64 string near crypto keywords",
                        "code_snippet": match.group(0)[:200],
                    },
                    recommendation=(
                        "If this is a cryptographic key, move it to Android Keystore. "
                        "Base64-encoded keys in source are easily extractable."
                    ),
                    owasp="M10: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-1",
                ))

            # Check for RSA private keys
            if '-----BEGIN PRIVATE KEY-----' in content or '-----BEGIN RSA PRIVATE KEY-----' in content:
                findings.append(self._make_finding(
                    vuln_class="Hardcoded RSA Private Key",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence={
                        "file": rel_path,
                        "issue": "RSA private key embedded in source code",
                        "description": "PEM-formatted private key found",
                    },
                    recommendation=(
                        "CRITICAL: RSA private key is exposed in the APK. Rotate this key immediately. "
                        "Use Android Keystore to generate and store RSA keys. Never embed private keys "
                        "in application code."
                    ),
                    owasp="M10: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-1",
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ))

        return findings
