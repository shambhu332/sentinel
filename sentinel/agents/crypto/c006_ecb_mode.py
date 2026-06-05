"""C_006: ECB Cipher Mode Detection.

Detects use of ECB mode which leaks plaintext patterns.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class EcbModeAgent(BaseAgent):
    """Detect ECB cipher mode usage."""

    AGENT_ID = "C_006"
    VULN_CLASS = "ECB Cipher Mode"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Run if crypto APIs are used."""
        return self.context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        """Analyze code for ECB mode usage."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Find Cipher.getInstance() calls
            cipher_pattern = r'Cipher\.getInstance\s*\(\s*"([^"]+)"\s*\)'
            matches = re.finditer(cipher_pattern, content)

            for match in matches:
                transformation = match.group(1)

                # Check for ECB mode
                if '/ECB/' in transformation.upper():
                    findings.append(self._make_finding(
                        vuln_class="ECB Cipher Mode Usage",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        evidence={
                            "file": rel_path,
                            "transformation": transformation,
                            "code_snippet": match.group(0),
                            "description": "ECB mode leaks plaintext patterns",
                        },
                        recommendation=(
                            f"Replace '{transformation}' with a secure mode like GCM or CBC. "
                            "ECB mode encrypts identical plaintext blocks to identical ciphertext, "
                            "revealing patterns. Use AES/GCM/NoPadding for authenticated encryption."
                        ),
                        owasp="M2: Inadequate Supply Chain Security",
                        masvs="MSTG-CRYPTO-2",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        poc=(
                            "ECB mode vulnerability can be demonstrated by encrypting repeated data. "
                            "Identical plaintext blocks produce identical ciphertext blocks, "
                            "allowing pattern analysis attacks."
                        ),
                    ))

                # Check for default transformation (may default to ECB)
                elif transformation in ['AES', 'DES', 'DESede']:
                    findings.append(self._make_finding(
                        vuln_class="Default Cipher Transformation",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        evidence={
                            "file": rel_path,
                            "transformation": transformation,
                            "code_snippet": match.group(0),
                            "description": "Cipher transformation without explicit mode/padding",
                        },
                        recommendation=(
                            f"Specify explicit mode and padding for '{transformation}'. "
                            "Default transformation may use ECB mode on some platforms. "
                            "Use explicit transformation like 'AES/GCM/NoPadding'."
                        ),
                        owasp="M2: Inadequate Supply Chain Security",
                        masvs="MSTG-CRYPTO-2",
                    ))

        return findings
