"""B_004: In-App Purchase Bypass Detection.

Detects vulnerabilities in receipt validation and purchase verification.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class IapBypassAgent(BaseAgent):
    """Detect in-app purchase bypass vulnerabilities."""

    AGENT_ID = "B_004"
    VULN_CLASS = "In-App Purchase Bypass"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Run if billing/purchase APIs are detected."""
        if not self.context.decompiled_dir:
            return False

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            if any(api in content for api in [
                'BillingClient',
                'IabHelper',
                'Purchase',
                'SkuDetails',
            ]):
                return True
        return False

    async def analyze(self) -> list[Finding]:
        """Analyze IAP implementation for bypass vulnerabilities."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Check for client-side validation only
            if 'Purchase' in content and 'onPurchasesUpdated' in content:
                has_server_validation = any(keyword in content for keyword in [
                    'verifyPurchase',
                    'validateReceipt',
                    'backend',
                    'server',
                    'api/purchase',
                ])

                if not has_server_validation:
                    findings.append(self._make_finding(
                        vuln_class="Client-Side Purchase Validation",
                        severity=Severity.CRITICAL,
                        confidence=0.75,
                        evidence={
                            "file": rel_path,
                            "issue": "Purchase validation appears to be client-side only",
                            "description": "No server-side receipt verification detected",
                        },
                        recommendation=(
                            "Always validate purchases server-side using Google Play Developer API. "
                            "Never trust client-side purchase state. Implement receipt verification "
                            "on your backend before granting premium features."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-ARCH-2",
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    ))

            # Check for signature verification
            if 'Purchase' in content and 'getSignature' in content:
                if 'verify' not in content.lower():
                    findings.append(self._make_finding(
                        vuln_class="Missing Purchase Signature Verification",
                        severity=Severity.HIGH,
                        confidence=0.70,
                        evidence={
                            "file": rel_path,
                            "issue": "Purchase signature retrieved but not verified",
                            "description": "Signature verification logic not found",
                        },
                        recommendation=(
                            "Verify purchase signatures using the public key from Google Play Console. "
                            "Use Security.verifyPurchase() or implement proper RSA signature verification."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-ARCH-2",
                    ))

            # Check for hardcoded license keys
            if 'base64EncodedPublicKey' in content or 'LICENSE_KEY' in content:
                findings.append(self._make_finding(
                    vuln_class="Hardcoded IAP License Key",
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    evidence={
                        "file": rel_path,
                        "issue": "IAP license key hardcoded in source",
                        "description": "Public key for signature verification is embedded in code",
                    },
                    recommendation=(
                        "While the public key can be in the app, ensure it's obfuscated and "
                        "combined with server-side validation. Consider using NDK to store the key."
                    ),
                    owasp="M7: Client Code Quality",
                    masvs="MSTG-RESILIENCE-3",
                ))

        return findings
