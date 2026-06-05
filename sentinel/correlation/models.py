"""Data models for exploit chain detection.

A chain is a sequence of vulnerabilities that, when combined, produce
a higher-severity impact than any individual finding.

Example: cleartext HTTP + missing pinning + auth token in URL = critical token theft
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinel.core.finding import Finding, Severity


class ChainType(str, Enum):
    """Categories of exploit chains."""

    TOKEN_THEFT = "token_theft"
    RCE = "remote_code_execution"
    DATA_EXFIL = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTH_BYPASS = "authentication_bypass"
    ACCOUNT_TAKEOVER = "account_takeover"


@dataclass
class ChainPattern:
    """A known exploit chain pattern.

    Patterns are matched against the finding graph. Each node in the
    pattern is a vulnerability class (e.g., "Cleartext HTTP Traffic").
    """

    chain_id: str
    name: str
    chain_type: ChainType
    pattern: list[str]  # Ordered list of vuln_class names
    severity: Severity
    description: str
    impact: str
    recommendation: str
    cvss_vector: str | None = None
    owasp: str | None = None

    def matches(self, vuln_classes: list[str]) -> bool:
        """Check if a sequence of vuln classes matches this pattern.

        Allows partial matches (pattern is a subsequence of vuln_classes).
        """
        if len(self.pattern) > len(vuln_classes):
            return False

        # Check if pattern is a subsequence
        pattern_idx = 0
        for vc in vuln_classes:
            if pattern_idx < len(self.pattern) and vc == self.pattern[pattern_idx]:
                pattern_idx += 1

        return pattern_idx == len(self.pattern)


@dataclass
class ChainFinding:
    """A detected exploit chain.

    Contains the chain pattern, the specific findings that form the chain,
    and the path through the graph.
    """

    pattern: ChainPattern
    findings: list[Finding]
    path: list[str]  # Node IDs in the graph
    confidence: float  # 0.0-1.0
    evidence: dict[str, str]  # Additional context

    def to_finding(self, session_id: str) -> Finding:
        """Convert chain to a Finding object for storage."""
        return Finding(
            agent_id="COR_001",
            vuln_class=self.pattern.name,
            severity=self.pattern.severity,
            confidence=self.confidence,
            evidence={
                "chain_type": self.pattern.chain_type.value,
                "chain_id": self.pattern.chain_id,
                "component_findings": [f.finding_id for f in self.findings],
                "component_count": len(self.findings),
                "path": " → ".join(self.path),
                **self.evidence,
            },
            cvss_vector=self.pattern.cvss_vector,
            owasp=self.pattern.owasp,
            recommendation=self.pattern.recommendation,
            session_id=session_id,
        )


# ---------- Hardcoded Chain Patterns ----------

CHAIN_PATTERNS: list[ChainPattern] = [
    # Token theft via cleartext + missing pinning
    ChainPattern(
        chain_id="CHAIN_001",
        name="Authentication Token Theft via Cleartext Traffic",
        chain_type=ChainType.TOKEN_THEFT,
        pattern=[
            "Cleartext HTTP Traffic",
            "Missing Certificate Pinning",
            "Insecure Authentication Token Storage",
        ],
        severity=Severity.CRITICAL,
        description=(
            "The application transmits authentication tokens over cleartext HTTP "
            "without certificate pinning, allowing an attacker to intercept tokens "
            "via MITM and gain unauthorized access."
        ),
        impact=(
            "An attacker on the same network can intercept authentication tokens, "
            "impersonate the victim, and access their account without credentials."
        ),
        recommendation=(
            "1. Enforce HTTPS for all network traffic\n"
            "2. Implement certificate pinning\n"
            "3. Store tokens in Android Keystore with hardware backing\n"
            "4. Use short-lived tokens with refresh mechanism"
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        owasp="M3: Insecure Communication",
    ),
    # RCE via WebView misconfiguration
    ChainPattern(
        chain_id="CHAIN_002",
        name="Remote Code Execution via WebView",
        chain_type=ChainType.RCE,
        pattern=[
            "Insecure WebView Configuration",
            "JavaScript Interface Exposure",
            "File Access Enabled",
        ],
        severity=Severity.CRITICAL,
        description=(
            "The application exposes a JavaScript interface in a WebView with "
            "file access enabled, allowing arbitrary code execution via malicious "
            "web content."
        ),
        impact=(
            "An attacker can execute arbitrary Java code in the app's context, "
            "read sensitive files, and exfiltrate data."
        ),
        recommendation=(
            "1. Disable JavaScript if not required\n"
            "2. Remove @JavascriptInterface annotations\n"
            "3. Disable file access: setAllowFileAccess(false)\n"
            "4. Validate all URLs loaded in WebView"
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        owasp="M1: Improper Platform Usage",
    ),
    # Data exfiltration via exported component
    ChainPattern(
        chain_id="CHAIN_003",
        name="Data Exfiltration via Exported Content Provider",
        chain_type=ChainType.DATA_EXFIL,
        pattern=[
            "World-Readable Storage",
            "Exported Content Provider Without Permission",
        ],
        severity=Severity.HIGH,
        description=(
            "The application stores sensitive data in world-readable files and "
            "exposes them via an unprotected Content Provider, allowing any app "
            "to read private data."
        ),
        impact=(
            "Any installed app can query the Content Provider and read sensitive "
            "user data without requesting permissions."
        ),
        recommendation=(
            "1. Use MODE_PRIVATE for all file operations\n"
            "2. Add android:permission to Content Provider\n"
            "3. Use EncryptedSharedPreferences for sensitive data\n"
            "4. Set android:exported=false if not needed"
        ),
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        owasp="M2: Insecure Data Storage",
    ),
    # Privilege escalation via deep link
    ChainPattern(
        chain_id="CHAIN_004",
        name="Privilege Escalation via Deep Link Hijacking",
        chain_type=ChainType.PRIVILEGE_ESCALATION,
        pattern=[
            "Deep Link Hijacking",
            "Insecure Authentication Token Storage",
        ],
        severity=Severity.HIGH,
        description=(
            "The application accepts deep links without validation and stores "
            "authentication tokens insecurely, allowing an attacker to trigger "
            "privileged actions via malicious deep links."
        ),
        impact=(
            "An attacker can craft a malicious deep link that triggers privileged "
            "operations (e.g., password reset, payment) without user consent."
        ),
        recommendation=(
            "1. Validate all deep link parameters\n"
            "2. Require user confirmation for sensitive actions\n"
            "3. Use Android App Links with domain verification\n"
            "4. Store tokens in Android Keystore"
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        owasp="M1: Improper Platform Usage",
    ),
    # Auth bypass via weak crypto
    ChainPattern(
        chain_id="CHAIN_005",
        name="Authentication Bypass via Weak Cryptography",
        chain_type=ChainType.AUTH_BYPASS,
        pattern=[
            "Weak Cryptographic Algorithm",
            "Hardcoded Cryptographic Key",
        ],
        severity=Severity.CRITICAL,
        description=(
            "The application uses weak cryptography (DES/MD5) with hardcoded keys "
            "to protect authentication data, allowing an attacker to decrypt and "
            "forge authentication tokens."
        ),
        impact=(
            "An attacker can decrypt authentication tokens, forge new tokens, and "
            "bypass authentication entirely."
        ),
        recommendation=(
            "1. Use AES-256-GCM for encryption\n"
            "2. Generate keys using Android Keystore\n"
            "3. Use PBKDF2 or Argon2 for password hashing\n"
            "4. Rotate keys regularly"
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        owasp="M5: Insufficient Cryptography",
    ),
    # Account takeover via runtime bypass
    ChainPattern(
        chain_id="CHAIN_006",
        name="Account Takeover via Certificate Pinning Bypass",
        chain_type=ChainType.ACCOUNT_TAKEOVER,
        pattern=[
            "Certificate Pinning Bypass",
            "Sensitive Data in Transit",
        ],
        severity=Severity.CRITICAL,
        description=(
            "The application's certificate pinning can be bypassed at runtime, "
            "and sensitive authentication data is transmitted over the network, "
            "allowing session hijacking."
        ),
        impact=(
            "An attacker can use Frida to bypass pinning, intercept credentials "
            "or session tokens, and take over user accounts."
        ),
        recommendation=(
            "1. Implement root/Frida detection\n"
            "2. Use SafetyNet Attestation API\n"
            "3. Add runtime integrity checks\n"
            "4. Use certificate transparency logs"
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        owasp="M3: Insecure Communication",
    ),
]
