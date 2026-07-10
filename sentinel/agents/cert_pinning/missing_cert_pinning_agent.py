"""N_001 — Missing Certificate Pinning Agent.

Detects Android applications that perform HTTPS networking without
implementing certificate pinning. Without pinning, the app trusts any
certificate signed by a CA in the Android trust store — including
certificates from a compromised CA, a CA controlled by a hostile state,
or a custom CA that the user (or attacker) installed on the device.

Why this matters: in a Man-in-the-Middle attack, the attacker presents
a certificate signed by a trusted CA (or one they convinced the user
to install). Without pinning, the app accepts the cert and the attacker
intercepts all traffic — including auth tokens, API responses, and
PII. Bug bounty programs treat missing cert pinning on financial,
healthcare, or auth-bearing apps as Medium-to-High severity, paying
$1,000-$5,000 with confirmed MitM demonstration.

Detection pipeline:
1. Walk decompiled Java files for HTTPS networking primitives:
   OkHttp Builder, HttpsURLConnection, Retrofit
2. Look for CertificatePinner, NetworkSecurityConfig pin-set, or
   custom TrustManager with pin verification
3. Check resources/xml for network_security_config.xml with <pin-set>
4. If app does HTTPS but has NO pinning indicators, emit Medium finding
5. If app uses 'cleartextTrafficPermitted=true' alongside, escalate
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# HTTPS networking primitives — presence indicates the app DOES use HTTPS
_HTTPS_USAGE_PATTERNS = [
    re.compile(r"\bnew\s+OkHttpClient(?:\.Builder)?\s*\("),
    re.compile(r"\bRetrofit\.Builder\s*\("),
    re.compile(r"\bHttpsURLConnection\b"),
    re.compile(r"\bSSLContext\.getInstance\s*\("),
    re.compile(r"https://[^\s\"']+"),
]

# Pinning indicators — presence means pinning IS implemented somewhere
_PINNING_PATTERNS = [
    re.compile(r"\bCertificatePinner\b"),
    re.compile(r"\.certificatePinner\s*\("),
    re.compile(r"\bsha256/[A-Za-z0-9+/=]+"),
    # NetworkSecurityConfig pin reference (in code or in XML resource)
    re.compile(r"<pin-set\b"),
    re.compile(r'<pin\s+digest='),
    # Custom TrustManager that does pin verification (heuristic)
    re.compile(
        r"\bcheckServerTrusted\b[\s\S]{0,400}?\b(?:fingerprint|pin|digest|"
        r"MessageDigest|SHA-256)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bTrustKit\b"),  # TrustKit-Android library
    re.compile(r"\bSSLPinning\b", re.IGNORECASE),
]

_MAX_FILES_TO_SCAN = 3000


class MissingCertPinningAgent(BaseAgent):
    """N_001: detects HTTPS apps that don't implement certificate pinning."""

    AGENT_ID = "N_002"
    VULN_CLASS = "Missing Certificate Pinning"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[N_001] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context

        uses_https = False
        has_pinning = False
        https_examples: list[str] = []
        pinning_examples: list[str] = []

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            # HTTPS usage
            if not uses_https or len(https_examples) < 5:
                for pat in _HTTPS_USAGE_PATTERNS:
                    if pat.search(text):
                        uses_https = True
                        if len(https_examples) < 5:
                            https_examples.append(rel)
                        break

            # Pinning indicators
            for pat in _PINNING_PATTERNS:
                if pat.search(text):
                    has_pinning = True
                    if len(pinning_examples) < 5:
                        pinning_examples.append(rel)
                    break

        # Also check resources/xml/network_security_config.xml
        if ctx.resources_dir and ctx.resources_dir.exists():
            for xml_path in ctx.resources_dir.rglob("network_security_config.xml"):
                try:
                    xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                if "<pin-set" in xml_text or "<pin " in xml_text:
                    has_pinning = True
                    pinning_examples.append(str(xml_path.name))

        if not uses_https:
            logger.info("[N_001] App does not appear to use HTTPS — skipping")
            return []

        if has_pinning:
            logger.info("[N_001] App uses HTTPS AND has pinning indicators — clean")
            return []

        # App uses HTTPS but has no pinning indicators
        manifest = ctx.manifest or {}
        package = manifest.get("package", "?")
        cleartext = manifest.get("uses_cleartext_traffic", False)

        # Severity: Medium baseline; Low if Network Security Config exists
        # but doesn't include pin-set; High if app handles auth/payments
        # (we can't determine that from static alone, so Medium is the default).

        if cleartext:
            severity = Severity.HIGH
            confidence = 0.80
            summary = (
                "App uses HTTPS but allows cleartext traffic AND has no "
                "certificate pinning. An attacker can downgrade traffic to "
                "plain HTTP or substitute a CA-signed cert in their MitM."
            )
        else:
            severity = Severity.MEDIUM
            confidence = 0.70
            summary = (
                "App uses HTTPS but does not pin server certificates. Any "
                "compromised, malicious, or user-installed CA can be used "
                "to intercept and decrypt traffic in a MitM attack."
            )

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(),
            evidence={
                "title": "Missing Certificate Pinning",
                "summary": summary,
                "package": package,
                "https_usage_files": https_examples,
                "uses_cleartext_traffic": cleartext,
                "vector": (
                    "On a rooted device, install a custom CA into the user trust "
                    "store. Run mitmproxy or Burp Suite with the custom CA's "
                    "certificate. Route the device's traffic through the proxy. "
                    "Without pinning, the app will accept the proxy's "
                    "intercepted certificates and all HTTPS traffic becomes "
                    "readable. Capture auth tokens, API responses, and any "
                    "sensitive data sent over HTTPS."
                ),
            },
        )]

    @staticmethod
    def _build_recommendation() -> str:
        return (
            "Implement certificate pinning using OkHttp's CertificatePinner or "
            "the platform NetworkSecurityConfig. Example with OkHttp:\n"
            "  CertificatePinner pinner = new CertificatePinner.Builder()\n"
            "      .add(\"api.example.com\", \"sha256/AAAA...primary...=\")\n"
            "      .add(\"api.example.com\", \"sha256/BBBB...backup...=\")\n"
            "      .build();\n"
            "  OkHttpClient client = new OkHttpClient.Builder()\n"
            "      .certificatePinner(pinner).build();\n"
            "Always pin AT LEAST TWO certificates (primary + backup) so the "
            "app keeps working when the primary cert is rotated. Pin to the "
            "intermediate or root certificate's SubjectPublicKeyInfo (SPKI) "
            "rather than the leaf cert for easier rotation. For Android 7+ "
            "(API 24), prefer NetworkSecurityConfig with <pin-set> over "
            "code-based pinning so security policy lives in resources, not "
            "code paths. Test the pinning by running the app through a "
            "MitM proxy with a self-signed cert — the connection MUST fail."
        )
