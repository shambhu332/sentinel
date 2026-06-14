"""C_017 — Hardcoded Certificate / Key Finder Agent.

Scans res/raw and assets directories for certificate and key files
(.pem, .crt, .bks, .jks, .p12, .pfx, .der, .cer, .key) and uses
Shannon entropy analysis to determine if they contain real
cryptographic material.

Why this matters: shipping certificates or private keys inside the APK
means every user has a copy of the credential. Private keys enable
impersonation; client certs bypass mutual-TLS server-side ACLs. Even
public CA certs embedded in the app (custom trust anchors) reveal
backend infrastructure.
"""
from __future__ import annotations

import logging
import math
from collections import Counter

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# File extensions to search for
_CERT_EXTENSIONS = {
    ".pem", ".crt", ".cer", ".der",  # certificates
    ".key",                           # private keys
    ".bks", ".jks",                   # Java/Bouncy Castle keystores
    ".p12", ".pfx",                   # PKCS#12 bundles
}

# Entropy threshold: real crypto material has high entropy (>5.0 typical).
# Placeholder / test files tend to be low-entropy or very small.
_HIGH_ENTROPY_THRESHOLD = 5.0
_MEDIUM_ENTROPY_THRESHOLD = 4.0

# Max file size to analyze (1 MiB)
_MAX_FILE_SIZE = 1 * 1024 * 1024

# PEM header detection
_PEM_HEADERS = (
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
)


def _shannon_entropy_bytes(data: bytes) -> float:
    """Calculate Shannon entropy of raw bytes (0.0 – 8.0 scale)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class HardcodedCertFinderAgent(BaseAgent):
    """C_017: finds certificate and key files in APK resources/assets."""

    AGENT_ID = "C_017"
    VULN_CLASS = "Hardcoded Certificate/Key"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.resources_dir and ctx.resources_dir.exists())

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        ctx = self._context

        cert_files: list[dict] = []
        key_files: list[dict] = []
        keystore_files: list[dict] = []

        # Scan res/raw and assets directories
        search_dirs = []
        res_dir = ctx.resources_dir
        if res_dir:
            for subdir in ["res/raw", "assets", "res"]:
                candidate = res_dir / subdir
                if candidate.exists():
                    search_dirs.append(candidate)
            # Also scan root resources_dir for flat structure
            if res_dir.exists():
                search_dirs.append(res_dir)

        seen_paths: set[str] = set()

        for search_dir in search_dirs:
            for path in search_dir.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in _CERT_EXTENSIONS:
                    continue

                abs_str = str(path.resolve())
                if abs_str in seen_paths:
                    continue
                seen_paths.add(abs_str)

                try:
                    stat = path.stat()
                    if stat.st_size > _MAX_FILE_SIZE or stat.st_size == 0:
                        continue
                    data = path.read_bytes()
                except OSError:
                    continue

                rel = str(path.relative_to(res_dir))
                entropy = _shannon_entropy_bytes(data)
                is_pem = any(h in data for h in _PEM_HEADERS)
                has_private = any(
                    h in data for h in (
                        b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY",
                    )
                )

                file_info = {
                    "file": rel,
                    "size_bytes": len(data),
                    "entropy": round(entropy, 2),
                    "is_pem": is_pem,
                    "has_private_key": has_private,
                    "extension": path.suffix.lower(),
                }

                # Categorize
                if has_private or path.suffix.lower() == ".key":
                    key_files.append(file_info)
                elif path.suffix.lower() in {".bks", ".jks", ".p12", ".pfx"}:
                    keystore_files.append(file_info)
                else:
                    cert_files.append(file_info)

        # Emit findings based on category and entropy
        if key_files:
            # Private keys are always critical
            high_entropy = [f for f in key_files
                            if f["entropy"] >= _MEDIUM_ENTROPY_THRESHOLD]
            severity = Severity.CRITICAL if high_entropy else Severity.HIGH
            findings.append(self._make_finding(
                vuln_class="Hardcoded Private Key",
                severity=severity,
                confidence=0.90 if high_entropy else 0.70,
                recommendation=(
                    "Remove private key files from the APK immediately. "
                    "Private keys must never be shipped to end-user devices. "
                    "Use the Android Keystore system for client-side key "
                    "storage, or fetch short-lived keys from a server-side "
                    "key management system. Rotate the compromised key."
                ),
                evidence={
                    "title": f"{len(key_files)} private key file(s) found",
                    "match_count": len(key_files),
                    "hits": key_files[:10],
                    "high_entropy_count": len(high_entropy),
                },
                owasp="M5: Insufficient Cryptography",
                masvs="MSTG-CRYPTO-1",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            ))

        if keystore_files:
            high_entropy = [f for f in keystore_files
                            if f["entropy"] >= _MEDIUM_ENTROPY_THRESHOLD]
            findings.append(self._make_finding(
                vuln_class="Hardcoded Keystore",
                severity=Severity.HIGH,
                confidence=0.80 if high_entropy else 0.60,
                recommendation=(
                    "Remove keystore files (.bks, .jks, .p12, .pfx) from "
                    "the APK. These may contain private keys and client "
                    "certificates. If mutual TLS is required, provision "
                    "client certificates at runtime via a secure enrollment "
                    "flow, not by bundling them in the APK."
                ),
                evidence={
                    "title": f"{len(keystore_files)} keystore file(s) found",
                    "match_count": len(keystore_files),
                    "hits": keystore_files[:10],
                    "high_entropy_count": len(high_entropy),
                },
                owasp="M5: Insufficient Cryptography",
                masvs="MSTG-CRYPTO-1",
            ))

        if cert_files:
            high_entropy = [f for f in cert_files
                            if f["entropy"] >= _HIGH_ENTROPY_THRESHOLD]
            # Public certs are lower severity — they reveal infra but
            # don't directly compromise security
            findings.append(self._make_finding(
                vuln_class="Embedded Certificate",
                severity=Severity.LOW,
                confidence=0.70,
                recommendation=(
                    "Review embedded certificate files. Public CA certs "
                    "used as custom trust anchors reveal backend "
                    "infrastructure. Consider using Android's Network "
                    "Security Configuration instead of bundling certs."
                ),
                evidence={
                    "title": f"{len(cert_files)} certificate file(s) found",
                    "match_count": len(cert_files),
                    "hits": cert_files[:10],
                    "high_entropy_count": len(high_entropy),
                },
                owasp="M5: Insufficient Cryptography",
                masvs="MSTG-CRYPTO-1",
            ))

        return findings


__all__ = ["HardcodedCertFinderAgent"]
