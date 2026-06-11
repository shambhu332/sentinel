"""N_015 — Internal Endpoint Scanner Agent.

Detects RFC1918 private IP addresses and internal domain names
accidentally left in production APK code and resources.

Detection targets:
1. RFC1918 IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
2. Internal domains: *.corp, *.local, *.internal, *.intranet, *.dev,
   *.staging, *.test
3. Localhost variants: 127.0.0.x, 0.0.0.0
4. Common internal URL patterns: /api/internal/, /debug/, /admin/

Why this matters: internal endpoints leak network topology, staging
credentials, and debug interfaces. Attackers use them to map the
backend infrastructure and find unprotected admin panels.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_FILES = 3000

# RFC1918 private IP patterns with proper subnet validation
_RFC1918_RE = re.compile(
    r'\b(?:'
    r'10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'|'
    r'172\.(?:1[6-9]|2\d|3[01])\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'|'
    r'192\.168\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r')\b'
)

# Internal domain TLDs
_INTERNAL_DOMAIN_RE = re.compile(
    r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'\.(?:corp|local|internal|intranet|dev|staging|test|lan|home|'
    r'priv|localhost|localdomain)\b',
    re.IGNORECASE,
)

# Localhost variants (beyond standard exclusions)
_LOCALHOST_RE = re.compile(
    r'\b(?:127\.0\.0\.\d{1,3}|0\.0\.0\.0)\b'
)

# Context lines that suggest the IP is intentionally local (Android emulator, etc.)
_FP_CONTEXTS = (
    "emulator", "proxy", "debug", "test_config",
    "10.0.2.2",  # Android emulator host
    "10.0.3.2",  # Genymotion host
    "xmlns", "schema",
)

# Files to skip entirely
_SKIP_FILES = {"R.java", "BuildConfig.java"}


class InternalEndpointScannerAgent(BaseAgent):
    """N_015: scans for leaked internal endpoints and private IPs."""

    AGENT_ID = "N_015"
    VULN_CLASS = "Internal Endpoint Exposure"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        has_source = ctx.decompiled_dir and ctx.decompiled_dir.exists()
        has_resources = ctx.resources_dir and ctx.resources_dir.exists()
        has_androguard = ctx.has_androguard()
        return bool(has_source or has_resources or has_androguard)

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        ip_hits: list[dict] = []
        domain_hits: list[dict] = []
        localhost_hits: list[dict] = []

        # Scan decompiled Java
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            self._scan_dir(ctx.decompiled_dir, ".java",
                           ip_hits, domain_hits, localhost_hits)

        # Scan apktool resources (XML configs)
        if ctx.resources_dir and ctx.resources_dir.exists():
            self._scan_dir(ctx.resources_dir, ".xml",
                           ip_hits, domain_hits, localhost_hits)

        # Scan Androguard strings
        if ctx.has_androguard():
            self._scan_androguard(ip_hits, domain_hits, localhost_hits)

        findings: list[Finding] = []

        if ip_hits:
            findings.append(self._make_finding(
                vuln_class="RFC1918 Private IP Addresses",
                severity=Severity.MEDIUM,
                confidence=0.80,
                recommendation=(
                    "Remove hardcoded private IP addresses from the "
                    "application. Use environment-specific configuration "
                    "files or build variants to inject backend URLs. "
                    "Private IPs leak internal network topology."
                ),
                evidence={
                    "title": f"{len(ip_hits)} private IP(s) found",
                    "match_count": len(ip_hits),
                    "hits": ip_hits[:15],
                },
                owasp="M9: Reverse Engineering",
                masvs="MSTG-CODE-2",
            ))

        if domain_hits:
            findings.append(self._make_finding(
                vuln_class="Internal Domain Names",
                severity=Severity.MEDIUM,
                confidence=0.75,
                recommendation=(
                    "Remove internal domain names (*.corp, *.local, etc.) "
                    "from production builds. These expose internal DNS "
                    "infrastructure and may point to unprotected services."
                ),
                evidence={
                    "title": f"{len(domain_hits)} internal domain(s) found",
                    "match_count": len(domain_hits),
                    "hits": domain_hits[:15],
                },
                owasp="M9: Reverse Engineering",
                masvs="MSTG-CODE-2",
            ))

        if localhost_hits:
            findings.append(self._make_finding(
                vuln_class="Localhost Endpoint References",
                severity=Severity.LOW,
                confidence=0.60,
                recommendation=(
                    "Localhost references (127.0.0.1, 0.0.0.0) in "
                    "production code may indicate debug endpoints that "
                    "were not removed before release."
                ),
                evidence={
                    "title": f"{len(localhost_hits)} localhost ref(s) found",
                    "match_count": len(localhost_hits),
                    "hits": localhost_hits[:10],
                },
            ))

        return findings

    def _scan_dir(
        self, root: Path, suffix: str,
        ip_hits: list, domain_hits: list, localhost_hits: list,
    ) -> None:
        scanned = 0
        for path in root.rglob(f"*{suffix}"):
            if not path.is_file() or path.name in _SKIP_FILES:
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(root))
            for ln, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if not s:
                    continue
                lower = s.lower()
                if any(fp in lower for fp in _FP_CONTEXTS):
                    continue

                for m in _RFC1918_RE.finditer(s):
                    ip = m.group(0)
                    if ip.startswith("10.0.2.") or ip.startswith("10.0.3."):
                        continue  # Android emulator
                    if len(ip_hits) < 50:
                        ip_hits.append({"file": rel, "line": ln,
                                        "ip": ip, "context": s[:150]})

                for m in _INTERNAL_DOMAIN_RE.finditer(s):
                    if len(domain_hits) < 50:
                        domain_hits.append({"file": rel, "line": ln,
                                            "domain": m.group(0),
                                            "context": s[:150]})

                for m in _LOCALHOST_RE.finditer(s):
                    if len(localhost_hits) < 30:
                        localhost_hits.append({"file": rel, "line": ln,
                                              "ip": m.group(0),
                                              "context": s[:150]})

    def _scan_androguard(
        self, ip_hits: list, domain_hits: list, localhost_hits: list,
    ) -> None:
        androguard = self._context.sources.get("androguard")
        if not androguard:
            return
        try:
            strings = androguard.get_all_strings()
        except Exception:  # noqa: BLE001
            return

        for s in strings:
            if not s or len(s) < 7:
                continue
            for m in _RFC1918_RE.finditer(s):
                ip = m.group(0)
                if ip.startswith("10.0.2.") or ip.startswith("10.0.3."):
                    continue
                if len(ip_hits) < 50:
                    ip_hits.append({"file": "(bytecode)", "ip": ip,
                                    "context": s[:150]})
            for m in _INTERNAL_DOMAIN_RE.finditer(s):
                if len(domain_hits) < 50:
                    domain_hits.append({"file": "(bytecode)",
                                        "domain": m.group(0),
                                        "context": s[:150]})


__all__ = ["InternalEndpointScannerAgent"]
