"""N_006: API Key Leakage Detection (Dynamic Analysis).

Detects API keys in network traffic via mitmproxy.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class ApiKeyLeakageAgent(BaseAgent):
    """Detect API keys in network traffic."""

    AGENT_ID = "N_006"
    VULN_CLASS = "API Key Leakage"
    PHASE = "Phase 4"

    # Common API key patterns
    API_KEY_PATTERNS = [
        (r'api[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})', 'Generic API Key'),
        (r'authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})', 'Bearer Token'),
        (r'x-api-key:\s*([A-Za-z0-9_\-]{20,})', 'X-API-Key Header'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
        (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key'),
        (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Key'),
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token'),
        (r'glpat-[0-9a-zA-Z\-_]{20,}', 'GitLab Personal Access Token'),
    ]

    async def is_applicable(self) -> bool:
        """Run if mitmproxy capture exists."""
        return self.context.sources.get("mitmproxy") is not None

    async def analyze(self) -> list[Finding]:
        """Analyze network traffic for API key leakage."""
        findings: list[Finding] = []

        capture = self.context.sources.get("mitmproxy")
        if capture is None:
            return findings

        flows = getattr(capture, "flows", None) or []
        capture_file = getattr(capture, "capture_file", None)

        parts: list[str] = []
        for flow in flows:
            for hdrs in (
                getattr(flow, "request_headers", {}),
                getattr(flow, "response_headers", {}),
            ):
                for k, v in (hdrs or {}).items():
                    parts.append(f"{k}: {v}")
            req_body = getattr(flow, "request_body", "") or ""
            resp_body = getattr(flow, "response_body", "") or ""
            parts.append(req_body)
            parts.append(resp_body)

        if not parts and capture_file and capture_file.exists():
            try:
                parts.append(capture_file.read_text(errors="replace"))
            except Exception as e:  # noqa: BLE001
                self._log.warning("Could not read capture file %s: %s", capture_file, e)
                return findings

        traffic_data = "\n".join(parts)
        if not traffic_data:
            return findings

        found_keys = set()

        for pattern, key_type in self.API_KEY_PATTERNS:
            matches = re.finditer(pattern, traffic_data, re.IGNORECASE)

            for match in matches:
                key_value = match.group(1) if match.lastindex else match.group(0)

                # Avoid duplicates
                if key_value in found_keys:
                    continue
                found_keys.add(key_value)

                # Determine severity based on key type
                severity = Severity.CRITICAL if 'live' in key_type.lower() or 'AWS' in key_type else Severity.HIGH

                # Mask the key for evidence
                masked_key = key_value[:8] + '*' * (len(key_value) - 12) + key_value[-4:] if len(key_value) > 12 else key_value[:4] + '***'

                findings.append(self._make_finding(
                    vuln_class=f"{key_type} in Network Traffic",
                    severity=severity,
                    confidence=0.90,
                    evidence={
                        "key_type": key_type,
                        "masked_key": masked_key,
                        "location": "HTTP headers or request body",
                        "description": f"{key_type} transmitted over network",
                    },
                    recommendation=(
                        f"CRITICAL: {key_type} detected in network traffic. "
                        "API keys should never be transmitted from mobile apps. "
                        "Use a backend proxy to make API calls with keys stored server-side. "
                        "Rotate this key immediately if it's a production credential."
                    ),
                    owasp="M1: Improper Credential Usage",
                    masvs="MSTG-STORAGE-14",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    poc=(
                        "API key was captured in cleartext during network traffic analysis. "
                        "An attacker with network access can intercept and reuse this key."
                    ),
                ))

        # Check for high-entropy strings (potential undocumented keys)
        high_entropy_pattern = r'[A-Za-z0-9_\-]{32,}'
        for match in re.finditer(high_entropy_pattern, traffic_data):
            value = match.group(0)

            # Calculate entropy
            if len(set(value)) / len(value) > 0.6:  # High character diversity
                if value not in found_keys:
                    found_keys.add(value)

                    findings.append(self._make_finding(
                        vuln_class="High-Entropy String in Traffic",
                        severity=Severity.MEDIUM,
                        confidence=0.60,
                        evidence={
                            "masked_value": value[:8] + '***' + value[-4:],
                            "length": len(value),
                            "description": "Potential API key or secret token",
                        },
                        recommendation=(
                            "Review this high-entropy string. If it's an API key or secret, "
                            "move it to server-side and use a proxy pattern."
                        ),
                        owasp="M1: Improper Credential Usage",
                        masvs="MSTG-STORAGE-14",
                    ))

        return findings
