"""N_003 — Improper TLS Validation Agent.

Detects apps that don't properly validate TLS certificates, making them
vulnerable to man-in-the-middle (MitM) attacks on hostile networks.

How it works:
- During Phase 4 (DAST), mitmproxy sits between the app and the internet
  with a self-signed CA cert installed on the device.
- Apps that PROPERLY validate certs will reject mitmproxy's cert and fail
  the TLS handshake (these are the secure apps — good behavior).
- Apps that DON'T validate (or improperly validate) will accept mitmproxy's
  cert as valid and proceed normally (these are vulnerable — bug bounty
  finding).

Detection logic:
- For each unique host the app contacted:
  - If the app made successful HTTPS requests through mitmproxy →
    no/weak cert validation → REAL BUG
  - If the app's TLS handshake failed with "client does not trust
    proxy's certificate" → cert pinning is working → no bug
  - If the app didn't connect at all → no signal

Severity:
- Apps handling financial/auth data with no pinning: HIGH
- Generic apps with no pinning: MEDIUM
- Apps with pinning that we successfully bypassed via Magisk: LOW (note)

Bug bounty value: $500-$5,000 depending on data sensitivity.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Hosts that SHOULD pin certs in production (regulated/financial/auth)
# If app hits these without pinning, severity is HIGH not MEDIUM
_HIGH_SENSITIVITY_HOST_PATTERNS = (
    "auth", "login", "oauth", "sso", "identity", "account",
    "bank", "pay", "wallet", "transaction", "billing",
    "api.", "graphql",  # generic API endpoints often carry tokens
)

# Hosts that are common analytics/CDN — pinning them is unusual and not a bug
# We DOWN-WEIGHT findings against these hosts (lower confidence)
_LOW_SENSITIVITY_HOST_PATTERNS = (
    "analytics", "metric", "telemetry", "crashlytics",
    "googletagmanager", "doubleclick", "facebook.net",
    "cdn.", "static.", "fonts.", "imageresizer",
)


class ImproperTLSAgent(BaseAgent):
    """N_003: detects apps that accept invalid TLS certificates."""

    AGENT_ID = "N_003"
    VULN_CLASS = "Improper TLS Validation"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        """Applicable when Phase 4 produced a mitmproxy capture."""
        capture = self._context.sources.get("mitmproxy")
        if not capture:
            logger.info("[N_003] No mitmproxy capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Inspect captured flows for TLS validation weaknesses."""
        capture = self._context.sources.get("mitmproxy")
        if capture is None:
            return []

        flows = capture.flows if hasattr(capture, "flows") else []
        if not flows:
            logger.info("[N_003] No flows captured")
            return []

        # Group flows by host: classify each host as
        # - "no_pinning": HTTPS connections succeeded through mitmproxy
        # - "pinned": TLS handshake failed (cert pinning rejecting our cert)
        # - "http_only": only HTTP, no HTTPS attempted
        host_state: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "successful_https": 0,
                "failed_tls": 0,
                "http_count": 0,
                "sample_url": "",
            },
        )

        for flow in flows:
            host = (flow.host or "").lower().strip()
            if not host:
                continue
            state = host_state[host]
            if flow.tls_failed:
                state["failed_tls"] += 1
            elif flow.scheme == "https":
                state["successful_https"] += 1
                if not state["sample_url"]:
                    state["sample_url"] = flow.url
            elif flow.scheme == "http":
                state["http_count"] += 1
                if not state["sample_url"]:
                    state["sample_url"] = flow.url

        # Categorize: which hosts accepted our cert (= no pinning = bug)?
        no_pinning_hosts: list[dict[str, Any]] = []
        pinned_hosts: list[dict[str, Any]] = []

        for host, state in host_state.items():
            if state["successful_https"] > 0:
                # App successfully completed HTTPS through our proxy — no pinning
                no_pinning_hosts.append({
                    "host": host,
                    "flow_count": state["successful_https"],
                    "sample_url": state["sample_url"],
                    "sensitivity": self._classify_sensitivity(host),
                })
            elif state["failed_tls"] > 0:
                # TLS handshake failed — pinning is working
                pinned_hosts.append({
                    "host": host,
                    "failed_count": state["failed_tls"],
                })

        if not no_pinning_hosts:
            logger.info("[N_003] No hosts without cert pinning found")
            return []

        # Decide severity from the highest-sensitivity host
        sensitivities = {h["sensitivity"] for h in no_pinning_hosts}
        if "high" in sensitivities:
            severity = Severity.HIGH
            confidence = 0.85
        elif "low" in sensitivities and len(sensitivities) == 1:
            # Only low-sensitivity hosts (analytics, CDN) — likely not exploitable
            severity = Severity.LOW
            confidence = 0.55
        else:
            severity = Severity.MEDIUM
            confidence = 0.75

        # One aggregated finding
        finding = self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(),
            evidence={
                "title": (
                    f"App accepts unverified TLS certificate on "
                    f"{len(no_pinning_hosts)} host(s)"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "hosts_without_pinning": no_pinning_hosts[:20],  # cap report size
                "hosts_with_pinning": [
                    h["host"] for h in pinned_hosts[:20]
                ],  # context: which hosts DID pin (good design)
                "total_unpinned_hosts": len(no_pinning_hosts),
                "total_pinned_hosts": len(pinned_hosts),
                "vector": (
                    "On a hostile network (public WiFi, malicious VPN), an "
                    "attacker can intercept and modify traffic between the "
                    "app and these unpinned hosts. Steps to reproduce: "
                    "1) Install mitmproxy CA on test device, "
                    "2) Route phone traffic through mitmproxy, "
                    "3) Open the app, "
                    "4) Observe successful HTTPS interception of the "
                    "listed hosts. This proves the app trusts user-added "
                    "CAs in production."
                ),
                "sources": ["mitmproxy"],
            },
        )

        return [finding]

    @staticmethod
    def _classify_sensitivity(host: str) -> str:
        """Classify a host as 'high', 'medium', or 'low' sensitivity."""
        host_l = host.lower()
        for pattern in _HIGH_SENSITIVITY_HOST_PATTERNS:
            if pattern in host_l:
                return "high"
        for pattern in _LOW_SENSITIVITY_HOST_PATTERNS:
            if pattern in host_l:
                return "low"
        return "medium"

    @staticmethod
    def _build_recommendation() -> str:
        return (
            "Implement certificate pinning on all production HTTPS endpoints. "
            "Use OkHttp's CertificatePinner, the platform NetworkSecurityConfig "
            "via res/xml/network_security_config.xml with <pin-set>, or a "
            "library like TrustKit. At minimum, pin the leaf certificate's "
            "SHA-256 hash; pinning intermediate or root CA hashes is more "
            "resilient to leaf rotation. Additionally, the network security "
            "config should set <trust-anchors><certificates src=\"system\"/></trust-anchors> "
            "with no user-added CAs trusted in release builds. Test by "
            "installing mitmproxy CA on a test device and confirming the app "
            "refuses to connect."
        )
