"""N_004 — Sensitive Data In Transit Agent.

Scans captured HTTP/HTTPS flows for sensitive data sent over the wire:
- Auth tokens (Bearer, JWT, session cookies)
- Credentials (passwords, API keys)
- Personally Identifiable Information (PII): emails, phone numbers, SSNs
- Payment data (card numbers, CVV)

Severity scales with what's leaked AND how:
- Auth token over cleartext HTTP: CRITICAL (account takeover)
- Auth token over HTTPS but logged in URL: HIGH (URLs in logs/browser history)
- PII in any traffic: MEDIUM
- Auth token in HTTPS request body (normal case): not a finding

Bug bounty value:
- Cleartext auth: $1,000-$10,000 (depends on user count)
- Token in URL: $500-$5,000
- PII leak: $250-$2,000
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Patterns for sensitive data. Each: (label, regex, category)
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # JWT — three base64url segments separated by dots
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "auth_token"),
    # Bearer token in Authorization header value
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.~+/]{20,}=*", re.IGNORECASE), "auth_token"),
    # API key style (prefix like 'sk_live_', 'pk_', 'api_key=')
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "api_key"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "api_key"),
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "api_key"),
    # Credit card numbers (Luhn check not done — flag for review)
    ("Credit card number", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), "payment"),
    # Email — sensitive when sent unnecessarily
    ("Email address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "pii"),
    # Phone numbers (loose — flag for review)
    ("Phone number", re.compile(r"\b\+?[1-9]\d{1,2}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b"), "pii"),
    # Common password field names being sent in body
    ("Password field", re.compile(r'"password"\s*:\s*"[^"]{4,}"', re.IGNORECASE), "credential"),
    ("Plain password in form", re.compile(r"(?:^|&)password=[^&\s]{4,}", re.IGNORECASE), "credential"),
]

# Common header names that DO carry auth tokens (so finding them is not noise)
_AUTH_HEADER_NAMES = {
    "authorization", "x-auth-token", "x-api-key", "x-access-token",
    "x-session-token", "cookie", "x-csrf-token",
}

# Substrings in URL paths that indicate the URL itself carries auth
_URL_AUTH_PARAM_KEYS = (
    "token=", "auth=", "api_key=", "apikey=", "access_token=",
    "session=", "sessionid=", "jwt=", "bearer=",
)


class DataInTransitAgent(BaseAgent):
    """N_004: detects sensitive data leaking through network traffic."""

    AGENT_ID = "N_004"
    VULN_CLASS = "Sensitive Data In Transit"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture:
            logger.info("[N_004] No mitmproxy capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None:
            return []

        flows = capture.flows if hasattr(capture, "flows") else []
        if not flows:
            return []

        # Severity heuristic:
        # - finding in HTTP (cleartext) → escalate one level
        # - auth in URL → escalate one level
        # - PII over HTTPS → keep base severity
        leaks_by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for flow in flows:
            if flow.tls_failed:
                continue  # nothing was actually transmitted
            is_cleartext = (flow.scheme == "http")
            self._scan_flow(flow, is_cleartext, leaks_by_category)

        if not leaks_by_category:
            logger.info("[N_004] No sensitive data detected in transit")
            return []

        # Build one finding per category (auth_token, api_key, pii, payment,
        # credential)
        findings: list[Finding] = []
        for category, leaks in leaks_by_category.items():
            severity, confidence = self._severity_for_category(category, leaks)
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=confidence,
                recommendation=self._build_recommendation(category),
                evidence={
                    "title": (
                        f"Sensitive {category.replace('_', ' ')} data in "
                        f"network traffic ({len(leaks)} occurrences)"
                    ),
                    "package": (self._context.manifest or {}).get("package", "?"),
                    "category": category,
                    "leak_count": len(leaks),
                    "samples": [
                        {
                            "pattern": leak["pattern"],
                            "host": leak["host"],
                            "url": leak["url"][:200],
                            "location": leak["location"],
                            "scheme": leak["scheme"],
                            "redacted_value": self._redact(leak["value"]),
                        }
                        for leak in leaks[:10]
                    ],
                    "cleartext_leak_count": sum(
                        1 for leak in leaks if leak["scheme"] == "http"
                    ),
                    "url_leak_count": sum(
                        1 for leak in leaks if leak["location"] == "url"
                    ),
                    "vector": (
                        "Use a network proxy (mitmproxy or equivalent) to "
                        "intercept traffic from the running app. The "
                        "captured flows contain sensitive data visible to "
                        "any party on the network path. For cleartext (HTTP) "
                        "leaks, ANY network intermediary (WiFi operator, ISP, "
                        "VPN provider) can read the data. For HTTPS leaks "
                        "in URLs, the data is logged by web servers, "
                        "browsers, and CDN caches."
                    ),
                    "sources": ["mitmproxy"],
                },
            ))

        return findings

    # ---------- Flow scanning ----------

    def _scan_flow(
        self,
        flow: Any,
        is_cleartext: bool,
        leaks_by_category: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Scan one captured flow for all sensitive-data patterns."""
        # Scan URL (high-severity location — URLs end up in logs)
        if flow.url:
            self._scan_text(
                flow.url, "url", flow, is_cleartext, leaks_by_category,
            )

        # Scan request headers
        for hname, hvalue in (flow.request_headers or {}).items():
            if not isinstance(hvalue, str):
                continue
            self._scan_text(
                hvalue, f"request_header:{hname}", flow, is_cleartext,
                leaks_by_category,
                is_auth_header=hname.lower() in _AUTH_HEADER_NAMES,
            )

        # Scan request body
        if flow.request_body:
            self._scan_text(
                flow.request_body, "request_body", flow, is_cleartext,
                leaks_by_category,
            )

        # Scan response headers (set-cookie etc.)
        for hname, hvalue in (flow.response_headers or {}).items():
            if not isinstance(hvalue, str):
                continue
            self._scan_text(
                hvalue, f"response_header:{hname}", flow, is_cleartext,
                leaks_by_category,
            )

        # Scan response body (look for tokens echoed back, PII leaks)
        if flow.response_body:
            self._scan_text(
                flow.response_body, "response_body", flow, is_cleartext,
                leaks_by_category,
            )

    def _scan_text(
        self,
        text: str,
        location: str,
        flow: Any,
        is_cleartext: bool,
        leaks_by_category: dict[str, list[dict[str, Any]]],
        is_auth_header: bool = False,
    ) -> None:
        for label, pattern, category in _SENSITIVE_PATTERNS:
            for match in pattern.finditer(text):
                matched = match.group(0)
                # Special filtering for auth tokens
                if category == "auth_token":
                    # In an Authorization header, a Bearer token is NORMAL
                    # (it's how OAuth works) — only flag if cleartext or in URL
                    if (is_auth_header and not is_cleartext
                            and location.startswith("request_header")):
                        # Token in Authorization header over HTTPS = normal
                        continue

                leaks_by_category[category].append({
                    "pattern": label,
                    "host": flow.host,
                    "url": flow.url,
                    "location": location,
                    "scheme": flow.scheme,
                    "value": matched,
                })

    # ---------- Severity assignment ----------

    @staticmethod
    def _severity_for_category(
        category: str, leaks: list[dict[str, Any]],
    ) -> tuple[Severity, float]:
        has_cleartext = any(leak["scheme"] == "http" for leak in leaks)
        has_url_leak = any(leak["location"] == "url" for leak in leaks)

        if category == "auth_token":
            if has_cleartext:
                return Severity.CRITICAL, 0.95
            if has_url_leak:
                return Severity.HIGH, 0.85
            return Severity.MEDIUM, 0.65  # token in body over HTTPS, rare

        if category == "api_key":
            if has_cleartext:
                return Severity.HIGH, 0.90
            return Severity.MEDIUM, 0.75

        if category == "credential":
            if has_cleartext:
                return Severity.CRITICAL, 0.95
            return Severity.HIGH, 0.80

        if category == "payment":
            if has_cleartext:
                return Severity.CRITICAL, 0.95
            return Severity.HIGH, 0.85

        if category == "pii":
            if has_cleartext:
                return Severity.MEDIUM, 0.75
            return Severity.LOW, 0.55

        return Severity.LOW, 0.50

    @staticmethod
    def _redact(value: str) -> str:
        """Show first 4 and last 4 chars, redact the middle."""
        if len(value) <= 12:
            return value[:4] + "***"
        return f"{value[:4]}...{value[-4:]}"

    @staticmethod
    def _build_recommendation(category: str) -> str:
        recommendations = {
            "auth_token": (
                "Never send auth tokens over cleartext HTTP. Always use HTTPS "
                "with cert pinning. Never include tokens in URLs (they end up "
                "in server logs, browser history, and referrer headers). Use "
                "the Authorization header with short-lived bearer tokens."
            ),
            "api_key": (
                "API keys should never travel from the mobile app over the "
                "network. Use a backend-for-frontend (BFF) pattern: store the "
                "API key on YOUR server, have the app authenticate to your "
                "server, then your server uses the API key on the app's behalf."
            ),
            "credential": (
                "Passwords should ALWAYS be sent over HTTPS, transmitted only "
                "to authentication endpoints, and never logged. Implement "
                "PBKDF2/scrypt/argon2 on the server. For the client, send "
                "password in a POST body, never in URL, never in GET request."
            ),
            "payment": (
                "Payment data must NEVER be transmitted directly through your "
                "app. Use PCI-compliant tokenization (Stripe, Braintree, Adyen) "
                "which gives you a one-use token to send to your backend. "
                "Storing or transmitting raw card data violates PCI-DSS."
            ),
            "pii": (
                "Personal information (email, phone, address) should only be "
                "transmitted over HTTPS, only to endpoints that need it, and "
                "should be minimized (don't send full profile when only "
                "user_id is needed)."
            ),
        }
        return recommendations.get(category, recommendations["pii"])
