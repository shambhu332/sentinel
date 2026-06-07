"""D_013 — PII / Credential Exfiltration to Third-Party Endpoints.

Mobile apps routinely embed analytics, crash reporters, marketing
SDKs, ad networks, and feature-flag services. These vendors operate
on different hosts than the app's own backend, and they routinely
receive event payloads built from in-app state. Two well-known bug
classes follow:

* **Token exfiltration** — the app reuses a bearer token, session
  cookie, or refresh token across vendors, putting it inside an
  analytics ``properties`` blob. Anyone with access to the analytics
  account (vendor staff, compromised marketing employee, leaked
  S3 export) now has every user's session.
* **PII / credential leakage** — passwords, OTPs, account numbers,
  full names, emails, and government IDs end up in crash reports,
  Sentry breadcrumbs, Firebase Analytics events, or postback URLs.

Detection
---------

A flow is a candidate when:

1. The host is *not* under the application's own root domain
   (heuristic from the package), AND
2. The host matches a known third-party SDK / analytics / crash /
   ad-network domain pattern (sentry, datadog, segment, mixpanel,
   amplitude, branch, appsflyer, adjust, firebase analytics,
   google analytics, doubleclick, facebook graph, snowplow, etc.).

Then we check the outbound payload (URL query, request body) for:

* JWT-shaped values   — flag as ``token_in_telemetry``.
* Bearer tokens / cookies in body — flag as ``token_in_telemetry``.
* Email addresses    — flag as ``pii_in_telemetry``.
* Phone numbers / IBANs / SSNs / card-shaped (Luhn-suspect) — flag
  as ``pii_in_telemetry``.
* Strings under JSON keys named ``password`` / ``passwd`` / ``pwd`` /
  ``otp`` / ``pin`` / ``secret`` — flag as ``credential_in_telemetry``.

Findings:

* **CRITICAL** — credential in telemetry (passwords / OTPs).
* **HIGH**     — token or session ID in telemetry.
* **MEDIUM**   — PII (email / phone / IBAN / SSN / card-shape) in
  telemetry.

One consolidated finding per category, with up to 5 sample flows.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_THIRD_PARTY_HOSTS = (
    "sentry.io", "ingest.sentry", "datadoghq", "segment.io", "segment.com",
    "mixpanel.com", "amplitude.com", "branch.io",
    "appsflyer.com", "adjust.com", "kochava.com",
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "doubleclick.net", "googleadservices.com",
    "facebook.com", "graph.facebook", "fbcdn",
    "snowplow", "heap.io", "fullstory.com", "hotjar.com",
    "newrelic.com", "bugsnag.com", "rollbar.com",
    "firebaseio.com", "googleapis.com/firebase",
    "intercom.io", "smartlook.com", "logz.io", "loggly.com",
)
_JWT_RE = re.compile(
    r"\b[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b",
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
)
_PHONE_RE = re.compile(r"\+?\d[\d\s\-]{7,15}\d")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_CRED_JSON_KEYS = re.compile(
    r'"(?:password|passwd|pwd|otp|pin|secret|access_token|'
    r'refresh_token|api_key|api_secret)"\s*:\s*"([^"]{3,})"',
    re.IGNORECASE,
)


class ThirdPartyPiiLeakAgent(BaseAgent):
    """D_013: detect tokens / credentials / PII leaving to third-parties."""

    AGENT_ID = "D_013"
    VULN_CLASS = "Sensitive Data Sent to Third-Party Endpoint"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_013] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        package = (self._context.manifest or {}).get("package") or ""
        own_root = _root_domain_from_package(package)

        credential_hits: list[dict[str, Any]] = []
        token_hits: list[dict[str, Any]] = []
        pii_hits: list[dict[str, Any]] = []

        for flow in capture.flows:
            host = (getattr(flow, "host", "") or "").lower()
            if not host:
                continue
            if own_root and host.endswith(own_root):
                continue
            if not _is_third_party(host):
                continue

            method = getattr(flow, "method", "") or ""
            path = getattr(flow, "path", "") or ""
            url = getattr(flow, "url", "") or ""
            body = (getattr(flow, "request_body", "") or "")[:32000]
            corpus = f"{url}\n{body}"

            sample = {
                "host": host,
                "method": method,
                "path": path,
            }

            # ---- credentials in telemetry (CRITICAL) ----
            cred_match = _CRED_JSON_KEYS.search(body)
            if cred_match:
                credential_hits.append({
                    **sample,
                    "key_seen": cred_match.group(0).split(":", 1)[0]
                                  .strip().strip('"'),
                })
                continue

            # ---- tokens in telemetry (HIGH) ----
            if _JWT_RE.search(corpus) or _BEARER_RE.search(corpus):
                token_hits.append(sample)
                continue

            # ---- PII (MEDIUM) ----
            if (_EMAIL_RE.search(corpus)
                    or _SSN_RE.search(corpus)
                    or _IBAN_RE.search(corpus)
                    or _looks_card(corpus)
                    or _PHONE_RE.search(corpus)):
                pii_hits.append(sample)

        findings: list[Finding] = []
        if credential_hits:
            findings.append(self._cred_finding(credential_hits))
        if token_hits:
            findings.append(self._token_finding(token_hits))
        if pii_hits:
            findings.append(self._pii_finding(pii_hits))
        return findings

    def _cred_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Credential Leaked to Third-Party Endpoint",
            severity=Severity.CRITICAL,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application sent a request body to a third-"
                    "party telemetry / analytics / crash-report "
                    "endpoint that contains a JSON key named "
                    "``password`` / ``otp`` / ``pin`` / ``secret`` / "
                    "``access_token`` / ``refresh_token`` / ``api_key`` "
                    "/ ``api_secret`` with a non-empty string value. "
                    "Anyone with access to the vendor account "
                    "(vendor staff, compromised marketing employee, "
                    "leaked export) reads the credential in cleartext."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: outbound flow to a third-"
                    "party host; request body scanned for "
                    "credential-named JSON keys."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Never include user secrets in analytics or crash "
                "reports. Configure the SDK's redaction allow-list "
                "(Sentry beforeSend, Datadog beforeSend, Segment "
                "transformations) to drop or hash credential-named "
                "fields. Audit your SDK setup: most vendors offer a "
                "shared-helper that intercepts every event before "
                "it leaves the device. Treat any secret in telemetry "
                "as already compromised — rotate immediately."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _token_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Bearer Token Leaked to Third-Party Endpoint",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application sent a JWT-shaped or "
                    "``Bearer <token>``-shaped string to a third-"
                    "party host. The same token authenticates the "
                    "user to the app's own backend, so any party "
                    "with access to the vendor's logs (vendor staff, "
                    "data-export downstream, breach) can impersonate "
                    "the user."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: outbound flow to a third-"
                    "party host; URL and request body scanned for "
                    "JWT and Bearer-token shapes."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Never expose bearer tokens to telemetry. Configure "
                "the SDK to drop any property named "
                "``Authorization`` / ``access_token`` / "
                "``id_token``. If the token leaked through an HTTP "
                "header (e.g., a proxy or breadcrumb capturing the "
                "outbound headers), strip the Authorization header "
                "from the SDK's request-capture before any record "
                "leaves the device. Rotate any token observed in a "
                "vendor log."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _pii_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="PII Sent to Third-Party Endpoint",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application sent PII-shaped values (email, "
                    "phone, IBAN, SSN, or 13-19 digit card-shaped) "
                    "to a third-party telemetry / analytics endpoint. "
                    "Per GDPR Art. 44 and India DPDP Act §7, "
                    "transmission of personal data to a non-first-"
                    "party processor requires lawful basis, contract, "
                    "and documented user consent."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: outbound flow to a third-"
                    "party host; URL + request body scanned for "
                    "canonical PII regex shapes."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Hash or remove PII before it enters a telemetry "
                "event. Most vendors expose a beforeSend hook (Sentry, "
                "Datadog) or a transformation step (Segment) that "
                "lets you scrub email / phone / IBAN keys with one "
                "redact call. Confirm the SDK is configured to "
                "respect Limit Ad Tracking / Do Not Track. Confirm "
                "your privacy policy lists every third-party endpoint "
                "PII reaches."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )


# ---------- helpers ----------


def _root_domain_from_package(package: str) -> str:
    if not package:
        return ""
    parts = package.split(".")
    if len(parts) < 2:
        return package
    return f"{parts[1]}.{parts[0]}".lower()


def _is_third_party(host: str) -> bool:
    return any(host.endswith(suf) or suf in host for suf in _THIRD_PARTY_HOSTS)


def _looks_card(corpus: str) -> bool:
    """Card-shape + Luhn-suspect. We avoid running full Luhn on the
    entire body — only on a small set of plausible substrings — to
    keep this fast."""
    for m in _CARD_RE.finditer(corpus):
        digits = re.sub(r"\D", "", m.group(0))
        if not (13 <= len(digits) <= 19):
            continue
        if _passes_luhn(digits):
            return True
    return False


def _passes_luhn(s: str) -> bool:
    try:
        total = 0
        rev = s[::-1]
        for i, ch in enumerate(rev):
            d = int(ch)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except (ValueError, TypeError):
        return False
