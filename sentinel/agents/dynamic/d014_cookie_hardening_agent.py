"""D_014 — Cookie Hardening Audit.

Even when mobile apps use bearer tokens for first-party auth,
``Set-Cookie`` headers still show up: in OAuth redirect flows, in
embedded WebViews, in CDN-served pages, and in any path that touches
a Django / Rails / Flask backend. The cookie flags determine whether
a session cookie survives a network MITM, a malicious co-resident
script, or an iframed phishing page.

Detection
---------

We walk every ``Set-Cookie`` header in the mitmproxy response
headers across the session and group by ``host``. Each cookie is
scored on:

* ``Secure``    — sent only over TLS. Missing means a cleartext
  hijack target.
* ``HttpOnly``  — invisible to JavaScript. Missing means an XSS in
  any page on the host reads the cookie.
* ``SameSite``  — defends CSRF / cross-context bearer leakage.
  ``None`` is treated as "explicit opt-out" and is acceptable when
  paired with ``Secure``. Missing / ``unrestricted`` (no explicit
  attribute) is a finding for any session-shaped cookie.

A cookie is *session-shaped* when its name matches the canonical
session-id / auth token vocabulary (``sessionid``, ``session``,
``sid``, ``jsessionid``, ``phpsessid``, ``connect.sid``,
``laravel_session``, ``_session``, ``auth``, ``token``,
``access_token``, ``csrftoken``, ``xsrf-token``, ``access``,
``refresh``).

Findings (one per category, per (host, cookie_name)):

* **HIGH**   — session cookie without ``Secure`` flag.
* **HIGH**   — session cookie without ``HttpOnly`` flag.
* **MEDIUM** — session cookie without ``SameSite`` attribute.
* **MEDIUM** — session cookie with ``Domain=`` set to a parent
  domain (cookie leaks to every subdomain).
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_SESSION_NAMES = {
    "sessionid", "session", "sid", "jsessionid", "phpsessid",
    "connect.sid", "laravel_session", "_session",
    "auth", "token", "access_token", "csrftoken",
    "xsrf-token", "access", "refresh",
}
_NAME_VAL = re.compile(r"^\s*([^=]+)=([^;]*)(.*)$")
_ATTR = re.compile(r"\s*;\s*([^;=]+)(?:=([^;]*))?", re.IGNORECASE)


class CookieHardeningAgent(BaseAgent):
    """D_014: Set-Cookie hardening across the mitmproxy capture."""

    AGENT_ID = "D_014"
    VULN_CLASS = "Cookie Hardening Weakness"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_014] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        # Group findings (host, name) -> categories.
        no_secure: dict[tuple[str, str], dict[str, Any]] = {}
        no_httponly: dict[tuple[str, str], dict[str, Any]] = {}
        no_samesite: dict[tuple[str, str], dict[str, Any]] = {}
        parent_domain: dict[tuple[str, str], dict[str, Any]] = {}

        for flow in capture.flows:
            host = (getattr(flow, "host", "") or "").lower()
            headers = getattr(flow, "response_headers", {}) or {}
            cookies = _extract_set_cookies(headers)
            for cookie in cookies:
                name = cookie["name"].lower()
                if name not in _SESSION_NAMES:
                    # Apply the cookie-name allow-list strictly; we
                    # don't want to flag every analytics cookie.
                    continue
                key = (host, name)
                sample = {
                    "host": host,
                    "name": cookie["name"],
                    "attributes": cookie["attributes"],
                }
                if not cookie["secure"]:
                    no_secure[key] = sample
                if not cookie["httponly"]:
                    no_httponly[key] = sample
                if not cookie["samesite"]:
                    no_samesite[key] = sample
                if cookie["domain_is_parent"]:
                    parent_domain[key] = {
                        **sample,
                        "domain": cookie["domain_value"],
                    }

        findings: list[Finding] = []
        if no_secure:
            findings.append(self._missing_flag_finding(
                "Secure", list(no_secure.values()),
                severity=Severity.HIGH,
                why=(
                    "Without the ``Secure`` flag, the browser / "
                    "WebView will replay the session cookie over any "
                    "HTTP request to the host (downgrade, captive "
                    "portal, mixed-content load). A network attacker "
                    "captures the cookie in cleartext."
                ),
                fix=(
                    "Set the ``Secure`` attribute on every "
                    "session-shaped cookie. Combine with HSTS on the "
                    "server response so the browser never attempts "
                    "an HTTP request in the first place."
                ),
            ))
        if no_httponly:
            findings.append(self._missing_flag_finding(
                "HttpOnly", list(no_httponly.values()),
                severity=Severity.HIGH,
                why=(
                    "Without the ``HttpOnly`` flag, any JavaScript "
                    "running on the host can read the cookie via "
                    "``document.cookie``. An XSS on any page of the "
                    "host — including the marketing site or a "
                    "compromised support widget — exfiltrates the "
                    "session token."
                ),
                fix=(
                    "Set the ``HttpOnly`` attribute on every cookie "
                    "the front-end JS doesn't strictly need to read. "
                    "If the JS does need to read the value, that "
                    "value isn't a session token — split into two "
                    "cookies."
                ),
            ))
        if no_samesite:
            findings.append(self._missing_flag_finding(
                "SameSite", list(no_samesite.values()),
                severity=Severity.MEDIUM,
                why=(
                    "Without a ``SameSite`` attribute the cookie is "
                    "attached to cross-site sub-requests by default "
                    "on older Chromium and on Safari. An attacker "
                    "page iframes / submits to the host with the "
                    "victim's cookie attached — classic CSRF."
                ),
                fix=(
                    "Set ``SameSite=Lax`` for default browser "
                    "navigation behaviour, or ``SameSite=Strict`` "
                    "for high-value cookies. Only use "
                    "``SameSite=None`` for genuinely cross-site "
                    "cookies, and pair it with ``Secure``."
                ),
            ))
        if parent_domain:
            findings.append(self._parent_domain_finding(
                list(parent_domain.values()),
            ))
        return findings

    def _missing_flag_finding(
        self,
        flag: str,
        items: list[dict[str, Any]],
        *, severity: Severity, why: str, fix: str,
    ) -> Finding:
        return self._make_finding(
            vuln_class=f"Cookie Missing {flag} Flag",
            severity=severity,
            confidence=0.95,
            evidence={
                "issue": (
                    f"Session-shaped cookie(s) set without the "
                    f"``{flag}`` attribute. {why}"
                ),
                "occurrence_count": len(items),
                "samples": items[:8],
                "vector": (
                    "mitmproxy capture: response Set-Cookie headers "
                    "parsed and flagged when a session-name cookie "
                    "lacks the attribute."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=fix,
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
            if severity == Severity.HIGH
            else "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        )

    def _parent_domain_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Cookie Scoped To Parent Domain",
            severity=Severity.MEDIUM,
            confidence=0.85,
            evidence={
                "issue": (
                    "Session cookies are issued with ``Domain=`` set "
                    "to a parent domain (e.g. ``Domain=.example.com``). "
                    "Every subdomain — staging, marketing, "
                    "third-party hosted help center, abandoned "
                    "experimental subdomain — now receives the "
                    "cookie. An XSS or open redirect on any one of "
                    "them captures the session token."
                ),
                "occurrence_count": len(items),
                "samples": items[:8],
                "vector": (
                    "mitmproxy capture: Set-Cookie ``Domain`` "
                    "attribute compared against the response host."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Drop the ``Domain`` attribute so the cookie is "
                "host-only (the default). Use a separate session "
                "cookie per subdomain if the architecture really "
                "needs cross-subdomain auth, and front the parent "
                "domain with a CSP / iframe-busting policy."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        )


# ---------- helpers ----------


def _extract_set_cookies(headers: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull every Set-Cookie value out of the response headers.

    mitmproxy gives us a plain ``dict[str, str]`` so multiple
    Set-Cookie values land newline-joined or comma-joined depending on
    capture mode — we split on either."""
    raw_values: list[str] = []
    for h_name, h_val in headers.items():
        if h_name.lower() != "set-cookie":
            continue
        text = str(h_val)
        # Heuristic split: '\n' is the cleanest separator; the comma
        # split would falsely break on Expires=Wed, … so we only use
        # ``\n`` here.
        for line in text.split("\n"):
            line = line.strip()
            if line:
                raw_values.append(line)
    out: list[dict[str, Any]] = []
    for value in raw_values:
        cookie = _parse_set_cookie(value)
        if cookie:
            out.append(cookie)
    return out


def _parse_set_cookie(value: str) -> dict[str, Any] | None:
    m = _NAME_VAL.match(value)
    if not m:
        return None
    name = m.group(1).strip()
    attrs_str = m.group(3) or ""
    attrs: dict[str, str | bool] = {}
    for am in _ATTR.finditer(attrs_str):
        k = am.group(1).strip().lower()
        v = (am.group(2) or "").strip()
        attrs[k] = v or True
    secure = bool(attrs.get("secure"))
    httponly = bool(attrs.get("httponly"))
    samesite = attrs.get("samesite")
    domain_value = attrs.get("domain")
    domain_is_parent = False
    if isinstance(domain_value, str) and domain_value.startswith("."):
        domain_is_parent = True
    return {
        "name": name,
        "attributes": sorted(attrs.keys()),
        "secure": secure,
        "httponly": httponly,
        "samesite": bool(samesite),
        "domain_value": (
            domain_value if isinstance(domain_value, str) else None
        ),
        "domain_is_parent": domain_is_parent,
    }
