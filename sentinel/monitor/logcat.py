"""Logcat analysis — PII, credential, and debug-leak detection.

Consumes raw logcat text (from AdbRunner.logcat_dump) and emits
Finding objects for every class of sensitive data exposure.

Detection model:
  1. PII patterns   — email, phone, card, SSN, JWT, bearer tokens, API keys
  2. Password echoes — log lines whose tag or message contains "password"/"passwd"
  3. Debug-level leaks — V/D lines whose tags are on the sensitive-tag watchlist
  4. URL token leaks — query-param patterns (?token=, ?key=, ?api_key=)

Design decisions:
  - Regex-only, no LLM call: fast, no network, reproducible.
  - Per-pattern deduplication: one finding per pattern class, not per line.
    Evidence carries up to 20 example lines so a report stays readable.
  - Severity is tied to data class, not volume (one leaked card = CRITICAL).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.finding import Finding, Severity

AGENT_ID = "MON_001"

# ---------- logcat line format ----------

# MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG  : message
_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+?)\s*:\s+"
    r"(?P<msg>.*)$"
)

# ---------- PII / credential patterns ----------

@dataclass
class _Pattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    vuln_class: str
    owasp: str
    masvs: str
    recommendation: str


_PATTERNS: list[_Pattern] = [
    _Pattern(
        name="email_address",
        regex=re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
        severity=Severity.HIGH,
        vuln_class="PII Leak in Logcat — Email Address",
        owasp="M9",
        masvs="MASVS-STORAGE-2",
        recommendation="Remove user email addresses from log statements. Use a "
                       "privacy-safe identifier (e.g. hashed user ID) for debugging.",
    ),
    _Pattern(
        name="phone_number",
        regex=re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
        severity=Severity.HIGH,
        vuln_class="PII Leak in Logcat — Phone Number",
        owasp="M9",
        masvs="MASVS-STORAGE-2",
        recommendation="Remove phone numbers from log output. Log only redacted "
                       "last-4 digits or a stable opaque identifier.",
    ),
    _Pattern(
        name="credit_card",
        regex=re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d\d)\d{12})\b"),
        severity=Severity.CRITICAL,
        vuln_class="PCI-DSS Violation — Payment Card Number in Logcat",
        owasp="M9",
        masvs="MASVS-STORAGE-2",
        recommendation="Never log payment card data. Truncate to last 4 digits at "
                       "the point of capture; ensure no log call sites receive raw card numbers.",
    ),
    _Pattern(
        name="ssn",
        regex=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        severity=Severity.CRITICAL,
        vuln_class="PII Leak in Logcat — SSN / National ID",
        owasp="M9",
        masvs="MASVS-STORAGE-2",
        recommendation="Never log government-issued identifiers. Remove all log "
                       "statements that receive SSN or national ID values.",
    ),
    _Pattern(
        name="jwt_token",
        regex=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        severity=Severity.CRITICAL,
        vuln_class="Credential Leak in Logcat — JWT Token",
        owasp="M4",
        masvs="MASVS-AUTH-2",
        recommendation="Strip authentication tokens from all log statements. "
                       "If debugging auth flows, log only the token's `jti` claim.",
    ),
    _Pattern(
        name="bearer_token",
        regex=re.compile(r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}"),
        severity=Severity.CRITICAL,
        vuln_class="Credential Leak in Logcat — Bearer Token",
        owasp="M4",
        masvs="MASVS-AUTH-2",
        recommendation="Never log HTTP Authorization headers or bearer tokens. "
                       "Sanitize network request/response interceptors before logging.",
    ),
    _Pattern(
        name="api_key",
        regex=re.compile(
            r"(?:api[_\-]?key|apikey|x\-api\-key|access[_\-]?key)[=:\s\"']+([A-Za-z0-9\-_]{20,})",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        vuln_class="Credential Leak in Logcat — API Key",
        owasp="M9",
        masvs="MASVS-STORAGE-2",
        recommendation="Remove API key values from log output. Use key references "
                       "(e.g. key ID) for debugging, never the secret itself.",
    ),
    _Pattern(
        name="password_value",
        regex=re.compile(
            r"(?:password|passwd|secret|pwd)[=:\s\"']+\S{4,}",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        vuln_class="Credential Leak in Logcat — Password or Secret",
        owasp="M4",
        masvs="MASVS-AUTH-2",
        recommendation="Never log passwords or secrets. Audit all log call sites "
                       "in authentication and account-management flows.",
    ),
    _Pattern(
        name="url_token",
        regex=re.compile(
            r"https?://[^\s\"']*[?&](?:token|api_key|key|access_token|auth)=[A-Za-z0-9%\-_\.]{10,}",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        vuln_class="Credential Leak in Logcat — Token in URL Query Parameter",
        owasp="M9",
        masvs="MASVS-NETWORK-2",
        recommendation="Move authentication credentials from URL query parameters "
                       "to HTTP headers. Never log full URLs that contain credentials.",
    ),
    _Pattern(
        name="private_key_pem",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        vuln_class="Credential Leak in Logcat — Private Key Material",
        owasp="M4",
        masvs="MASVS-CRYPTO-2",
        recommendation="Never log private key material. Audit all crypto-related "
                       "code paths for accidental key serialization in log calls.",
    ),
]

# ---------- sensitive tag watchlist (debug-level leaks) ----------

_SENSITIVE_TAGS: frozenset[str] = frozenset({
    "Auth", "Authentication", "Login", "Password", "Crypto",
    "KeyStore", "Keychain", "Token", "OAuth", "JWT",
    "Payment", "Card", "Billing", "Account", "User",
    "PII", "Profile", "Location", "GPS", "Camera",
    "Microphone", "Contact", "Database", "SQLite",
    "SharedPreferences", "Preferences", "Config",
    "Network", "HTTP", "OkHttp", "Volley", "Retrofit",
    "WebView", "Cookie", "Session",
})

_DEBUG_LEVELS: frozenset[str] = frozenset({"V", "D"})

MAX_EVIDENCE_LINES = 20


# ---------- parsed line ----------

@dataclass
class _LogLine:
    ts: str
    pid: str
    level: str
    tag: str
    msg: str
    raw: str


def _parse_lines(logcat_text: str) -> list[_LogLine]:
    lines: list[_LogLine] = []
    for raw in logcat_text.splitlines():
        m = _LINE_RE.match(raw)
        if m:
            lines.append(_LogLine(
                ts=m.group("ts"),
                pid=m.group("pid"),
                level=m.group("level"),
                tag=m.group("tag").strip(),
                msg=m.group("msg"),
                raw=raw,
            ))
    return lines


# ---------- public API ----------

def analyze_logcat(
    logcat_text: str,
    session_id: str,
    *,
    tenant_id: str | None = None,
) -> list[Finding]:
    """Analyze raw logcat text and return a list of Findings.

    Args:
        logcat_text: Raw output from ``adb logcat -d -v time``.
        session_id:  Scan session identifier for the Finding objects.
        tenant_id:   Optional tenant context (SaaS multi-tenant).

    Returns:
        List of Finding objects, one per detected pattern class that
        has at least one matching line. Empty list if clean.
    """
    lines = _parse_lines(logcat_text)
    findings: list[Finding] = []

    findings.extend(_detect_pii_patterns(lines, session_id, tenant_id))
    findings.extend(_detect_debug_leaks(lines, session_id, tenant_id))

    return findings


def _detect_pii_patterns(
    lines: list[_LogLine],
    session_id: str,
    tenant_id: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    for pat in _PATTERNS:
        matched: list[dict[str, Any]] = []
        for line in lines:
            if pat.regex.search(line.msg):
                if len(matched) < MAX_EVIDENCE_LINES:
                    matched.append({
                        "ts": line.ts,
                        "level": line.level,
                        "tag": line.tag,
                        "snippet": line.msg[:200],
                    })

        if not matched:
            continue

        findings.append(Finding(
            agent_id=AGENT_ID,
            vuln_class=pat.vuln_class,
            severity=pat.severity,
            confidence=0.85,
            evidence={
                "pattern": pat.name,
                "match_count": len(matched),
                "examples": matched,
            },
            owasp=pat.owasp,
            masvs=pat.masvs,
            recommendation=pat.recommendation,
            session_id=session_id,
            tenant_id=tenant_id,
            verification_status="Verified",
            verification_state="verified",
            finding_category="Static_Tool",
        ))

    return findings


def _detect_debug_leaks(
    lines: list[_LogLine],
    session_id: str,
    tenant_id: str | None,
) -> list[Finding]:
    """Flag Verbose/Debug log lines from sensitive-tagged components."""
    by_tag: dict[str, list[dict[str, Any]]] = {}

    for line in lines:
        if line.level not in _DEBUG_LEVELS:
            continue
        tag_normalised = line.tag.strip()
        for sensitive in _SENSITIVE_TAGS:
            if sensitive.lower() in tag_normalised.lower():
                bucket = by_tag.setdefault(tag_normalised, [])
                if len(bucket) < MAX_EVIDENCE_LINES:
                    bucket.append({
                        "ts": line.ts,
                        "level": line.level,
                        "tag": line.tag,
                        "snippet": line.msg[:200],
                    })
                break

    findings: list[Finding] = []
    for tag, examples in by_tag.items():
        findings.append(Finding(
            agent_id=AGENT_ID,
            vuln_class=f"Verbose/Debug Logging from Sensitive Component: {tag}",
            severity=Severity.MEDIUM,
            confidence=0.70,
            evidence={
                "tag": tag,
                "line_count": len(examples),
                "examples": examples,
            },
            owasp="M9",
            masvs="MASVS-STORAGE-2",
            recommendation=(
                f"The '{tag}' component emits Verbose/Debug log lines in a "
                "production build. Wrap all sensitive log calls in "
                "`if (BuildConfig.DEBUG)` guards and strip them at release time "
                "using ProGuard/R8 rules."
            ),
            session_id=session_id,
            tenant_id=tenant_id,
            verification_status="Verified",
            verification_state="verified",
            finding_category="Static_Tool",
        ))

    return findings
