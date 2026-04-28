"""A_007 — Insecure Logging Agent.

Detects Log.* calls that print sensitive data (credentials, tokens, PII)
to logcat, where they're readable by any app holding READ_LOGS permission
or by anyone with adb access.

Why this matters: logcat output persists in device buffers and crash dumps.
Apps with READ_LOGS or rooted devices can dump everything. On older Android
versions (pre-4.1) any app could read logs without permission. Bug bounty
programs pay $200-$1000 for credential leaks via logging, more if the leaked
data includes session tokens or auth credentials.

Detection pipeline:
1. Walk decompiled .java files
2. Find Log.d / Log.e / Log.i / Log.v / Log.w / System.out.println calls
3. Check if the logged content references variables named password, token,
   secret, credit_card, ssn, etc.
4. Severity scales by sensitivity of the leaked field
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Sensitive variable name patterns. We look for these inside Log.* calls.
# Each tuple: (display_name, regex_inside_log_call, severity)
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("password", re.compile(
        r"\bpassword\b|\bpasswd\b|\bpwd\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("token / API key", re.compile(
        r"\b(?:auth_?token|access_?token|api_?key|session_?token|jwt|bearer)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("credit card / payment", re.compile(
        r"\b(?:credit_?card|cc_?num|cvv|card_?number|pan)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("SSN / national ID", re.compile(
        r"\b(?:ssn|social_?security|national_?id|aadhaar|aadhar)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("PIN / OTP", re.compile(
        r"\b(?:pin_?code|otp|one_?time|verification_?code)\b",
        re.IGNORECASE,
    ), Severity.MEDIUM),
    ("secret / private key", re.compile(
        r"\b(?:secret|private_?key|priv_?key|cert_?key)\b",
        re.IGNORECASE,
    ), Severity.MEDIUM),
]

# Match any Log.X(...) or System.out.println(...) call, capturing the args
_LOG_CALL_RE = re.compile(
    r'(?:Log\.[devwif]|System\.(?:out|err)\.println|Timber\.[devwif])\s*\(([^;]*?)\)\s*;',
    re.IGNORECASE | re.DOTALL,
)

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_FINDING = 20

# ProGuard rule example used in remediation. Defined as a plain string so we
# don't have to wrestle with f-string brace escaping.
_PROGUARD_RULE_EXAMPLE = (
    "-assumenosideeffects class android.util.Log { "
    "public static *** d(...); "
    "public static *** v(...); "
    "public static *** i(...); "
    "}"
)


class InsecureLoggingAgent(BaseAgent):
    """A_007: detects sensitive data printed to log output."""

    AGENT_ID = "A_007"
    VULN_CLASS = "Insecure Logging"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[A_007] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        # Group hits by sensitivity category
        hits_by_category: dict[str, list[dict[str, Any]]] = {}
        category_severity: dict[str, Severity] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[A_007] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for log_match in _LOG_CALL_RE.finditer(text):
                args = log_match.group(1)
                # For each sensitivity pattern, check if it appears in the args
                for category, sense_pat, severity in _SENSITIVE_PATTERNS:
                    if sense_pat.search(args):
                        # Capture the full call line
                        start = max(0, text.rfind("\n", 0, log_match.start()) + 1)
                        end = text.find("\n", log_match.end())
                        if end == -1:
                            end = len(text)
                        line = text[start:end].strip()

                        hits_by_category.setdefault(category, []).append({
                            "file": rel,
                            "context": line[:200],
                            "matched": log_match.group(0)[:120],
                        })
                        category_severity[category] = severity
                        break  # one category per hit

        if not hits_by_category:
            logger.info("[A_007] No insecure logging detected")
            return []

        package = (ctx.manifest or {}).get("package", "?")

        # One finding per category
        findings: list[Finding] = []
        for category, instances in hits_by_category.items():
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=category_severity[category],
                confidence=0.70,
                recommendation=self._build_recommendation(category),
                evidence={
                    "title": f"Sensitive Data in Logs: {category}",
                    "category": category,
                    "package": package,
                    "match_count": len(instances),
                    "hits": instances[:_MAX_HITS_PER_FINDING],
                    "vector": (
                        f"Run `adb logcat | grep -i {category.split()[0]}` "
                        f"while exercising the application. The {category} value "
                        f"appears in plaintext in the log buffer, accessible to "
                        f"any app holding READ_LOGS permission or to anyone "
                        f"with USB debugging access to the device."
                    ),
                },
            ))

        return findings

    @staticmethod
    def _build_recommendation(category: str) -> str:
        # Build the recommendation by concatenating regular strings; the ProGuard
        # rule example contains literal { and } characters that f-strings choke on.
        return (
            "Remove all log statements containing " + category + " from production "
            "builds. Use BuildConfig.DEBUG to gate Log.* calls so they only "
            "execute in development. Better still, use ProGuard/R8 rules to "
            "strip Log.d, Log.v, and Log.i calls from release builds entirely. "
            "Example proguard-rules.pro entry:\n"
            + _PROGUARD_RULE_EXAMPLE + "\n"
            "For data that must be logged (debugging, crash reports), redact "
            "sensitive fields before logging — for example, log only the last "
            "4 digits of a credit card number, never the full PAN."
        )
