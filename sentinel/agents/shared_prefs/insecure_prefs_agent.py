"""STG_006 — Insecure SharedPreferences Agent.

(Renamed from C_006 to resolve a duplicate AGENT_ID collision with
c006_ecb_mode.EcbModeAgent. ECB keeps C_006; SharedPrefs moves to
STG_006 under the new STG_* storage prefix.)

Detects Android applications that store sensitive data in plain
SharedPreferences instead of using EncryptedSharedPreferences (Jetpack
Security library) or the Android Keystore.

Why this matters: SharedPreferences are stored as XML files in the app's
private data directory. On a rooted device, or via `adb backup` if backup
is enabled, anyone can read these files and extract any tokens, passwords,
or credentials stored within. Modern Android (API 23+) provides
EncryptedSharedPreferences which transparently encrypts both keys and
values using AES-256-GCM with hardware-backed keys when available.
Failing to use it for sensitive data is a Medium-to-High severity bug.

Detection pipeline:
1. Walk decompiled Java files looking for getSharedPreferences()
2. For each call, look for putString()/putInt() near sensitive keys
3. Sensitive keys: token, password, secret, auth, credential, session, key,
   pin, cvv, ssn, cardnumber
4. Verify the file is NOT using EncryptedSharedPreferences
5. Severity scales: High if auth-related, Medium otherwise
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Sensitive key patterns to look for in put*() calls
_SENSITIVE_KEY_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("Authentication tokens", re.compile(
        r"\b(?:auth_?token|access_?token|refresh_?token|bearer|session_?token|"
        r"id_?token|jwt)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("Passwords", re.compile(
        r"\bpassword\b|\bpasswd\b|\bpwd\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("API keys / secrets", re.compile(
        r"\b(?:api_?key|api_?secret|client_?secret|app_?secret|secret_?key)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("Credit card / payment", re.compile(
        r"\b(?:credit_?card|card_?number|cvv|cvc|pan)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("Personal identifiers", re.compile(
        r"\b(?:ssn|social_?security|aadhaar|aadhar|national_?id|passport)\b",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("Session / credentials", re.compile(
        r"\b(?:credential|session_?id|user_?id|account_?id)\b",
        re.IGNORECASE,
    ), Severity.MEDIUM),
    ("PINs / OTPs", re.compile(
        r"\b(?:pin_?code|otp|verification_?code)\b",
        re.IGNORECASE,
    ), Severity.MEDIUM),
]

# putString / putInt / putLong / putFloat / putBoolean calls.
# Also Editor methods.
_PUT_CALL_RE = re.compile(
    r'\.put(?:String|Int|Long|Float|Boolean|StringSet)\s*\(\s*"([^"]+)"',
    re.IGNORECASE,
)

# Detect EncryptedSharedPreferences usage — if present in the file, treat
# usages as safer.
_ENCRYPTED_PREFS_RE = re.compile(
    r"\bEncryptedSharedPreferences\b",
)

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_FINDING = 20


class InsecureSharedPrefsAgent(BaseAgent):
    """STG_006: detects sensitive data in unencrypted SharedPreferences."""

    AGENT_ID = "STG_006"
    VULN_CLASS = "Insecure SharedPreferences"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[STG_006] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        hits_by_category: dict[str, list[dict[str, Any]]] = {}
        category_severity: dict[str, Severity] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[STG_006] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            # If this file uses EncryptedSharedPreferences, treat it as safer
            # and skip — at least the developer is aware of the issue.
            if _ENCRYPTED_PREFS_RE.search(text):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for put_match in _PUT_CALL_RE.finditer(text):
                key_name = put_match.group(1)
                # Check if key name matches a sensitive pattern
                for category, pat, severity in _SENSITIVE_KEY_PATTERNS:
                    if pat.search(key_name):
                        # Capture line for evidence
                        start = max(0, text.rfind("\n", 0, put_match.start()) + 1)
                        end = text.find("\n", put_match.end())
                        if end == -1:
                            end = len(text)
                        line = text[start:end].strip()

                        hits_by_category.setdefault(category, []).append({
                            "file": rel,
                            "key": key_name,
                            "context": line[:200],
                        })
                        category_severity[category] = severity
                        break

        if not hits_by_category:
            logger.info("[STG_006] No sensitive SharedPreferences usage detected")
            return []

        package = (ctx.manifest or {}).get("package", "?")
        findings: list[Finding] = []

        for category, instances in hits_by_category.items():
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=category_severity[category],
                confidence=0.75,
                recommendation=self._build_recommendation(category),
                evidence={
                    "title": f"Sensitive Data in Plain SharedPreferences: {category}",
                    "category": category,
                    "package": package,
                    "match_count": len(instances),
                    "hits": instances[:_MAX_HITS_PER_FINDING],
                    "vector": (
                        "On a rooted device or via `adb backup` (if allowBackup=true), "
                        f"extract the SharedPreferences XML from "
                        f"/data/data/{package}/shared_prefs/. The "
                        f"{category} value will be present in plaintext, "
                        "directly readable. No decryption required."
                    ),
                },
            ))

        return findings

    @staticmethod
    def _build_recommendation(category: str) -> str:
        return (
            f"Replace plain SharedPreferences with EncryptedSharedPreferences "
            f"from the Jetpack Security library (androidx.security:security-crypto) "
            f"for any storage of {category}. Example:\n"
            "  MasterKey masterKey = new MasterKey.Builder(context)\n"
            "      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();\n"
            "  SharedPreferences prefs = EncryptedSharedPreferences.create(\n"
            "      context, \"secure_prefs\", masterKey,\n"
            "      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n"
            "      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);\n"
            "EncryptedSharedPreferences encrypts both keys and values using "
            "AES-256, with the master key stored in the Android Keystore "
            "(hardware-backed when available). For tokens that should be "
            "ephemeral, also consider storing only in memory and re-fetching "
            "on app launch instead of persisting."
        )
