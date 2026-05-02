"""A_001 — Insecure Authentication Token Storage Agent.

Detects authentication tokens, session identifiers, and credentials being
written to insecure storage locations: SharedPreferences (plain), files
on disk, SQLite databases, or external storage. Distinct from C_006 in
that it specifically focuses on auth-relevant material and follows the
data flow across multiple storage APIs, not just SharedPreferences.

Why this matters: tokens and stored credentials can be exfiltrated by:
- Other apps with READ_EXTERNAL_STORAGE (if on /sdcard)
- Anyone with adb backup access (if allowBackup=true)
- Anyone with root access (always)
- Malware exploiting an unrelated vulnerability to read the token

Once a token or credential is stolen, the attacker can impersonate the
user until the token expires or is revoked. Bug bounty programs typically
rate this as High severity, paying $500-$3,000 with confirmed account
takeover demos paying significantly more.

Detection pipeline:
1. Walk decompiled Java files
2. Find variables/strings containing auth-related terms (modern token
   keywords AND traditional credential keywords)
3. Look for writes to persistent storage near those references
4. Storage APIs: SharedPreferences, FileOutputStream, SQLiteDatabase,
   getExternalStorageDirectory, Environment.getExternalStorageDirectory
5. Check for use of Android Keystore — if Keystore is used, downgrade severity
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Auth-related context — files containing these are candidates for analysis.
# Three families covered:
#   1. Modern token keywords (snake_case, common in OAuth/JWT apps)
#   2. CamelCase variants (older Android Java code style)
#   3. Credential storage keywords (legacy apps that persist username/password)
_AUTH_CONTEXT_RE = re.compile(
    # --- Token-style patterns (snake_case) ---
    r"\b(?:auth_?token|access_?token|refresh_?token|bearer|jwt|"
    r"session_?token|id_?token|api_?key|api_?secret|client_?secret|"
    r"login_?token|"
    # --- CamelCase variants (older Android codebases) ---
    r"authToken|accessToken|refreshToken|sessionToken|"
    r"loginToken|apiKey|apiSecret|clientSecret|"
    # --- "Encrypted" / "Secure" prefixed credential keys ---
    # Common pattern: developer KNOWS the data is sensitive (so labels it
    # "Encrypted" or "Secure") but still stores it badly.
    r"encryptedUsername|encryptedPassword|"
    r"securePassword|superSecure|"
    # --- "Saved" / "Stored" / "Cached" credential prefixes ---
    # Common in "remember me" feature implementations.
    r"savedPassword|storedPassword|cachedPassword|"
    r"savedCredential|storedCredential)\b",
    re.IGNORECASE,
)

# Insecure storage API patterns
_STORAGE_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("External storage (sdcard)", re.compile(
        r"\b(?:getExternalStorageDirectory|Environment\.getExternalStoragePublicDirectory|"
        r"getExternalFilesDir|/sdcard/|EXTERNAL_STORAGE)\b",
    ), Severity.HIGH),
    ("Plain SharedPreferences", re.compile(
        r"\.getSharedPreferences\s*\(",
    ), Severity.HIGH),
    ("FileOutputStream", re.compile(
        r"\bnew\s+FileOutputStream\s*\(|\.openFileOutput\s*\(",
    ), Severity.MEDIUM),
    ("SQLite database", re.compile(
        r"\b(?:SQLiteDatabase|SQLiteOpenHelper|openOrCreateDatabase)\b",
    ), Severity.MEDIUM),
]

# Markers that this code IS using secure storage (downgrade or skip)
_SECURE_STORAGE_RE = re.compile(
    r"\b(?:EncryptedSharedPreferences|EncryptedFile|"
    r"AndroidKeyStore|KeyStore\.getInstance\s*\(\s*\"AndroidKeyStore\")\b",
)

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_FINDING = 20
# How close (in chars) the storage API call must be to the auth context.
# Bumped from 500 to 1000 because real Android code often has the
# getSharedPreferences() call in onCreate() and the putString() call in a
# button handler several methods later — they can be 600-800 chars apart in
# the decompiled output.
_PROXIMITY_WINDOW = 1000


class InsecureAuthStorageAgent(BaseAgent):
    """A_001: detects auth tokens or credentials persisted to insecure storage."""

    AGENT_ID = "A_001"
    VULN_CLASS = "Insecure Auth Token Storage"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[A_001] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        hits_by_storage: dict[str, list[dict[str, Any]]] = {}
        storage_severity: dict[str, Severity] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[A_001] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            # Quick filter — file must contain SOME auth context
            auth_matches = list(_AUTH_CONTEXT_RE.finditer(text))
            if not auth_matches:
                continue

            # Check if file uses secure storage as a downgrade signal
            uses_secure_storage = bool(_SECURE_STORAGE_RE.search(text))

            rel = str(path.relative_to(ctx.decompiled_dir))

            # For each storage pattern, check if it appears near an auth context
            for storage_name, storage_pat, base_severity in _STORAGE_PATTERNS:
                for storage_match in storage_pat.finditer(text):
                    # Check proximity to any auth match
                    nearest_auth = min(
                        (abs(storage_match.start() - am.start()) for am in auth_matches),
                        default=None,
                    )
                    if nearest_auth is None or nearest_auth > _PROXIMITY_WINDOW:
                        continue

                    # If the file uses secure storage, downgrade severity
                    severity = base_severity
                    if uses_secure_storage:
                        # Drop one severity level
                        downgrade_map = {
                            Severity.HIGH: Severity.MEDIUM,
                            Severity.MEDIUM: Severity.LOW,
                        }
                        severity = downgrade_map.get(severity, severity)

                    # Capture line for evidence
                    start = max(0, text.rfind("\n", 0, storage_match.start()) + 1)
                    end = text.find("\n", storage_match.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end].strip()

                    hits_by_storage.setdefault(storage_name, []).append({
                        "file": rel,
                        "context": line[:200],
                        "matched": storage_match.group(0)[:80],
                        "auth_proximity_chars": nearest_auth,
                        "uses_secure_storage_in_file": uses_secure_storage,
                    })
                    # Use highest severity seen for this storage type
                    existing = storage_severity.get(storage_name)
                    if existing is None or _severity_rank(severity) > _severity_rank(existing):
                        storage_severity[storage_name] = severity

        if not hits_by_storage:
            logger.info("[A_001] No insecure auth token storage detected")
            return []

        package = (ctx.manifest or {}).get("package", "?")
        findings: list[Finding] = []

        for storage_name, instances in hits_by_storage.items():
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=storage_severity[storage_name],
                confidence=0.70,
                recommendation=self._build_recommendation(storage_name),
                evidence={
                    "title": f"Auth Tokens Stored Insecurely: {storage_name}",
                    "storage_type": storage_name,
                    "package": package,
                    "match_count": len(instances),
                    "hits": instances[:_MAX_HITS_PER_FINDING],
                    "vector": (
                        f"Authentication tokens or credentials are written to "
                        f"{storage_name} without encryption. An attacker with "
                        "file system access (rooted device, adb backup if "
                        "allowBackup=true, or another app with "
                        "READ_EXTERNAL_STORAGE for sdcard) can read the data "
                        "and use it to impersonate the user."
                    ),
                },
            ))

        return findings

    @staticmethod
    def _build_recommendation(storage_name: str) -> str:
        base = (
            "Authentication tokens and stored credentials should be held in "
            "the Android Keystore, not in plain files or databases. The "
            "Android Keystore provides hardware-backed key storage on "
            "supported devices and is the recommended location for any "
            "cryptographic key or sensitive credential."
        )

        specifics = {
            "External storage (sdcard)": (
                " URGENT: external storage is readable by any app with "
                "READ_EXTERNAL_STORAGE permission. Move all auth-related data "
                "to internal storage immediately, then encrypt at rest."
            ),
            "Plain SharedPreferences": (
                " Replace SharedPreferences with EncryptedSharedPreferences "
                "(androidx.security:security-crypto) for any auth token or "
                "credential storage."
            ),
            "FileOutputStream": (
                " Use EncryptedFile from the Jetpack Security library, or "
                "encrypt the file contents using a key from Android Keystore."
            ),
            "SQLite database": (
                " Use SQLCipher (encrypted SQLite) for any database storing "
                "authentication or session data, with the database key held "
                "in the Android Keystore."
            ),
        }

        return base + specifics.get(storage_name, "")


def _severity_rank(s: Severity) -> int:
    """Higher rank = more severe."""
    return {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }.get(s, 0)
