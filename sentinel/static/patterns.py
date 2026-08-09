"""Centralized static analysis pattern catalog.

All grep/regex patterns used across Sentinel agents live here.
Agents import from this module instead of embedding raw strings,
so a pattern fix propagates everywhere automatically.

Pattern groups are organized by vulnerability category, matching
the OWASP Mobile Top 10 / MASVS control mapping. Each entry is a
:class:`GrepPattern` with:
  - ``pattern``:  Python-compatible regex (re.search semantics)
  - ``label``:    short human-readable description for evidence keys
  - ``severity``: default Severity for a match
  - ``owasp``:    OWASP Mobile category string
  - ``masvs``:    MASVS v2 control ID

Usage::

    from sentinel.static.patterns import PATTERNS_BY_CATEGORY, GrepPattern
    from sentinel.static.patterns import CRYPTO_PATTERNS, HARDCODED_SECRETS

    for pat in CRYPTO_PATTERNS:
        if re.search(pat.pattern, code):
            ...
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.finding import Severity


@dataclass(frozen=True)
class GrepPattern:
    pattern: str
    label: str
    severity: Severity = Severity.MEDIUM
    owasp: str = ""
    masvs: str = ""
    note: str = ""


# ── Hardcoded Secrets / Credentials ──────────────────────────────────────────

HARDCODED_SECRETS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'(?i)(password|passwd|pwd)\s*=\s*"[^"]{4,}"',
        "Hardcoded password literal",
        Severity.CRITICAL,
        "M1: Improper Credential Usage",
        "MASVS-AUTH-2",
    ),
    GrepPattern(
        r'(?i)(api[_-]?key|apikey)\s*=\s*"[A-Za-z0-9+/]{20,}"',
        "Hardcoded API key",
        Severity.HIGH,
        "M1: Improper Credential Usage",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'(?i)(secret|token|bearer)\s*=\s*"[^"]{8,}"',
        "Hardcoded secret/token",
        Severity.HIGH,
        "M1: Improper Credential Usage",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'(?i)aws[_-]?access[_-]?key[_-]?id\s*=\s*"AKIA[0-9A-Z]{16}"',
        "Hardcoded AWS access key",
        Severity.CRITICAL,
        "M1: Improper Credential Usage",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'AIza[0-9A-Za-z\-_]{35}',
        "Hardcoded Google API key (AIza prefix)",
        Severity.HIGH,
        "M1: Improper Credential Usage",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'(?i)private[_\s]?key\s*=\s*"-----BEGIN',
        "Hardcoded private key PEM block",
        Severity.CRITICAL,
        "M1: Improper Credential Usage",
        "MASVS-CRYPTO-2",
    ),
    GrepPattern(
        r'(?i)(jdbc|db)[_\s]?(url|uri|password)\s*=\s*"[^"]{6,}"',
        "Hardcoded database credential",
        Severity.HIGH,
        "M1: Improper Credential Usage",
        "MASVS-STORAGE-1",
    ),
)

# ── Weak / Insecure Cryptography ──────────────────────────────────────────────

CRYPTO_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'getInstance\s*\(\s*"DES(?:ede)?"',
        "DES/3DES — broken symmetric cipher",
        Severity.HIGH,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'getInstance\s*\(\s*"(?:AES/ECB|AES(?!/))',
        "AES/ECB or raw AES — no IV, deterministic",
        Severity.HIGH,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'getInstance\s*\(\s*"RC[24]"',
        "RC2/RC4 — broken stream cipher",
        Severity.HIGH,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"',
        "MD5/SHA-1 — collision-vulnerable hash",
        Severity.MEDIUM,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'new\s+SecureRandom\s*\(\s*"[^"]+"\s*\)',
        "SecureRandom seeded with constant string",
        Severity.HIGH,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'IvParameterSpec\s*\(\s*new\s+byte\s*\[',
        "Static/zero IV in IvParameterSpec",
        Severity.HIGH,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
    ),
    GrepPattern(
        r'PBEKeySpec\s*\(.*,\s*\d+\s*\)',
        "PBEKeySpec with hardcoded iteration count",
        Severity.MEDIUM,
        "M10: Insufficient Cryptography",
        "MASVS-CRYPTO-1",
        "Check iteration count is ≥ 310000 for PBKDF2-SHA256",
    ),
)

# ── Insecure Data Storage ─────────────────────────────────────────────────────

STORAGE_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'getSharedPreferences.*MODE_WORLD_READABLE',
        "SharedPreferences world-readable",
        Severity.HIGH,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-1",
    ),
    GrepPattern(
        r'openFileOutput\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD_READABLE',
        "openFileOutput MODE_WORLD_READABLE",
        Severity.HIGH,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-1",
    ),
    GrepPattern(
        r'Environment\.getExternalStorageDirectory',
        "External storage write (world-readable on older Android)",
        Severity.MEDIUM,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-2",
    ),
    GrepPattern(
        r'\.edit\(\).*putString\s*\(\s*"(?:password|token|secret|key)',
        "Sensitive data in SharedPreferences in plaintext",
        Severity.HIGH,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-1",
    ),
    GrepPattern(
        r'SQLiteDatabase\.openOrCreateDatabase',
        "Unencrypted SQLite database creation",
        Severity.LOW,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-1",
        "Use SQLCipher if the DB stores sensitive data",
    ),
    GrepPattern(
        r'Log\.[dievw]\s*\(.*(?:password|token|secret|key|ssn|credit)',
        "Sensitive data in log statement",
        Severity.MEDIUM,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-3",
    ),
    GrepPattern(
        r'(?i)\.write(?:UTF|Bytes|Chars)?\s*\(.*(?:password|token|private_key)',
        "Plaintext credential write to file",
        Severity.HIGH,
        "M9: Insecure Data Storage",
        "MASVS-STORAGE-1",
    ),
)

# ── Network / TLS ─────────────────────────────────────────────────────────────

NETWORK_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'http://(?!localhost|127\.0\.0\.1|10\.\d|192\.168)',
        "Cleartext HTTP to non-local host",
        Severity.MEDIUM,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'SSLSocketFactory\.getInsecure\b',
        "SSLSocketFactory.getInsecure() — no validation",
        Severity.CRITICAL,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER',
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        Severity.CRITICAL,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'checkServerTrusted\s*\([^)]*\)\s*\{\s*\}',
        "Empty checkServerTrusted — accepts all certs",
        Severity.CRITICAL,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'onReceivedSslError.*handler\.proceed',
        "WebViewClient.onReceivedSslError calls handler.proceed()",
        Severity.HIGH,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'(?i)android:usesCleartextTraffic\s*=\s*"true"',
        "usesCleartextTraffic=true in manifest",
        Severity.MEDIUM,
        "M5: Insecure Communication",
        "MASVS-NETWORK-1",
    ),
    GrepPattern(
        r'setSSLSocketFactory.*SSLContext\.getDefault',
        "Default SSLContext — may not enforce pinning",
        Severity.LOW,
        "M5: Insecure Communication",
        "MASVS-NETWORK-2",
    ),
)

# ── IPC / Component Exposure ──────────────────────────────────────────────────

IPC_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'android:exported\s*=\s*"true"(?![^>]*android:permission)',
        "Exported component without permission guard",
        Severity.MEDIUM,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-1",
    ),
    GrepPattern(
        r'getStringExtra|getIntExtra|getDataString',
        "Intent extra read — verify input validation before use",
        Severity.INFO,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
        "Flag for taint-agent follow-up",
    ),
    GrepPattern(
        r'sendBroadcast\s*\((?!.*permission)',
        "sendBroadcast without permission restriction",
        Severity.MEDIUM,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-1",
    ),
    GrepPattern(
        r'startActivity.*ACTION_VIEW.*getDataString',
        "Deep-link data passed to startActivity without validation",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-3",
    ),
    GrepPattern(
        r'PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*FLAG_MUTABLE',
        "Mutable PendingIntent (pre-S) — hijackable",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
    ),
)

# ── WebView ───────────────────────────────────────────────────────────────────

WEBVIEW_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        "JavaScript enabled in WebView",
        Severity.MEDIUM,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
    ),
    GrepPattern(
        r'addJavascriptInterface\s*\(',
        "JavaScript interface bridge registered",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
        "Check @JavascriptInterface annotations for exposed methods",
    ),
    GrepPattern(
        r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
        "setAllowFileAccessFromFileURLs(true) — XSS-to-file-read",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
    ),
    GrepPattern(
        r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
        "setAllowUniversalAccessFromFileURLs(true) — UXSS",
        Severity.CRITICAL,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
    ),
    GrepPattern(
        r'loadUrl\s*\(\s*"javascript:',
        "loadUrl with javascript: URI",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-PLATFORM-2",
    ),
    GrepPattern(
        r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)',
        "WebView remote debugging enabled — check not in release build",
        Severity.MEDIUM,
        "M4: Insufficient Input/Output Validation",
        "MASVS-RESILIENCE-4",
    ),
)

# ── Authentication ────────────────────────────────────────────────────────────

AUTH_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'BiometricPrompt.*setAllowedAuthenticators.*BIOMETRIC_WEAK',
        "BiometricPrompt allows weak biometric (Class 2)",
        Severity.MEDIUM,
        "M3: Insecure Authentication/Authorization",
        "MASVS-AUTH-2",
    ),
    GrepPattern(
        r'KeyguardManager.*isKeyguardSecure\s*\(\s*\)\s*==\s*false',
        "Keyguard secure check — screen lock may not be enforced",
        Severity.MEDIUM,
        "M3: Insecure Authentication/Authorization",
        "MASVS-AUTH-1",
    ),
    GrepPattern(
        r'\.alg\s*=\s*"(?:none|HS256)"',
        'JWT alg field hardcoded to "none" or weak',
        Severity.CRITICAL,
        "M3: Insecure Authentication/Authorization",
        "MASVS-AUTH-2",
    ),
    GrepPattern(
        r'SharedPreferences.*getBoolean\s*\(\s*"(?:is_admin|is_logged_in|authenticated)',
        "Auth state read from SharedPreferences — bypassable",
        Severity.HIGH,
        "M3: Insecure Authentication/Authorization",
        "MASVS-AUTH-1",
    ),
)

# ── Anti-Tamper / RASP ────────────────────────────────────────────────────────

RESILIENCE_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'android\.os\.Debug\.isDebuggerConnected\s*\(\s*\)',
        "Debugger detection check",
        Severity.INFO,
        "M7: Insufficient Binary Protections",
        "MASVS-RESILIENCE-2",
    ),
    GrepPattern(
        r'(?i)(?:su|superuser|magisk|xposed)',
        "Root/Xposed framework reference",
        Severity.INFO,
        "M7: Insufficient Binary Protections",
        "MASVS-RESILIENCE-1",
    ),
    GrepPattern(
        r'getPackageInfo.*SIGNATURE',
        "Signature integrity check present",
        Severity.INFO,
        "M7: Insufficient Binary Protections",
        "MASVS-RESILIENCE-3",
    ),
    GrepPattern(
        r'android\.app\.ActivityManager.*getRunningAppProcesses',
        "Running process enumeration — common emulator/root check",
        Severity.INFO,
        "M7: Insufficient Binary Protections",
        "MASVS-RESILIENCE-1",
    ),
)

# ── Dynamic Code Loading ──────────────────────────────────────────────────────

DYNAMIC_LOAD_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'DexClassLoader\s*\(',
        "DexClassLoader — loads external DEX at runtime",
        Severity.HIGH,
        "M7: Insufficient Binary Protections",
        "MASVS-CODE-3",
    ),
    GrepPattern(
        r'PathClassLoader\s*\(',
        "PathClassLoader — loads external classes",
        Severity.MEDIUM,
        "M7: Insufficient Binary Protections",
        "MASVS-CODE-3",
    ),
    GrepPattern(
        r'System\.loadLibrary\s*\(\s*[^"]+\)',
        "System.loadLibrary with dynamic name",
        Severity.MEDIUM,
        "M7: Insufficient Binary Protections",
        "MASVS-CODE-3",
    ),
    GrepPattern(
        r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
        "Runtime.exec() — command execution",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-CODE-4",
    ),
)

# ── SQL Injection ─────────────────────────────────────────────────────────────

SQLI_PATTERNS: tuple[GrepPattern, ...] = (
    GrepPattern(
        r'rawQuery\s*\(\s*".*\+',
        "rawQuery with string concatenation — SQLi risk",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-CODE-4",
    ),
    GrepPattern(
        r'execSQL\s*\(\s*".*\+',
        "execSQL with string concatenation — SQLi risk",
        Severity.HIGH,
        "M4: Insufficient Input/Output Validation",
        "MASVS-CODE-4",
    ),
    GrepPattern(
        r'rawQuery\s*\(\s*[^"]*\+\s*[^,]+,\s*null\s*\)',
        "rawQuery with null selectionArgs — no parameterization",
        Severity.MEDIUM,
        "M4: Insufficient Input/Output Validation",
        "MASVS-CODE-4",
    ),
)

# ── Master registry ───────────────────────────────────────────────────────────

PATTERNS_BY_CATEGORY: dict[str, tuple[GrepPattern, ...]] = {
    "hardcoded_secrets": HARDCODED_SECRETS,
    "crypto": CRYPTO_PATTERNS,
    "storage": STORAGE_PATTERNS,
    "network": NETWORK_PATTERNS,
    "ipc": IPC_PATTERNS,
    "webview": WEBVIEW_PATTERNS,
    "auth": AUTH_PATTERNS,
    "resilience": RESILIENCE_PATTERNS,
    "dynamic_load": DYNAMIC_LOAD_PATTERNS,
    "sqli": SQLI_PATTERNS,
}

ALL_PATTERNS: tuple[GrepPattern, ...] = tuple(
    p for group in PATTERNS_BY_CATEGORY.values() for p in group
)

__all__ = [
    "GrepPattern",
    "PATTERNS_BY_CATEGORY",
    "ALL_PATTERNS",
    "HARDCODED_SECRETS",
    "CRYPTO_PATTERNS",
    "STORAGE_PATTERNS",
    "NETWORK_PATTERNS",
    "IPC_PATTERNS",
    "WEBVIEW_PATTERNS",
    "AUTH_PATTERNS",
    "RESILIENCE_PATTERNS",
    "DYNAMIC_LOAD_PATTERNS",
    "SQLI_PATTERNS",
]
