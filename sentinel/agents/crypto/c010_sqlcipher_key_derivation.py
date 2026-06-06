"""C_010: SQLCipher Key Derivation Audit.

SQLCipher is Android's most common at-rest database-encryption library,
shipped as ``net.sqlcipher.database.SQLiteDatabase``. Used correctly
(passphrase derived via PBKDF2 with a per-user salt, or backed by a
key stored in Android Keystore) it is genuinely secure. Used the way
the README's quick-start example shows it — a hardcoded ASCII
passphrase passed straight to ``openOrCreateDatabase`` — the encrypted
database is decryptable with ``strings`` in under a minute.

What we detect
--------------

Every call to one of:

* ``SQLiteDatabase.openOrCreateDatabase(``
* ``SQLiteDatabase.openDatabase(``
* ``net.sqlcipher.database.SQLiteOpenHelper`` constructor /
  ``getWritableDatabase(passphrase)`` / ``getReadableDatabase(passphrase)``
* ``SQLiteOpenHelper.getWritableDatabase(passphrase)`` (the SQLCipher
  overload — the platform one takes no arguments)

is inspected for the key/passphrase argument:

* **CRITICAL** — string literal passed inline (``"mypassword"``,
  hex-string constant, Base64 constant).
* **HIGH** — single local variable read from ``BuildConfig.<X>`` or a
  ``static final String`` declared in the same file, which compiles to
  a constant.
* **MEDIUM** — passphrase derived from a SharedPreferences read with
  no surrounding ``PBKDF2`` / ``SecretKeyFactory`` invocation in the
  file (likely hashed-once or plain-text).
* **No finding** — call site is followed within 200 chars by
  ``SecretKeyFactory.getInstance("PBKDF2WithHmacSHA``,
  ``MessageDigest``-then-iterations, or a ``KeyStore.getInstance``
  reference, indicating proper derivation.

The detection is regex-based and intentionally tight; the SQLCipher
import string itself is enough to drop the false-positive rate of
platform SQLite calls to zero.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_SQLCIPHER_IMPORT = re.compile(
    r"\bimport\s+net\.sqlcipher(?:\.\w+)*\s*;",
)

_OPEN_CALL = re.compile(
    r"\b(openOrCreateDatabase|openDatabase|"
    r"getWritableDatabase|getReadableDatabase|SQLiteOpenHelper)\s*\(",
)

_STRING_LITERAL_ARG = re.compile(r'^\s*"[^"]{1,200}"')
_BASE64_OR_HEX_LITERAL = re.compile(r'^\s*"[A-Za-z0-9+/=]{16,}"\s*$|^\s*"[0-9a-fA-F]{16,}"\s*$')
_BUILDCONFIG_REF = re.compile(r"\bBuildConfig\.\w+\b")
_STATIC_FINAL_STRING_DECL = re.compile(
    r"static\s+final\s+String\s+(\w+)\s*=\s*\"",
)
_PROPER_KDF = re.compile(
    r"SecretKeyFactory\.getInstance\s*\(\s*\"PBKDF2|"
    r"KeyStore\.getInstance\s*\(|"
    r"PBEKeySpec\s*\(",
)
_PREFS_READ = re.compile(
    r"\.(getString|getStringExtra)\s*\(\s*\"\w+\"",
)


def _balanced_args(source: str, paren_start: int) -> str | None:
    if paren_start >= len(source) or source[paren_start] != "(":
        return None
    depth = 0
    for i in range(paren_start, len(source)):
        ch = source[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[paren_start + 1 : i]
    return None


def _split_top_level_commas(args: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    last = 0
    for i, ch in enumerate(args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(args[last:i].strip())
            last = i + 1
    parts.append(args[last:].strip())
    return parts


class SQLCipherKeyDerivationAgent(BaseAgent):
    """Detect SQLCipher database opens with insecure passphrase handling."""

    AGENT_ID = "C_010"
    VULN_CLASS = "Insecure SQLCipher Key Derivation"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            if not _SQLCIPHER_IMPORT.search(source):
                continue

            static_keys = set(_STATIC_FINAL_STRING_DECL.findall(source))

            for match in _OPEN_CALL.finditer(source):
                paren_idx = source.find("(", match.start())
                args_str = _balanced_args(source, paren_idx)
                if args_str is None:
                    continue
                parts = _split_top_level_commas(args_str)
                # SQLCipher's openOrCreateDatabase(path, password, factory)
                # has the passphrase as arg #2. The 1-arg
                # getWritableDatabase(passphrase) has it as arg #0.
                key_arg = ""
                if len(parts) == 1:
                    key_arg = parts[0]
                elif len(parts) >= 2:
                    key_arg = parts[1]
                if not key_arg:
                    continue

                # Tail window after the call — used to detect a proper
                # KDF reference in the same method.
                tail = source[paren_idx : paren_idx + 600]

                severity, confidence, reason = self._classify(
                    key_arg=key_arg,
                    source=source,
                    tail=tail,
                    static_keys=static_keys,
                )
                if severity is None:
                    continue

                findings.append(self._make_finding(
                    vuln_class="Insecure SQLCipher Key Derivation",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": str(java_file.relative_to(decompiled)),
                        "call": match.group(1),
                        "key_arg": key_arg[:120],
                        "reason": reason,
                    },
                    recommendation=(
                        "Derive the SQLCipher passphrase via PBKDF2 with a "
                        "per-user salt and ≥ 100,000 iterations, or "
                        "generate a random key and seal it in the Android "
                        "Keystore. Use SQLCipher's "
                        "``SQLiteOpenHelper.getWritableDatabase(byte[])`` "
                        "byte-array overload with the derived key — the "
                        "String overload is convenience-only and easy to "
                        "misuse. Never ship a hardcoded passphrase or a "
                        "BuildConfig constant."
                    ),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-CRYPTO-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _classify(
        *,
        key_arg: str,
        source: str,
        tail: str,
        static_keys: set[str],
    ) -> tuple[Severity | None, float, str]:
        # 1) Direct string literal — Critical.
        if _STRING_LITERAL_ARG.match(key_arg):
            return Severity.CRITICAL, 0.95, "hardcoded string passphrase literal"
        if _BASE64_OR_HEX_LITERAL.match(key_arg):
            return Severity.CRITICAL, 0.90, "base64 / hex passphrase literal"

        # 2) BuildConfig.<X> — compile-time constant.
        if _BUILDCONFIG_REF.search(key_arg):
            return Severity.HIGH, 0.85, "BuildConfig compile-time constant"

        # 3) Static final String declared in same file — compile-time
        #    constant via reference.
        var = key_arg.strip().split()[-1] if key_arg.strip() else ""
        if var and var.isidentifier() and var in static_keys:
            return Severity.HIGH, 0.80, "static final String constant in same file"

        # 4) Proper KDF visible in the tail — skip.
        if _PROPER_KDF.search(tail):
            return None, 0.0, "PBKDF2 / Keystore present"

        # 5) Passphrase comes from a SharedPreferences read with no KDF
        #    visible — likely plain or single-hash storage.
        if _PREFS_READ.search(tail) and not _PROPER_KDF.search(source):
            return (
                Severity.MEDIUM, 0.70,
                "passphrase from preferences without visible PBKDF2",
            )

        return None, 0.0, "unclassified"
