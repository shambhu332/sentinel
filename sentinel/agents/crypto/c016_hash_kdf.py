"""C_016: Hash-as-KDF Detection (password → MessageDigest → key).

The single most common at-rest-encryption anti-pattern on Android:

    byte[] key = MessageDigest.getInstance("SHA-256")
                              .digest(password.getBytes());
    SecretKeySpec spec = new SecretKeySpec(key, "AES");

This is not a key-derivation function. ``SHA-256(password)`` has no
salt (so identical passwords on different devices produce identical
keys — rainbow tables work), no work factor (so brute force runs at
GPU speed — billions of guesses per second), and no domain
separation (so the same digest can mean three different things in
three different places).

The fix is a real KDF: PBKDF2 (built into Android), Argon2 (via
``com.lambdapioneer.argon2kt``), or scrypt. All three accept a salt
and an iteration / memory cost the attacker cannot skip.

Detection
---------

Two shapes catch this in practice:

1. ``MessageDigest.getInstance(<HASH>).digest(<EXPR>.getBytes()``
   where the expression looks password-derived (variable name
   contains ``password`` / ``passwd`` / ``passphrase`` / ``pwd`` /
   ``master`` / ``secret``).

2. ``MessageDigest.update(...)`` followed by ``MessageDigest.digest()``
   where one of the ``update`` calls receives a password-shaped
   variable. We catch this by looking at the enclosing method body.

The output is then used as a key when one of these is in scope in
the same method body: ``SecretKeySpec``, ``Cipher.init``,
``IvParameterSpec``. Without a key-use sink we drop to a MEDIUM
finding because the hash might be used for a non-crypto identifier.

A nearby ``SecretKeyFactory.getInstance("PBKDF2`` /
``PBEKeySpec`` / ``Argon2`` import suppresses the finding — the
developer is plausibly building a proper KDF and the hash output
isn't the key material.

Severity ladder
---------------

* CRITICAL — hash-derived bytes flow into SecretKeySpec / Cipher.init
  in the same method (key-use confirmed) and no PBKDF2 in file.
* HIGH — same digest shape with a password-named source but no
  key-use sink in scope (still wrong, just less certain it's the
  encryption key).
* Suppressed — PBKDF2 / Argon2 / scrypt visible in the file.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_DIGEST_INLINE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"(?:MD5|SHA-?1|SHA-?256|SHA-?384|SHA-?512)\"\s*\)"
    r"\s*\.\s*digest\s*\(\s*([^)]+?)\s*\)",
)
_DIGEST_UPDATE = re.compile(
    r"\.update\s*\(\s*([A-Za-z_]\w*)(?:\s*\.\s*getBytes\s*\([^)]*\))?\s*\)",
)
_PASSWORD_VAR_NAME = re.compile(
    r"\b(?:password|passwd|passphrase|pwd|master|user_secret|loginsecret)"
    r"\w*\b",
    re.IGNORECASE,
)
_PASSWORD_LITERAL_KEY = re.compile(
    r'"[^"]*(?:password|passwd|pwd|passphrase|master)[^"]*"',
    re.IGNORECASE,
)
_KEY_USE_SINK = re.compile(
    r"\b(?:SecretKeySpec|Cipher\s*\.\s*init|IvParameterSpec)\b",
)
_PROPER_KDF = re.compile(
    r"\bSecretKeyFactory\s*\.\s*getInstance\s*\(\s*\"PBKDF2|"
    r"\bPBEKeySpec\b|"
    r"\bArgon2|"
    r"\bScrypt|"
    r"\bcom\.lambdapioneer\.argon2kt\b",
)
_PROPER_HASH_USES = re.compile(
    # Common legitimate uses of MessageDigest that should not fire:
    # file hashing, cache keys, integrity comparison. Best-effort.
    r"\b(?:fileChecksum|cacheKey|integrityHash|computeDigest|"
    r"checksumOf|sha256(?:File|Stream|Of))\b",
)


def _enclosing_method_body(source: str, idx: int) -> str | None:
    open_idx = source.rfind("{", 0, idx)
    while open_idx != -1:
        depth = 0
        i = open_idx
        while i < len(source):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    if i >= idx:
                        return source[open_idx + 1 : i]
                    break
            i += 1
        open_idx = source.rfind("{", 0, open_idx)
    return None


class HashKdfAgent(BaseAgent):
    """Detect password → MessageDigest → key anti-pattern."""

    AGENT_ID = "C_016"
    VULN_CLASS = "Hash Used as Key Derivation Function"
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
            if "MessageDigest" not in source:
                continue
            if _PROPER_KDF.search(source):
                # Developer is plausibly building a real KDF elsewhere
                # in the file; we don't want to flag the auxiliary hash.
                continue

            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            for match in _DIGEST_INLINE.finditer(source):
                arg_expr = match.group(1).strip()
                open_idx = source.rfind("{", 0, match.start())
                if open_idx in seen_methods:
                    continue
                body = _enclosing_method_body(source, match.start()) or ""
                if not self._looks_password(arg_expr, body):
                    continue
                if _PROPER_HASH_USES.search(body):
                    continue
                seen_methods.add(open_idx)
                findings.append(self._build(
                    rel=rel,
                    shape="inline digest(password.getBytes())",
                    body=body,
                    arg_expr=arg_expr,
                ))

            # Two-step shape: digest() with no args after update(password)
            for match in re.finditer(
                r"MessageDigest\s*\.\s*getInstance\s*\([^)]*\)",
                source,
            ):
                open_idx = source.rfind("{", 0, match.start())
                if open_idx in seen_methods:
                    continue
                body = _enclosing_method_body(source, match.start()) or ""
                update_match = _DIGEST_UPDATE.search(body)
                if not update_match:
                    continue
                var = update_match.group(1)
                if not self._looks_password(var, body):
                    continue
                if "digest()" not in body.replace(" ", "") and \
                        ".digest()" not in body:
                    continue
                if _PROPER_HASH_USES.search(body):
                    continue
                seen_methods.add(open_idx)
                findings.append(self._build(
                    rel=rel,
                    shape="update(password) → digest()",
                    body=body,
                    arg_expr=var,
                ))

        return findings

    @staticmethod
    def _looks_password(expr: str, body: str) -> bool:
        """Does the digested expression look password-derived?"""
        if _PASSWORD_VAR_NAME.search(expr):
            return True
        # The variable name might be generic (``data``, ``input``) but
        # be assigned from a password-shaped source elsewhere in the
        # method body.
        ident_match = re.match(r"\s*([A-Za-z_]\w*)", expr)
        if not ident_match:
            return False
        var = ident_match.group(1)
        # ``<var> = something containing "password"``
        assign = re.search(
            r"\b" + re.escape(var) + r"\s*=\s*([^;]+);",
            body,
        )
        if assign and (
            _PASSWORD_VAR_NAME.search(assign.group(1))
            or _PASSWORD_LITERAL_KEY.search(assign.group(1))
        ):
            return True
        return False

    def _build(
        self,
        *,
        rel: str,
        shape: str,
        body: str,
        arg_expr: str,
    ) -> Finding:
        key_use = bool(_KEY_USE_SINK.search(body))
        severity = Severity.CRITICAL if key_use else Severity.HIGH
        confidence = 0.85 if key_use else 0.75
        return self._make_finding(
            vuln_class="Hash Used as Key Derivation Function",
            severity=severity,
            confidence=confidence,
            evidence={
                "file": rel,
                "shape": shape,
                "digest_argument": arg_expr[:120],
                "key_use_in_scope": key_use,
                "issue": (
                    "Password material is hashed with MessageDigest "
                    "and the output is "
                    + ("used as an encryption key" if key_use
                       else "plausibly used as key material")
                    + ". MessageDigest is not a KDF — no salt, no "
                    "work factor, no domain separation. Rainbow "
                    "tables and GPU brute force apply directly."
                ),
            },
            recommendation=(
                "Replace the MessageDigest with PBKDF2: "
                "``SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\")"
                ".generateSecret(new PBEKeySpec(password.toCharArray(), "
                "salt, 100_000, 256)).getEncoded()`` — or for new code, "
                "use Argon2 via the ``com.lambdapioneer.argon2kt`` "
                "library. The salt must be per-user and persisted "
                "alongside the ciphertext; the iteration count should "
                "be ≥ 100,000 for PBKDF2-SHA256 (or tuned to 500ms on "
                "the target device class)."
            ),
            owasp="M4: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-1",
            cvss_vector=(
                "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
                if key_use
                else "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
            ),
        )
