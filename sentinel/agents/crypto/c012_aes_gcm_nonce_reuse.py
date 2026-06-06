"""C_012: AES/GCM Deterministic Nonce Detection.

GCM is the recommended AEAD mode for AES on Android, but its security
collapses catastrophically if the 96-bit IV (nonce) is ever reused
under the same key:

* Two ciphertexts with the same key/nonce leak the XOR of the
  plaintexts — confidentiality gone.
* The GHASH authentication key can be recovered after observing two
  forgeries with the same nonce — authentication gone.

GCM nonces MUST be unique per key. The canonical safe construction is
``SecureRandom.nextBytes(iv)`` with a 12-byte buffer, or an
explicitly tracked counter that is guaranteed never to repeat. The
common mistakes we detect:

1. ``new byte[12]`` (or any other GCM-shaped length) passed straight
   into ``GCMParameterSpec`` — the IV is all-zero.
2. ``new byte[]{...}`` constant literal byte arrays.
3. IV derived from a field that is *not* refreshed before each
   encryption: same buffer reused → catastrophic nonce reuse.
4. IV pulled from a hash of static input (``MessageDigest`` over a
   constant) — deterministic.

We only fire when a Cipher.getInstance string mentioning ``GCM`` is
present in the same file. That keeps the false-positive rate against
CBC / CCM constructions essentially zero.

Severity ladder
---------------

* CRITICAL — zero-byte nonce / constant array literal.
* HIGH — field-stored IV reused across calls without SecureRandom in
  the file.
* MEDIUM — IV derived from MessageDigest of static-looking input.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_GCM_USAGE = re.compile(
    r"Cipher\.getInstance\s*\(\s*\"[^\"]*GCM",
)
_GCM_PARAM_SPEC = re.compile(
    # The ``new byte[...]`` branch must come first; otherwise the
    # identifier pattern matches the ``new`` keyword and we miss the
    # array argument entirely.
    r"GCMParameterSpec\s*\(\s*\d+\s*,\s*"
    r"(new\s+byte\s*\[[^\]]*\](?:\s*\{[^}]*\})?|[A-Za-z_][\w$]*)",
)
_ZERO_BYTE_BUFFER = re.compile(r"^\s*new\s+byte\s*\[\s*\d+\s*\]\s*$")
_CONSTANT_LITERAL_BUFFER = re.compile(r"^\s*new\s+byte\s*\[\s*\]\s*\{[^}]*\}\s*$")
_SECURE_RANDOM = re.compile(r"\bSecureRandom\b")
_MESSAGE_DIGEST = re.compile(r"\bMessageDigest\.getInstance\b")
_FIELD_DECL = re.compile(
    r"(?:private|protected|public|static|final|\s)+\s+byte\s*\[\s*\]\s+(\w+)\s*=",
)


class AesGcmNonceReuseAgent(BaseAgent):
    """Detect deterministic / reused IVs feeding into AES/GCM."""

    AGENT_ID = "C_012"
    VULN_CLASS = "AES-GCM Nonce Reuse"
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
            if not _GCM_USAGE.search(source):
                continue

            rel = str(java_file.relative_to(decompiled))
            secure_random = bool(_SECURE_RANDOM.search(source))
            field_names = set(_FIELD_DECL.findall(source))

            for match in _GCM_PARAM_SPEC.finditer(source):
                iv_arg = match.group(1).strip()
                severity, confidence, reason = self._classify(
                    iv_arg=iv_arg,
                    source=source,
                    secure_random=secure_random,
                    field_names=field_names,
                )
                if severity is None:
                    continue
                findings.append(self._make_finding(
                    vuln_class="AES-GCM Nonce Reuse",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "iv_argument": iv_arg[:120],
                        "reason": reason,
                        "secure_random_in_file": secure_random,
                    },
                    recommendation=(
                        "Generate a fresh 12-byte IV with SecureRandom "
                        "before each AES/GCM encryption: "
                        "``byte[] iv = new byte[12]; "
                        "new SecureRandom().nextBytes(iv);``. Never "
                        "reuse an IV under the same key and never derive "
                        "it deterministically — a single repeat is "
                        "enough to recover the GHASH authentication key "
                        "and forge ciphertexts."
                    ),
                    owasp="M4: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-2",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _classify(
        *,
        iv_arg: str,
        source: str,
        secure_random: bool,
        field_names: set[str],
    ) -> tuple[Severity | None, float, str]:
        # 1) ``new byte[N]`` inline → zero IV.
        if _ZERO_BYTE_BUFFER.match(iv_arg):
            return Severity.CRITICAL, 0.95, "zero-byte IV (new byte[N])"
        # 2) ``new byte[]{...}`` constant literal.
        if _CONSTANT_LITERAL_BUFFER.match(iv_arg):
            return Severity.CRITICAL, 0.90, "constant byte-array literal IV"
        # 3) Single identifier that is a field decl in this file,
        #    and SecureRandom is NOT in the file → reused field IV.
        if iv_arg.isidentifier() and iv_arg in field_names and not secure_random:
            return (
                Severity.HIGH, 0.80,
                "IV stored in field with no SecureRandom in file — "
                "buffer reused across encryptions",
            )
        # 4) Identifier whose declaration is filled from MessageDigest
        #    of a constant — best-effort string check around the field.
        if iv_arg.isidentifier() and _MESSAGE_DIGEST.search(source) and not secure_random:
            return (
                Severity.MEDIUM, 0.65,
                "IV derived from MessageDigest with no SecureRandom in file",
            )
        return None, 0.0, "unclassified"
