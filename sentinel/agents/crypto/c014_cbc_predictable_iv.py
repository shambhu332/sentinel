"""C_014: AES/CBC Predictable IV Detection.

AES-CBC's IV must be *unpredictable* per encryption (effectively
random and unknown to the attacker before they choose plaintext) to
defeat the BEAST-style chosen-plaintext attack. Reusing a counter,
sequence number, or static field as the IV breaks CBC's
indistinguishability property even if the key stays secret.

C_014 is the CBC equivalent of C_012 (GCM nonce reuse). The two
distinct sets of failure modes:

* GCM-mode reuse is catastrophic (authenticity break) — C_012.
* CBC-mode reuse is bad but only breaks confidentiality — C_014.

We gate on a Cipher.getInstance string containing ``CBC`` and
inspect each IvParameterSpec / GCMParameterSpec / CipherParameters
construction:

* CRITICAL — zero-byte IV (``new byte[16]``) or constant literal
  ``new byte[]{...}``.
* HIGH — IV stored in a field, with no SecureRandom in the file
  (reused buffer across encryptions).
* MEDIUM — IV derived from a counter / sequence / message-id-like
  identifier (the name pattern ``counter|messageId|seq|sequence``
  is in scope as the IV expression or the field's initializer).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_CBC_USAGE = re.compile(
    r'Cipher\.getInstance\s*\(\s*"[^"]*CBC',
)
_IV_PARAM_SPEC = re.compile(
    r"IvParameterSpec\s*\("
    r"\s*(new\s+byte\s*\[[^\]]*\](?:\s*\{[^}]*\})?|[A-Za-z_][\w$]*)",
)
_ZERO_BYTE_BUFFER = re.compile(r"^\s*new\s+byte\s*\[\s*\d+\s*\]\s*$")
_CONSTANT_LITERAL_BUFFER = re.compile(
    r"^\s*new\s+byte\s*\[\s*\]\s*\{[^}]*\}\s*$",
)
_SECURE_RANDOM = re.compile(r"\bSecureRandom\b")
_COUNTER_NAMES = re.compile(
    r"\b(counter|messageId|seq|sequence|nonceCounter|msgIndex)\b",
    re.IGNORECASE,
)
_FIELD_DECL = re.compile(
    r"(?:private|protected|public|static|final|\s)+\s+byte\s*\[\s*\]\s+(\w+)\s*=",
)


class CbcPredictableIvAgent(BaseAgent):
    """Detect predictable IVs feeding into AES/CBC."""

    AGENT_ID = "C_014"
    VULN_CLASS = "AES-CBC Predictable IV"
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
            if not _CBC_USAGE.search(source):
                continue

            rel = str(java_file.relative_to(decompiled))
            secure_random = bool(_SECURE_RANDOM.search(source))
            field_names = set(_FIELD_DECL.findall(source))
            counter_in_file = bool(_COUNTER_NAMES.search(source))

            for m in _IV_PARAM_SPEC.finditer(source):
                iv_arg = m.group(1).strip()
                severity, confidence, reason = self._classify(
                    iv_arg=iv_arg,
                    secure_random=secure_random,
                    field_names=field_names,
                    counter_in_file=counter_in_file,
                )
                if severity is None:
                    continue

                findings.append(self._make_finding(
                    vuln_class="AES-CBC Predictable IV",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "iv_argument": iv_arg[:120],
                        "reason": reason,
                        "secure_random_in_file": secure_random,
                    },
                    recommendation=(
                        "Generate a fresh, unpredictable 16-byte IV "
                        "with SecureRandom before each AES/CBC "
                        "encryption: ``byte[] iv = new byte[16]; "
                        "new SecureRandom().nextBytes(iv);`` and "
                        "prepend it to the ciphertext for the decryptor "
                        "to recover. Counters and message IDs are NOT "
                        "valid CBC IVs — they enable BEAST-style "
                        "chosen-plaintext recovery."
                    ),
                    owasp="M4: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-2",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        if severity != Severity.MEDIUM
                        else "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _classify(
        *,
        iv_arg: str,
        secure_random: bool,
        field_names: set[str],
        counter_in_file: bool,
    ) -> tuple[Severity | None, float, str]:
        if _ZERO_BYTE_BUFFER.match(iv_arg):
            return Severity.CRITICAL, 0.95, "zero-byte IV (new byte[N])"
        if _CONSTANT_LITERAL_BUFFER.match(iv_arg):
            return Severity.CRITICAL, 0.90, "constant byte-array literal IV"
        var = iv_arg.strip().split()[-1] if iv_arg.strip() else ""
        if var.isidentifier():
            if var in field_names and not secure_random:
                return (
                    Severity.HIGH, 0.80,
                    "IV stored in field with no SecureRandom in file",
                )
            if _COUNTER_NAMES.match(var) or counter_in_file:
                return (
                    Severity.MEDIUM, 0.70,
                    "IV variable name or scope contains counter / "
                    "messageId / sequence",
                )
        return None, 0.0, "unclassified"
