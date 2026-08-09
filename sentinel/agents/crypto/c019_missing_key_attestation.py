"""C_019 — Missing hardware key attestation.

``KeyGenParameterSpec.Builder.setAttestationChallenge(bytes)`` is the
only mechanism that produces a signed certificate chain proving a
private key was generated inside the device's TEE/StrongBox. Apps that
ship payment, signing, or auth-binding keys without an attestation
challenge cannot distinguish a real TEE key from a soft-token key
forged on a rooted device.

Detection
=========
For each decompiled Java/Kotlin file:

* find ``new KeyGenParameterSpec.Builder(alias, purpose...)`` calls
  whose ``purpose`` argument carries any of:
      PURPOSE_SIGN, PURPOSE_VERIFY, PURPOSE_AGREE_KEY,
      PURPOSE_ATTEST_KEY
  (the purposes where attestation actually matters), OR whose alias
  literal looks sensitive (``signing``, ``payment``, ``device_bind``).

* scan the same ``Builder().builder.builder.build()`` chain for a
  ``.setAttestationChallenge(`` call.

* flag when the chain reaches ``.build()`` without one.

Companion to ``C_011`` (StrongBox + setUserAuthenticationRequired)
and ``D_026`` (runtime keystore observation). Where C_011 verifies
key isolation, C_019 verifies that you can *prove* it to your
server.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_BUILDER_CTOR = re.compile(
    r"new\s+KeyGenParameterSpec\s*\.\s*Builder\s*\(([^)]*)\)",
)

# Purposes where attestation carries actual security weight.
_SENSITIVE_PURPOSES = (
    "PURPOSE_SIGN",
    "PURPOSE_VERIFY",
    "PURPOSE_AGREE_KEY",
    "PURPOSE_ATTEST_KEY",
)

_SENSITIVE_ALIAS_HINTS = (
    "sign", "signing", "payment", "pay_", "device_bind", "deviceid",
    "attestation", "wallet", "auth_bind",
)

_MAX_FILES = 2000


class MissingKeyAttestationAgent(BaseAgent):
    AGENT_ID = "C_019"
    VULN_CLASS = "Missing Key Attestation Challenge"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if decompiled is None:
            return []
        findings: list[Finding] = []
        seen = 0
        for path in decompiled.rglob("*.java"):
            seen += 1
            if seen > _MAX_FILES:
                break
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "KeyGenParameterSpec" not in source:
                continue
            for match in _BUILDER_CTOR.finditer(source):
                args = match.group(1)
                alias = _first_string_literal(args).lower()
                purposes = [p for p in _SENSITIVE_PURPOSES if p in args]
                alias_is_sensitive = any(h in alias for h in _SENSITIVE_ALIAS_HINTS)
                if not purposes and not alias_is_sensitive:
                    continue
                chain = _builder_chain(source, match.end())
                if "setAttestationChallenge" in chain:
                    continue
                findings.append(self._make_finding(
                    vuln_class=self.VULN_CLASS,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    recommendation=(
                        f"Key `{alias or '?'}` is generated for a "
                        f"sensitive purpose ({', '.join(purposes) or 'alias-hint'}) "
                        "without a setAttestationChallenge() call. Without "
                        "an attestation challenge the server cannot tell a "
                        "TEE/StrongBox-backed key from a software key forged "
                        "on a rooted device. Add "
                        "`.setAttestationChallenge(serverNonce)` to the "
                        "builder, ship the resulting certificate chain to "
                        "your backend, and verify it there against Google's "
                        "attestation root."
                    ),
                    evidence={
                        "file": str(path.relative_to(decompiled)),
                        "alias_literal": alias,
                        "purposes": purposes,
                        "builder_chain": chain[:400],
                    },
                    owasp="M5: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-1",
                ))
        return findings


def _first_string_literal(args: str) -> str:
    """Return the first quoted literal in a Builder ctor arg list."""
    quote = None
    buf: list[str] = []
    escaped = False
    for ch in args:
        if quote is None:
            if ch == '"':
                quote = ch
            continue
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == quote:
            return "".join(buf)
        buf.append(ch)
    return ""


def _builder_chain(source: str, start: int) -> str:
    """Return the fluent-builder chain starting at ``start`` up to
    the matching ``.build()`` (or the next semicolon)."""
    depth = 0
    out: list[str] = []
    for i in range(start, min(len(source), start + 4000)):
        ch = source[i]
        out.append(ch)
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0 and ch == ";":
            break
    return "".join(out)
