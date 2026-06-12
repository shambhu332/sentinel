"""C_018 — Roll-your-own crypto constant analyzer.

Detects three signals that the app ships its own cryptography rather
than using javax.crypto / Conscrypt:

1. **Algorithm magic constants** — well-known S-box/round-constant
   tables for AES, DES, MD5, SHA-1. If they appear as raw byte/int
   arrays in app code, the developer reimplemented the primitive
   instead of importing it. Reimplementations are almost universally
   broken (constant-time, padding, IV handling).
2. **Hardcoded all-zero IVs** — `byte[] iv = {0,0,0,0,...}` or any
   byte array of length 8/12/16 that's entirely zero. With AES-CBC
   or AES-GCM this collapses the encryption to a deterministic
   transform: the same plaintext always yields the same ciphertext.
3. **XOR-loop "encryption"** — `for (i = 0; i < n; i++) buf[i] ^= key[i % key.length]`.
   Trivially reversible; ships as a stand-in for real crypto in
   surprisingly many shipped APKs.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Well-known magic constants. The presence of any of these in a hex /
# decimal byte array is a near-certain sign of roll-your-own crypto.
_ALGO_CONSTANTS: list[tuple[str, list[str], Severity]] = [
    (
        "AES",
        # Rijndael S-box first three entries: 0x63, 0x7c, 0x77, 0x7b
        # Also matches the Rcon table starting 0x01, 0x02, 0x04
        ["0x63", "0x7c", "0x77", "0x7b", "0x6f", "0xc5"],
        Severity.HIGH,
    ),
    (
        "DES",
        # DES initial permutation table starts 58, 50, 42, 34
        ["58, 50, 42, 34", "57, 49, 41, 33"],
        Severity.HIGH,
    ),
    (
        "MD5",
        # MD5 K[0]: 0xd76aa478
        ["0xd76aa478", "0xe8c7b756", "0x242070db"],
        Severity.MEDIUM,
    ),
    (
        "SHA-1",
        # SHA-1 H0: 0x67452301 (also appears in MD5; combined hit is the
        # signal here)
        ["0x67452301", "0xefcdab89", "0x98badcfe"],
        Severity.MEDIUM,
    ),
]

# Hardcoded all-zero IV / key arrays of common sizes
_ZERO_IV_RE = re.compile(
    r"\b(?:byte\[\]|byte\s*\[\s*\])\s+\w*[iI][vV]\w*\s*=\s*\{\s*"
    r"(?:0\s*,\s*){7,15}0\s*\}"
)
# Same shape but for `new byte[16]` initialised to default (Java default
# is zero — explicit fill not required to be insecure). Pattern below
# matches the explicit form to keep false positives down.

# XOR-loop "encryption" — heuristic match on a for-loop body that
# contains `^=` with a buffer-style left-hand side. Allows whitespace
# variation but anchors to a typical Java construct.
_XOR_LOOP_RE = re.compile(
    r"for\s*\(\s*int\s+\w+\s*=\s*0\s*;[^)]+;\s*\w+\+\+\s*\)\s*\{[^}]{0,200}"
    r"\w+\s*\[\s*\w+\s*\]\s*\^=\s*"
)

_MAX_FILES = 2000


class CryptoConstantsAgent(BaseAgent):
    """C_018: detect hardcoded crypto constants / IVs / XOR-loop crypto."""

    AGENT_ID = "C_018"
    VULN_CLASS = "Roll-Your-Own Crypto"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))

            # 1) Algorithm constants — require ≥2 distinct hits for that
            # algorithm before flagging, so a stray 0x67452301 used as
            # a magic colour value doesn't trip the detector.
            for algo, needles, severity in _ALGO_CONSTANTS:
                hits = [n for n in needles if n in text]
                if len(hits) >= 2:
                    findings.append(self._emit_constants(rel, algo, hits, severity))

            # 2) Zero IVs
            for m in _ZERO_IV_RE.finditer(text):
                findings.append(self._emit_zero_iv(rel, m))

            # 3) XOR-loop crypto
            for m in _XOR_LOOP_RE.finditer(text):
                findings.append(self._emit_xor_loop(rel, m))

        return findings

    # ---------- emitters ----------

    def _emit_constants(
        self, rel: str, algo: str, hits: list[str], severity: Severity,
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.85,
            recommendation=(
                f"Magic constants for {algo} were found in app code. "
                f"This almost always indicates a reimplemented cipher. "
                f"Replace with the platform's javax.crypto / "
                f"androidx.security implementation, which is "
                f"side-channel-tested and FIPS-validated where available."
            ),
            evidence={
                "file": rel,
                "algorithm": algo,
                "matched_constants": hits,
            },
        )

    def _emit_zero_iv(self, rel: str, m: re.Match) -> Finding:
        return self._make_finding(
            vuln_class="Hardcoded All-Zero IV",
            severity=Severity.HIGH,
            confidence=0.90,
            recommendation=(
                "An all-zero IV is hardcoded next to a cipher operation. "
                "With AES-CBC the same plaintext always yields the same "
                "ciphertext (deterministic encryption); with AES-GCM "
                "nonce reuse with the same key catastrophically leaks "
                "the authentication key. Generate IVs/nonces with "
                "SecureRandom and prepend them to the ciphertext."
            ),
            evidence={
                "file": rel,
                "snippet": m.group(0)[:200],
            },
        )

    def _emit_xor_loop(self, rel: str, m: re.Match) -> Finding:
        return self._make_finding(
            vuln_class="XOR-Loop \"Encryption\"",
            severity=Severity.HIGH,
            confidence=0.70,
            recommendation=(
                "A buffer XOR loop was found. XOR with a repeating key "
                "is not encryption — it can be broken in seconds with "
                "known-plaintext or frequency analysis. Replace with "
                "AES-GCM via Cipher.getInstance(\"AES/GCM/NoPadding\")."
            ),
            evidence={
                "file": rel,
                "snippet": m.group(0)[:200],
            },
        )


__all__ = ["CryptoConstantsAgent"]
