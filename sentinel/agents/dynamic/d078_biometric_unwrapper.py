"""D_078 — Biometric CryptoObject unwrapper probe target.

Static half of the hybrid DAST flow:

* find code paths that combine ``BiometricPrompt`` with a
  ``CryptoObject`` and symmetric crypto primitives;
* emit a bounded Frida payload that hooks ``CryptoObject.getCipher()``
  at runtime and checks whether the initialized ``Cipher`` can still be
  used without showing the biometric UI again.

The dynamic half never extracts key bytes. It performs a harmless
``Cipher.doFinal`` probe against a caller-supplied or empty test buffer
and reports whether Android accepted the operation or rejected it with
an authentication/key-state exception.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_FILES = 1500
_MAX_FINDINGS = 100

_PACKAGE_RE = re.compile(r"\bpackage\s+([A-Za-z_][\w.]*);")
_CLASS_RE = re.compile(
    r"\b(?:public\s+|final\s+|abstract\s+|sealed\s+|open\s+)*"
    r"(?:class|interface|enum)\s+([A-Za-z_]\w*)",
)
_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_BIOMETRIC_RE = re.compile(
    r"\b(?:androidx\.biometric\.)?BiometricPrompt\b"
    r"|\bbiometricPrompt\s*\.\s*authenticate\s*\(",
)
_CRYPTO_OBJECT_RE = re.compile(r"\bBiometricPrompt\s*\.\s*CryptoObject\b")
_CIPHER_RE = re.compile(r"\b(?:javax\.crypto\.)?Cipher\b|Cipher\s*\.\s*getInstance\s*\(")
_SECRET_KEY_RE = re.compile(
    r"\b(?:javax\.crypto\.)?SecretKey\b|\bSecretKeySpec\b|\bKeyStore\b",
)


class BiometricCryptoUnwrapperAgent(BaseAgent):
    """D_078: flag biometric-bound ciphers for runtime unwrap probing."""

    AGENT_ID = "D_078"
    VULN_CLASS = "Biometric CryptoObject Unwrapper Probe"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        if root is None:
            return []

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES or len(findings) >= _MAX_FINDINGS:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            candidate = _classify_candidate(text)
            if not candidate:
                continue
            rel = str(path.relative_to(root))
            class_name = _class_name(path, text)
            findings.append(self._finding(rel, class_name, candidate, text))
        return findings

    def _finding(
        self,
        rel_path: str,
        class_name: str,
        signals: dict[str, bool],
        text: str,
    ) -> Finding:
        severity = (
            Severity.CRITICAL
            if signals["uses_crypto_object"] and signals["uses_cipher"]
            else Severity.HIGH
        )
        confidence = 0.84 if severity == Severity.CRITICAL else 0.74
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=(
                "Keep BiometricPrompt CryptoObject use scoped to one "
                "operation, clear every Cipher/CryptoObject reference after "
                "success or failure, and avoid caching decrypted secrets in "
                "process memory. Require BIOMETRIC_STRONG for keys protecting "
                "sensitive data and validate the D_078 Frida result before "
                "treating this as exploitable."
            ),
            evidence={
                "file": rel_path,
                "class_name": class_name,
                "line": _first_signal_line(text),
                "uses_biometric_prompt": signals["uses_biometric_prompt"],
                "uses_crypto_object": signals["uses_crypto_object"],
                "uses_cipher": signals["uses_cipher"],
                "uses_secret_key": signals["uses_secret_key"],
                "dynamic_target": True,
                "frida_payload": _build_payload(class_name),
            },
            owasp="M9: Reverse Engineering",
            masvs="MSTG-CRYPTO-1",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
        )


def _classify_candidate(text: str) -> dict[str, bool] | None:
    cleaned = _BLOCK_COMMENT_RE.sub("", _LINE_COMMENT_RE.sub("", text))
    signals = {
        "uses_biometric_prompt": bool(_BIOMETRIC_RE.search(cleaned)),
        "uses_crypto_object": bool(_CRYPTO_OBJECT_RE.search(cleaned)),
        "uses_cipher": bool(_CIPHER_RE.search(cleaned)),
        "uses_secret_key": bool(_SECRET_KEY_RE.search(cleaned)),
    }
    if not signals["uses_biometric_prompt"]:
        return None
    if not signals["uses_crypto_object"]:
        return None
    if not (signals["uses_cipher"] or signals["uses_secret_key"]):
        return None
    return signals


def _first_signal_line(text: str) -> int:
    for pattern in (_CRYPTO_OBJECT_RE, _CIPHER_RE, _SECRET_KEY_RE):
        if match := pattern.search(text):
            return text.count("\n", 0, match.start()) + 1
    return 1


def _class_name(path: Path, text: str) -> str:
    package = ""
    if match := _PACKAGE_RE.search(text):
        package = match.group(1)
    class_name = path.stem.split("$")[0]
    if match := _CLASS_RE.search(text):
        class_name = match.group(1)
    return f"{package}.{class_name}" if package else class_name


def _build_payload(class_name: str) -> dict[str, Any]:
    return {
        "type": "biometric_unwrap_probe",
        "class_name": class_name,
        "test_ciphertext_b64": "",
        "safety_budget": {
            "max_actions_total": 5,
            "max_actions_per_sec": 2,
            "wall_clock_budget_s": 30,
            "max_consecutive_crashes": 2,
        },
    }


__all__ = ["BiometricCryptoUnwrapperAgent"]
