"""D_061 — Crypto key extractor (Dynamic Testing Target)."""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_KEY_INIT_RE = re.compile(
    r"\bSecretKeySpec\s*\(|\bCipher\s*\.\s*init\s*\(|"
    r"\bKeyGenerator\s*\.\s*getInstance|\bMac\s*\.\s*init\s*\("
)
_KEYSTORE_RE = re.compile(
    r"\bAndroidKeyStore\b|KeyGenParameterSpec|\.setUserAuthenticationRequired"
)


class KeyExtractorAgent(BaseAgent):
    AGENT_ID = "D_061"
    VULN_CLASS = "Memory Key Extraction (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        crypto_files: set[str] = set()
        keystore_protected_files: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _KEY_INIT_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            crypto_files.add(rel)
            if _KEYSTORE_RE.search(text):
                keystore_protected_files.add(rel)
        if not crypto_files:
            return []
        unprotected = sorted(crypto_files - keystore_protected_files)
        severity = Severity.HIGH if unprotected else Severity.MEDIUM
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.70,
            recommendation=(
                f"{len(crypto_files)} key-using call site(s). "
                f"{len(unprotected)} do NOT use AndroidKeyStore — those "
                "keys live in plain JVM memory and the Frida hook will "
                "dump SecretKeySpec.getEncoded() bytes for each Cipher.init "
                "call. Move every long-lived key to AndroidKeyStore with "
                "setUserAuthenticationRequired(true); for ephemeral keys, "
                "zero the byte[] explicitly after use."
            ),
            evidence={
                "crypto_files": sorted(crypto_files)[:10],
                "unprotected_files": unprotected[:10],
                "keystore_protected_files": sorted(keystore_protected_files)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_targets": [
                        "javax.crypto.spec.SecretKeySpec.<init>",
                        "javax.crypto.Cipher.init",
                        "javax.crypto.Mac.init",
                    ],
                    "dump_bytes": True,
                    "max_bytes_per_key": 256,
                    "safety_budget": {
                        "max_actions_total": 100,
                        "max_actions_per_sec": 10,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 5,
                    },
                },
            },
        )]


__all__ = ["KeyExtractorAgent"]
