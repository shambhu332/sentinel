"""N_014: Hardcoded mTLS Client Certificate / Private Key.

Apps that use mutual TLS authenticate themselves to the backend by
presenting a client certificate. The standard implementation on
Android is to bundle a ``.p12`` / ``.pfx`` keystore in
``res/raw/`` or ``assets/`` and load it via:

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(getResources().openRawResource(R.raw.client_cert),
            "passw0rd".toCharArray());

Both halves of the bug land here:

* The private key is shipped to every user. ``apktool d`` extracts
  the ``.p12`` in seconds. There is no "per-user" mTLS — every
  install impersonates the same client.
* The keystore password is typically hardcoded as a string literal
  in the same class, making the extraction trivially completable.

mTLS at scale needs per-user provisioning — the device generates
the key in Android Keystore, sends a CSR to the backend, and gets
back a signed leaf cert. None of that key material should live in
the APK.

Detection
---------

1. Walk ``resources_dir`` for any of: ``*.p12``, ``*.pfx``,
   ``*.pem``, ``*.cer``, ``*.crt``, ``*.jks``, ``*.bks``,
   ``*.keystore`` under ``res/raw/`` or ``assets/``.

2. Walk decompiled Java for the loader calls:
   * ``KeyStore.getInstance("PKCS12")`` / ``"BKS"`` / ``"JKS"``
     followed by ``.load(stream, password)``
   * ``SSLContext.init(keyManagers, ...)``

3. Cross-reference: if step 1 found a keystore AND step 2 found a
   loader, fire CRITICAL. The asset alone (no loader) is HIGH
   (might be unused, but inclusion in the APK is a leak regardless).
   Loader without on-disk artifact (key bytes inline) is HIGH.

Hardcoded keystore password (``.load(stream, "literal")``) bumps
confidence by 0.05.
"""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_KEYSTORE_EXTS = {
    ".p12", ".pfx", ".pem", ".cer", ".crt",
    ".jks", ".bks", ".keystore",
}

_PKCS_GETINSTANCE = re.compile(
    r'KeyStore\s*\.\s*getInstance\s*\(\s*"(PKCS12|JKS|BKS|PKCS#?12)"\s*\)',
)

_KEYSTORE_LOAD = re.compile(
    r"\.load\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)",
)

_STRING_LITERAL = re.compile(r'^\s*"[^"]+"\s*\.\s*toCharArray\s*\(|^\s*"[^"]+"')

_RES_RAW_LOAD = re.compile(
    r"openRawResource\s*\(\s*R\s*\.\s*raw\s*\.\s*(\w+)\s*\)",
)


class HardcodedMtlsKeyAgent(BaseAgent):
    """Detect bundled mTLS client certificates and inline keystore loads."""

    AGENT_ID = "N_014"
    VULN_CLASS = "Hardcoded mTLS Client Certificate"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.resources_dir or self._context.decompiled_dir
        )

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        on_disk = self._find_keystore_artifacts()
        loaders = self._find_loader_calls()

        if not on_disk and not loaders:
            return findings

        # Cross-reference each loader to either an on-disk artifact
        # (CRITICAL) or none (HIGH for inline key bytes).
        used_artifacts: set[Path] = set()
        for loader in loaders:
            ext_match = self._loader_uses_resource(loader, on_disk)
            password_literal = loader["password_literal"]
            confidence = 0.85
            if password_literal:
                confidence += 0.05

            if ext_match is not None:
                used_artifacts.add(ext_match["path"])
                findings.append(self._make_finding(
                    vuln_class="Hardcoded mTLS Client Certificate",
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    evidence={
                        "file": loader["file"],
                        "keystore_format": loader["format"],
                        "asset_path": str(ext_match["rel"]),
                        "password_inline": password_literal,
                        "issue": (
                            f"{loader['format']} keystore at "
                            f"{ext_match['rel']!s} is loaded with a "
                            "hardcoded password — every install ships "
                            "the same private key. Bundle extraction "
                            "via apktool is trivial."
                        ),
                    },
                    recommendation=self._recommendation(),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-CRYPTO-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
                    ),
                ))
                continue

            # Loader without a matching on-disk artifact — inline key
            # bytes or a dynamically-constructed stream. Still wrong.
            findings.append(self._make_finding(
                vuln_class="Hardcoded mTLS Client Certificate",
                severity=Severity.HIGH,
                confidence=confidence - 0.05,
                evidence={
                    "file": loader["file"],
                    "keystore_format": loader["format"],
                    "password_inline": password_literal,
                    "issue": (
                        "KeyStore.getInstance(\""
                        f"{loader['format']}\").load(...) call site "
                        "with no matching res/raw artifact — the key "
                        "material is plausibly inline or loaded from a "
                        "dynamically-built stream. Bundled mTLS "
                        "private keys are leaked to every install."
                    ),
                },
                recommendation=self._recommendation(),
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MSTG-CRYPTO-1",
                cvss_vector=(
                    "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                ),
            ))

        # Artifacts on disk that no loader explicitly references —
        # still leak data (anyone can pull them out of the APK).
        for art in on_disk:
            if art["path"] in used_artifacts:
                continue
            findings.append(self._make_finding(
                vuln_class="Hardcoded Bundled Keystore",
                severity=Severity.HIGH,
                confidence=0.75,
                evidence={
                    "asset_path": str(art["rel"]),
                    "size_bytes": art["size"],
                    "issue": (
                        f"Keystore-shaped asset {art['rel']!s} ships "
                        "inside the APK. Even if it is not loaded by "
                        "the code reachable in static analysis, "
                        "anyone with the APK extracts the private key "
                        "material."
                    ),
                },
                recommendation=self._recommendation(),
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MSTG-CRYPTO-1",
            ))

        return findings

    # ---------- helpers ----------

    def _find_keystore_artifacts(self) -> list[dict]:
        res = self._context.resources_dir
        if not res:
            return []
        seen: set[Path] = set()
        candidates: list[dict] = []
        # Single recursive scan from the resources root deduplicates
        # naturally — the previous multi-scan approach found the same
        # file several times when both ``res/raw`` and the top-level
        # ``res`` patterns matched.
        for ext in _KEYSTORE_EXTS:
            for p in res.rglob(f"*{ext}"):
                if not p.is_file() or p in seen:
                    continue
                seen.add(p)
                try:
                    rel = p.relative_to(res)
                except ValueError:
                    rel = p
                candidates.append({
                    "path": p,
                    "rel": rel,
                    "ext": ext,
                    "size": p.stat().st_size,
                })
        return candidates

    def _find_loader_calls(self) -> list[dict]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []
        loaders: list[dict] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            for fmt_match in _PKCS_GETINSTANCE.finditer(source):
                fmt = fmt_match.group(1).replace("#", "")
                # Look for a .load() call within 500 chars after the
                # getInstance — the typical idiom keeps them adjacent.
                tail = source[fmt_match.end(): fmt_match.end() + 500]
                load_match = _KEYSTORE_LOAD.search(tail)
                if not load_match:
                    continue
                stream_arg = load_match.group(1).strip()
                password_arg = load_match.group(2).strip()
                rel = str(java_file.relative_to(decompiled))
                # res/raw refs in the stream argument scope the
                # cross-reference to a specific resource name.
                raw_match = _RES_RAW_LOAD.search(tail)
                loaders.append({
                    "file": rel,
                    "format": fmt,
                    "stream_arg": stream_arg[:80],
                    "password_arg": password_arg[:80],
                    "password_literal": _STRING_LITERAL.match(password_arg) is not None,
                    "raw_resource": raw_match.group(1) if raw_match else None,
                })
        return loaders

    @staticmethod
    def _loader_uses_resource(loader: dict, on_disk: list[dict]) -> dict | None:
        # Resource-id-based match
        if loader.get("raw_resource"):
            target = loader["raw_resource"].lower()
            for art in on_disk:
                stem = art["rel"].stem.lower() if hasattr(art["rel"], "stem") else art["rel"].name.split(".")[0].lower()
                if stem == target:
                    return art
        # Fallback: any keystore on disk paired with any loader.
        if on_disk:
            return on_disk[0]
        return None

    @staticmethod
    def _recommendation() -> str:
        return (
            "Stop shipping client keystores in the APK. Generate "
            "per-device keys with Android Keystore, send a CSR to the "
            "backend, and install the backend-signed leaf certificate "
            "via KeyChainAliasCallback. The Android Keystore key never "
            "leaves the secure element; the leaf cert is per-user and "
            "can be revoked. For short-term hardening: at minimum, "
            "derive the keystore password from a server-issued nonce "
            "stitched to the device install id, so two devices can't "
            "share the same key material in flight."
        )
