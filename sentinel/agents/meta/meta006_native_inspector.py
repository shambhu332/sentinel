"""META_006 — Native Library Inspector.

Wraps `sentinel.tools.native_analyzer.NativeAnalyzer` and converts the
ELF-level structured analysis into Findings. Three classes of finding:

1. **Tamper / root-detection strings** in any .so → INFO. The Frida agent
   consumes these as "Dynamic Testing Targets" (paired bypass hooks).
2. **Security-relevant exported symbols** (SSL_CTX_set_verify, ptrace,
   Java_*_checkRoot, dlopen of dynamic .so) → LOW/MEDIUM depending on
   category.
3. **High-entropy strings** in a binary that look like embedded keys or
   tokens → MEDIUM (entropy ≥ 4.5) or LOW (4.0–4.5). Below 4.0 the
   analyzer doesn't report them, so nothing to emit.

The agent is skipped when no native libs were found by Phase 1.5
(`META_005`); the orchestrator's skip-list also drops it before
construction in that case, so this is belt-and-braces.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.tools.native_analyzer import ElfAnalysis, NativeAnalyzer

logger = logging.getLogger(__name__)

# Map ELF symbol categories → (severity, vuln_class, recommendation)
_SYMBOL_REPORT: dict[str, tuple[Severity, str, str]] = {
    "anti_debug": (
        Severity.LOW,
        "Anti-Debug Symbols in Native Library",
        "Anti-debug primitives (ptrace, PT_DENY_ATTACH) detected. Pair "
        "with the Frida bypass agent for runtime validation; document "
        "for the dynamic test phase.",
    ),
    "root_detection": (
        Severity.LOW,
        "Root-Detection Symbols in Native Library",
        "Root-detection symbols (su, magisk, frida, xposed) present in "
        "exports. Likely a bypass target — flag as a dynamic-test target "
        "for Frida hook generation.",
    ),
    "dynamic_loading": (
        Severity.MEDIUM,
        "Dynamic Loading Primitives Exported",
        "dlopen / dlsym are exported from a shared object. Attacker-"
        "controlled paths or names can lead to library hijacking. "
        "Validate that all loader arguments are constants or come "
        "from trusted sources.",
    ),
    "ssl_tls": (
        Severity.MEDIUM,
        "TLS API Surface in Native Library",
        "OpenSSL/TLS symbols are exported from the native side. Verify "
        "that SSL_CTX_set_verify is set to SSL_VERIFY_PEER and not "
        "overridden by a custom callback that ignores certificate errors.",
    ),
    "jni_bridge": (
        Severity.INFO,
        "JNI Bridge Functions Exported",
        "JNI bridge methods discovered. Enumerated for the dynamic "
        "phase — Frida can hook these directly to inspect Java↔native "
        "boundary calls.",
    ),
    "crypto": (
        Severity.INFO,
        "Native Crypto Primitives Exported",
        "Crypto primitives (AES, EVP, RSA, HMAC, SHA*) exported from "
        "native side. Confirm the implementations come from a vetted "
        "library (BoringSSL, OpenSSL) and not a rolled-your-own variant.",
    ),
}


class NativeInspectorAgent(BaseAgent):
    """META_006: ELF inspector for Android .so libraries.

    Runs after Phase 1.5 has confirmed native libs exist. The actual ELF
    parsing happens in the `NativeAnalyzer` tool — this class only
    orchestrates the scan, decides which symbol/string findings rise to
    the report, and renders Findings.
    """

    AGENT_ID = "META_006"
    VULN_CLASS = "Native Library Inspection"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        lib_root = self._get_lib_root()
        return lib_root is not None and lib_root.exists()

    async def analyze(self) -> list[Finding]:
        lib_root = self._get_lib_root()
        if lib_root is None:
            return []

        analyzer = NativeAnalyzer()
        result = await analyzer.analyze_directory(lib_root)
        if not result.success or result.data is None:
            self._log.debug("NativeAnalyzer returned no data: %s", result.error)
            return []

        findings: list[Finding] = []
        for analysis in result.data.analyses:
            findings.extend(self._render_findings(analysis))
        return findings

    # ---------- Finding builders ----------

    def _render_findings(self, analysis: ElfAnalysis) -> list[Finding]:
        out: list[Finding] = []

        # 1) Tamper-detection strings (Dynamic Testing Targets)
        if analysis.tamper_detection_strings:
            out.append(self._make_finding(
                vuln_class="Native Tamper-Detection Strings (Dynamic Testing Target)",
                severity=Severity.INFO,
                confidence=0.85,
                recommendation=(
                    "These strings indicate runtime tamper / root / Frida "
                    "detection. Forwarded to the dynamic-analysis phase as "
                    "bypass targets — the Frida agent should hook the "
                    "functions that reference them."
                ),
                evidence={
                    "lib": analysis.path,
                    "arch": analysis.arch,
                    "strings": analysis.tamper_detection_strings[:50],
                    "dynamic_target": True,
                },
            ))

        # 2) Security-relevant exported symbols
        for category, names in analysis.security_symbols.items():
            spec = _SYMBOL_REPORT.get(category)
            if spec is None or not names:
                continue
            severity, vuln_class, recommendation = spec
            out.append(self._make_finding(
                vuln_class=vuln_class,
                severity=severity,
                confidence=0.75,
                recommendation=recommendation,
                evidence={
                    "lib": analysis.path,
                    "arch": analysis.arch,
                    "category": category,
                    "symbol_count": len(names),
                    "symbols": names[:25],
                },
            ))

        # 3) High-entropy embedded strings (potential keys / tokens)
        for s in analysis.high_entropy_strings:
            entropy = float(s.get("entropy", 0.0))
            if entropy >= 4.5:
                severity = Severity.MEDIUM
            elif entropy >= 4.0:
                severity = Severity.LOW
            else:
                continue
            out.append(self._make_finding(
                vuln_class="High-Entropy String in Native Library",
                severity=severity,
                confidence=0.55,
                recommendation=(
                    "High-entropy printable string extracted from binary "
                    "— candidate embedded secret. Triage manually: "
                    "encryption key, API token, or obfuscated data. If "
                    "real, rotate the key and move the secret to a "
                    "server-issued credential."
                ),
                evidence={
                    "lib": analysis.path,
                    "value_redacted": s.get("value"),
                    "length": s.get("length"),
                    "entropy": entropy,
                    "offset": s.get("offset"),
                },
            ))

        return out

    # ---------- Helpers ----------

    def _get_lib_root(self) -> Path | None:
        ctx = self._context
        if ctx.resources_dir and (ctx.resources_dir / "lib").is_dir():
            return ctx.resources_dir / "lib"
        return None


__all__ = ["NativeInspectorAgent"]
