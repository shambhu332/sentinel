"""RN_002 — React Native bridge taint detector.

React Native apps ship a JS bundle (`assets/index.android.bundle`)
that drives the native side via the bridge. Two attack shapes worth
flagging statically:

1. **NativeModule calls with attacker-influenced args.** The JS
   bundle is unminified-ish (Hermes bytecode mostly, but the symbol
   table leaks JS module names). When we see
   `NativeModules.MyModule.dangerousOp(x)` and `x` is traceable back
   to an externally-sourced value (an `Intent.getExtras` round-trip,
   a deep-link param, a WebView postMessage), the bridge is a taint
   source.

2. **JS bundle ships with insecure WebView config or eval-style
   code.** `eval(`, `Function(`, `setTimeout(string)` — same risks
   as on the web, doubled by the fact that you can't CSP a bundled
   JS file.

This agent runs string-scoped analysis on the bundle text. Hermes-
compiled bundles get a best-effort string-table extraction (the
symbol table contains module + method names even after compilation).

False positives are inherent: we can't prove a NativeModule call is
unsafe without taint analysis on JS, which we don't do. We surface
the call site + the calling module for human triage and flag the
dangerous primitives at higher confidence.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Bundle locations React Native commonly uses
_BUNDLE_RELPATHS = (
    "assets/index.android.bundle",
    "assets/main.jsbundle",
    "res/raw/index_android_bundle",
)

# JS primitives that are dangerous when fed attacker input
_EVAL_PRIMITIVES_RE = re.compile(
    r"\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*[\w]"
)

# NativeModules.X.method patterns. We also catch the older
# NativeModules['X']['method'] string-key shape.
_NATIVE_MODULE_RE = re.compile(
    r"NativeModules\s*"
    r"(?:\.\s*(\w+)\s*\.\s*(\w+)"
    r"|\[\s*['\"](\w+)['\"]\s*\]\s*\[\s*['\"](\w+)['\"]\s*\])"
    r"\s*\("
)

# Dangerous native method-name patterns (substring match, case-insensitive)
_DANGEROUS_METHOD_HINTS = (
    "exec", "shell", "loadurl", "writefile", "deletefile",
    "decrypt", "signpayload", "sendsms", "dial",
)

# Hermes bundles still contain printable method names. We extract any
# alpha-numeric token >= 5 chars from the raw bytes as a coarse name
# table when textual JS scan returns nothing.
_HERMES_TOKEN_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{4,}")

_MAX_BUNDLE_BYTES = 16 * 1024 * 1024  # 16 MiB safety cap


class ReactNativeBridgeTaintAgent(BaseAgent):
    """RN_002: JS-bundle bridge-taint static analyzer."""

    AGENT_ID = "RN_002"
    VULN_CLASS = "React Native Bridge Taint Surface"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        # RN detection is profiler-driven; fall back to bundle presence.
        if "React Native" in ctx.detected_frameworks():
            return True
        return self._find_bundle() is not None

    async def analyze(self) -> list[Finding]:
        bundle = self._find_bundle()
        if bundle is None:
            return []

        try:
            raw = bundle.read_bytes()
            if len(raw) > _MAX_BUNDLE_BYTES:
                raw = raw[:_MAX_BUNDLE_BYTES]
        except OSError:
            return []

        # Try text decode first — un-compiled bundles are still JS source.
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = ""

        findings: list[Finding] = []

        # 1) Eval primitives — high-signal regardless of bundle shape
        for m in _EVAL_PRIMITIVES_RE.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            findings.append(self._make_finding(
                vuln_class="JS Eval-Family Primitive in RN Bundle",
                severity=Severity.HIGH,
                confidence=0.75,
                recommendation=(
                    "eval / Function / setTimeout-as-string runs whatever "
                    "string you pass it. Shipped in a RN bundle, it's a "
                    "remote code-execution primitive if the input can be "
                    "influenced by a deep-link, WebView message, or "
                    "fetched config. Remove or replace with a parsed AST."
                ),
                evidence={
                    "bundle": str(bundle.name),
                    "line": line_no,
                    "snippet": text[max(0, m.start()-40):m.end()+40],
                },
            ))

        # 2) NativeModule call enumeration — surface for human triage
        seen_calls: set[tuple[str, str]] = set()
        for m in _NATIVE_MODULE_RE.finditer(text):
            mod = m.group(1) or m.group(3) or ""
            method = m.group(2) or m.group(4) or ""
            if not mod or not method:
                continue
            if (mod, method) in seen_calls:
                continue
            seen_calls.add((mod, method))
            method_lower = method.lower()
            is_dangerous = any(h in method_lower for h in _DANGEROUS_METHOD_HINTS)
            findings.append(self._make_finding(
                vuln_class=(
                    "Dangerous RN Bridge Method Call"
                    if is_dangerous
                    else "RN Bridge Method Enumerated"
                ),
                severity=Severity.MEDIUM if is_dangerous else Severity.INFO,
                confidence=0.70 if is_dangerous else 0.55,
                recommendation=(
                    "Confirm the Java handler for "
                    f"`{mod}.{method}` validates its arguments before "
                    "passing them to filesystem / crypto / network APIs. "
                    "RN bridge methods accept arbitrary JS-side input."
                ),
                evidence={
                    "bundle": str(bundle.name),
                    "module": mod,
                    "method": method,
                    "dangerous_hint_matched": is_dangerous,
                },
            ))

        # 3) Hermes fallback — when JS source not present, the symbol
        # table still leaks NativeModule names. Best-effort scan of the
        # raw bytes for tokens that look like NativeModule + method
        # pairs in proximity.
        if not seen_calls and _is_hermes(raw):
            tokens = {
                t.decode("ascii", errors="ignore")
                for t in _HERMES_TOKEN_RE.findall(raw[:_MAX_BUNDLE_BYTES])
            }
            # Heuristic: tokens that match Android's standard native
            # module catalog (Camera, Storage, FileSystem, etc).
            interesting = sorted(
                t for t in tokens
                if any(h in t.lower() for h in _DANGEROUS_METHOD_HINTS)
            )[:20]
            if interesting:
                findings.append(self._make_finding(
                    vuln_class="RN Hermes Bundle — Dangerous Method Names",
                    severity=Severity.LOW,
                    confidence=0.45,
                    recommendation=(
                        "The Hermes-compiled bundle leaks method names "
                        "matching dangerous categories. Confirm runtime "
                        "via the Frida agent which can hook RN bridge "
                        "dispatch."
                    ),
                    evidence={
                        "bundle": str(bundle.name),
                        "hermes": True,
                        "interesting_tokens": interesting,
                    },
                ))

        return findings

    # ---------- helpers ----------

    def _find_bundle(self) -> Path | None:
        ctx = self._context
        if not ctx.resources_dir:
            return None
        for rel in _BUNDLE_RELPATHS:
            p = ctx.resources_dir / rel
            if p.is_file():
                return p
        # Last-resort glob
        for p in ctx.resources_dir.rglob("*.jsbundle"):
            if p.is_file():
                return p
        return None


def _is_hermes(raw: bytes) -> bool:
    """Hermes magic: 0xC61FBC03."""
    return len(raw) >= 4 and raw[0:4] == b"\xc6\x1f\xbc\x03"


__all__ = ["ReactNativeBridgeTaintAgent"]
