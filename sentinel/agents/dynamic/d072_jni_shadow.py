"""D_072 — JNI Shadow Executor (Native RCE candidate identifier).

Native methods often skip input validation that the Java side relies
on. Two classic shapes:

  * **Format-string bugs**     — `__android_log_print(fmt, attacker_str)`
    where `attacker_str` flows from a `native` declared method.
  * **Buffer overflows**       — fixed-size stack/heap buffers
    populated from JNI string args via `strcpy` / `sprintf` /
    `memcpy(buf, jstr, jstrlen)`.

D_072 is the SAST half: it walks decompiled Java for `native` method
declarations whose name maps to a `Java_<pkg>_<class>_<method>`
export reported by META_006, and emits a `frida_payload` carrying the
exact native function signature the Frida hook should attach.

The Frida hook (`d072_jni_shadow.ts`) then:
  1. `Interceptor.attach`es on the resolved symbol address
  2. Injects a small canary + tiny format-string payload (`%n%n%n`)
  3. Watches with `MemoryAccessMonitor` for OOB writes
  4. **Hard-stops** if more than 2 memory violations occur in 1
     second — the kernel-panic kill-switch.

We require META_006's native_inspector output (`ctx.app_profile`
carries it after Phase 1.5). When META_006 didn't run we degrade
to "candidates only" — no symbol resolution, no Frida payload —
so the SAST half is never blocked by a missing native scan.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Catches: `public native String foo(String, int);`
# Captures (modifiers, return_type, name, params).
_NATIVE_RE = re.compile(
    r"\b(?:public|private|protected|static|final|\s)+\s+"
    r"native\s+([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*;"
)

# Catches Java class declaration: `class Foo extends Bar`
_CLASS_RE = re.compile(r"\bclass\s+(\w+)")

# Method name fragments that strongly suggest the native impl handles
# strings — these get HIGH severity because the format-string risk is
# real-world. Conservative on purpose.
_STRINGY_NAME_RE = re.compile(
    r"(format|log|print|sprintf|render|build|concat|append|"
    r"message|status|name|path|url|cmd|exec|parse)",
    re.IGNORECASE,
)

_MAX_FILES = 2000


def _java_jni_mangle(package: str, class_name: str, method: str) -> str:
    """Build the canonical JNI export name.

    JNI mangling rules: `Java_<pkg-with-dots-as-underscores>_<class>_<method>`,
    with literal `_` in any of those becoming `_1`. Real apps occasionally
    add the long-form overload suffix; that's not needed for symbol lookup.
    """
    def esc(s: str) -> str:
        return s.replace("_", "_1")
    pkg_part = "_".join(esc(p) for p in package.split(".") if p)
    return f"Java_{pkg_part}_{esc(class_name)}_{esc(method)}"


class JniShadowAgent(BaseAgent):
    """D_072: JNI native-method shadow executor target identifier."""

    AGENT_ID = "D_072"
    VULN_CLASS = "Native RCE Candidate (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        manifest = ctx.manifest or {}
        package = manifest.get("package", "") or ""

        # Pull the META_006 result from the app profile if present.
        # META_006 emits its evidence directly into Finding output, not
        # into ctx.app_profile. We poke for it via the memory layer
        # at runtime — but since findings haven't been emitted yet in
        # Phase 2, we read META_005's `native_libs_info` for the lib
        # list and surface that to the hook. Symbol enumeration is the
        # hook's job at runtime via Module.enumerateExports.
        native_info = ctx.app_profile.get("native_libs_info") or {}
        lib_hint: list[str] = native_info.get("libs", []) or []

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
            if "native " not in text:
                continue
            class_m = _CLASS_RE.search(text)
            if not class_m:
                continue
            class_name = class_m.group(1)
            rel = str(path.relative_to(root))

            # Recover the Java package from the file path under
            # decompiled_dir, falling back to the manifest package.
            file_pkg = self._infer_package(rel) or package

            for m in _NATIVE_RE.finditer(text):
                return_type = m.group(1)
                method = m.group(2)
                params = m.group(3).strip()
                stringy_name = bool(_STRINGY_NAME_RE.search(method))
                takes_string = "String" in params
                severity = (
                    Severity.HIGH if (stringy_name and takes_string)
                    else Severity.MEDIUM
                )
                jni_symbol = _java_jni_mangle(file_pkg, class_name, method)
                line_no = text[:m.start()].count("\n") + 1

                findings.append(self._make_finding(
                    vuln_class=self.VULN_CLASS,
                    severity=severity,
                    confidence=0.65,
                    recommendation=(
                        f"Native method `{class_name}.{method}` is declared "
                        f"with params `{params}`. The Frida shadow-execute "
                        f"hook will attach to `{jni_symbol}`, inject a "
                        "controlled canary + tiny format-string payload, "
                        "and watch for OOB writes via MemoryAccessMonitor. "
                        "Validate all jstring inputs before passing to "
                        "format / strcpy / sprintf — and prefer "
                        "snprintf-with-explicit-bound."
                    ),
                    evidence={
                        "file": rel,
                        "class": class_name,
                        "method": method,
                        "params": params,
                        "return_type": return_type,
                        "line": line_no,
                        "takes_string_arg": takes_string,
                        "stringy_method_name": stringy_name,
                        "jni_symbol": jni_symbol,
                        "native_lib_hints": lib_hint[:5],
                        "dynamic_target": True,
                        "frida_payload": self._build_payload(
                            jni_symbol, params, lib_hint,
                        ),
                    },
                ))
        return findings

    # ---------- helpers ----------

    @staticmethod
    def _infer_package(rel: str) -> str:
        """Derive the Java package from a decompiled-tree-relative path.

        Drops the leading "sources/" segment that JADX emits and the
        trailing `.java` filename.
        """
        parts = rel.replace("\\", "/").split("/")
        if parts and parts[0] == "sources":
            parts = parts[1:]
        if parts and parts[-1].endswith(".java"):
            parts = parts[:-1]
        return ".".join(parts)

    @staticmethod
    def _build_payload(
        jni_symbol: str, params: str, lib_hint: list[str],
    ) -> dict[str, Any]:
        return {
            "jni_symbol": jni_symbol,
            "native_lib_hints": lib_hint[:10],
            "params": params,
            # The TS hook applies these in order; each one is a tiny
            # payload so a memory monitor can isolate its blame.
            "probes": [
                {"kind": "canary", "value": "AAAA_CANARY_AAAA"},
                {"kind": "format_string", "value": "%n%n%n"},
                {"kind": "format_string_safe_short", "value": "%s%s%s"},
                {"kind": "oversize", "value": "A" * 256},
            ],
            "safety_budget": {
                # The brief specifies "Hard stop if >2 memory violations
                # in 1 second." We expose that as part of the payload so
                # the TS side enforces it without needing a separate config.
                "max_actions_total": 6,
                "max_actions_per_sec": 2,
                "wall_clock_budget_s": 15,
                "max_consecutive_crashes": 2,
                "max_mem_violations_per_sec": 2,
                "max_payload_bytes": 512,
            },
            "frida_script_hint":
                "// D_072 — Interceptor.attach on the JNI symbol; "
                "inject probes;\n"
                "// MemoryAccessMonitor watches for OOB writes.\n"
                "// rpc.exports.jnishadow(payload) is the entry\n",
        }


__all__ = ["JniShadowAgent"]
