"""NL_001 — Native Library Agent.

Audits Android shared objects (lib/**/*.so) for security-relevant
strings and patterns that Java-only SAST never sees.

Why this matters:
- Flutter ships ALL Dart code inside libapp.so. SAST against the
  decompiled Java sees an empty shell with one MainActivity.
- React Native ships JS in assets/index.android.bundle plus native
  shims; secrets often hide in libreactnativejni.so.
- C/C++ native libs routinely contain hardcoded backend URLs,
  hardcoded auth tokens, and anti-debug/anti-Frida checks. These
  bypass every Java-source-tree regex agent.

Detection pipeline:
1. Locate all *.so files (resources_dir/lib/<abi>/*.so when
   apktool succeeded, else nothing — keep simple, no zipfile fallback)
2. Extract printable ASCII strings (min length 8)
3. Run pattern matchers in four classes:
   - HTTP/HTTPS URLs (filter out boilerplate android/google/system)
   - High-entropy secrets (Bearer/AWS/Google/Stripe-style)
   - Anti-debug / anti-tamper syscalls and paths
   - Framework markers (Flutter, ReactNative, Unity, Mono)
4. Emit one finding per category with up to MAX_HITS hits
5. Always emit a JNI-export inventory INFO finding when JNI
   symbols are present

Limits:
- Per-binary string-scan cap of 8 MiB (skip huge libs to keep scan
  bounded against APKs with 50+ MB embedded Dart blobs)
- Max 25 hits per category to prevent finding explosion
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_PRINTABLE_BYTE = re.compile(rb"[\x20-\x7e]{8,}")

_MAX_BYTES_PER_BINARY = 8 * 1024 * 1024
_MAX_HITS_PER_CATEGORY = 25

# URLs — strip the obvious noise that ships with the NDK or AGP
_URL_RE = re.compile(rb"https?://[A-Za-z0-9.\-/_:?&=%~+#]{6,200}")
_URL_NOISE = (
    b"schemas.android.com",
    b"www.w3.org",
    b"developer.android.com",
    b"goo.gl/",
    b"www.google.com/pixel",
    b"play.google.com/about/",
    b"crashlytics.com/about",
    b"google.com/about",
)

# Secret-pattern matchers — copied conceptually from A_004 but
# byte-oriented because we're scanning binaries.
_SECRET_PATTERNS: list[tuple[str, bytes, Severity, float]] = [
    ("AWS access key", rb"\bAKIA[0-9A-Z]{16}\b", Severity.CRITICAL, 0.95),
    ("AWS secret key", rb"\b[A-Za-z0-9/+]{40}\b(?=[^A-Za-z0-9/+]|$)",
     Severity.LOW, 0.40),  # high FP rate — confirmation via context
    ("Google API key", rb"\bAIza[0-9A-Za-z\-_]{35}\b", Severity.HIGH, 0.90),
    ("Stripe live key", rb"\bsk_live_[0-9a-zA-Z]{24,}\b",
     Severity.CRITICAL, 0.95),
    ("Stripe publishable key", rb"\bpk_live_[0-9a-zA-Z]{24,}\b",
     Severity.HIGH, 0.85),
    ("GitHub token", rb"\bgh[ps]_[A-Za-z0-9]{36,}\b",
     Severity.CRITICAL, 0.95),
    ("Slack token", rb"\bxox[abpr]-[0-9A-Za-z\-]{10,}\b",
     Severity.HIGH, 0.85),
    ("Generic Bearer token", rb"\bBearer\s+[A-Za-z0-9._\-=]{20,}\b",
     Severity.MEDIUM, 0.55),
    ("Private key PEM header", rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     Severity.CRITICAL, 0.99),
]

# Anti-debug / anti-tamper / anti-Frida signals. Presence does NOT mean
# the app is protected — it means the app *attempts* protection. This is
# useful inventory for pentesters planning a Frida/dynamic engagement.
_ANTI_TAMPER_TOKENS: list[tuple[str, list[bytes]]] = [
    ("ptrace anti-debug", [b"ptrace", b"PT_DENY_ATTACH"]),
    ("TracerPid check", [b"TracerPid", b"/proc/self/status"]),
    ("Frida detection", [b"frida", b"gum-js-loop", b"gmain",
                          b"frida-server", b"linjector", b"re.frida"]),
    ("Xposed / EdXposed detection", [b"de.robv.android.xposed",
                                      b"XposedBridge"]),
    ("Magisk / root detection",
     [b"/sbin/.magisk", b"/system/xbin/su", b"/system/bin/su",
      b"magiskpolicy", b"magisk-cmd"]),
    ("Emulator detection",
     [b"qemu_pipe", b"goldfish", b"ranchu", b"vbox86", b"genymotion"]),
    ("ro.debuggable check", [b"ro.debuggable"]),
]

# Framework markers — telegraph the app's stack so the pentester knows
# which other tooling (Doldrums for Flutter, hermes-dec for RN, etc.)
# to reach for.
_FRAMEWORK_MARKERS: dict[str, list[bytes]] = {
    "Flutter": [b"FlutterEngine", b"flutter_assets", b"libapp.so",
                b"Dart_", b"Dart_Isolate"],
    "React Native": [b"facebook::react", b"ReactNative",
                     b"hermes", b"libreact_"],
    "Unity": [b"UnityEngine", b"libil2cpp", b"il2cpp_"],
    "Xamarin/.NET": [b"mono_jit_init", b"libmonosgen",
                     b"libmonodroid"],
    "Cocos2d-x": [b"cocos2dx", b"cocos2d::"],
    "Qt": [b"QtCore", b"QApplication"],
}

# JNI exports follow the pattern Java_<package>_<class>_<method>. We
# capture them to inventory the JNI surface a reverser would want to
# audit — they're not findings, just situational awareness.
_JNI_EXPORT_RE = re.compile(rb"\bJava_[A-Za-z0-9_]+_[A-Za-z0-9_]+\b")


class NativeLibraryAgent(BaseAgent):
    """NL_001: scans native .so files for secrets, anti-tamper, and frameworks."""

    AGENT_ID = "NL_001"
    VULN_CLASS = "Native Library Exposure"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        path = self._lib_root()
        if path is None:
            logger.info("[NL_001] No native lib directory — skipping")
            return False
        return True

    def _lib_root(self) -> Path | None:
        """Return the directory containing lib/<abi>/*.so, or None.

        Prefers apktool's resources_dir/lib/ since it's already extracted.
        We don't fall back to extracting from the APK zip ourselves —
        keeps the scan dependency-light and predictable. If apktool
        failed, NL_001 just doesn't run; the user gets a clear warning
        in scan output.
        """
        ctx = self._context
        if ctx.resources_dir and (ctx.resources_dir / "lib").is_dir():
            return ctx.resources_dir / "lib"
        return None

    async def analyze(self) -> list[Finding]:
        lib_root = self._lib_root()
        if lib_root is None:
            return []

        so_files = sorted(p for p in lib_root.rglob("*.so") if p.is_file())
        if not so_files:
            logger.info("[NL_001] No .so files under %s", lib_root)
            return []

        logger.info("[NL_001] Scanning %d native libraries", len(so_files))

        urls: list[dict[str, str]] = []
        secrets_by_kind: dict[str, list[dict[str, str]]] = {}
        secrets_meta: dict[str, tuple[Severity, float]] = {}
        anti_tamper: dict[str, set[str]] = {}
        frameworks: dict[str, set[str]] = {}
        jni_exports: list[str] = []

        for so in so_files:
            try:
                blob = so.read_bytes()
            except OSError as e:
                logger.warning("[NL_001] Cannot read %s: %s", so, e)
                continue
            if len(blob) > _MAX_BYTES_PER_BINARY:
                blob = blob[:_MAX_BYTES_PER_BINARY]
                logger.info("[NL_001] Truncated %s to %d bytes",
                            so.name, _MAX_BYTES_PER_BINARY)

            rel = str(so.relative_to(lib_root))

            # 1) URLs
            for m in _URL_RE.finditer(blob):
                url = m.group(0)
                if any(noise in url for noise in _URL_NOISE):
                    continue
                if len(urls) < _MAX_HITS_PER_CATEGORY:
                    urls.append({
                        "lib": rel,
                        "url": url.decode("ascii", errors="replace"),
                    })

            # 2) Secrets
            for label, pat, sev, conf in _SECRET_PATTERNS:
                for m in re.finditer(pat, blob):
                    bucket = secrets_by_kind.setdefault(label, [])
                    if len(bucket) >= _MAX_HITS_PER_CATEGORY:
                        break
                    bucket.append({
                        "lib": rel,
                        "match": _redact(m.group(0)),
                    })
                    secrets_meta[label] = (sev, conf)

            # 3) Anti-tamper inventory
            for label, tokens in _ANTI_TAMPER_TOKENS:
                for tok in tokens:
                    if tok in blob:
                        anti_tamper.setdefault(label, set()).add(rel)
                        break

            # 4) Framework markers
            for fw, tokens in _FRAMEWORK_MARKERS.items():
                for tok in tokens:
                    if tok in blob:
                        frameworks.setdefault(fw, set()).add(rel)
                        break

            # 5) JNI exports — inventory only
            for m in _JNI_EXPORT_RE.finditer(blob):
                if len(jni_exports) >= 200:
                    break
                sym = m.group(0).decode("ascii", errors="replace")
                if sym not in jni_exports:
                    jni_exports.append(sym)

        findings: list[Finding] = []

        if urls:
            findings.append(self._make_finding(
                vuln_class="Hardcoded URLs in Native Library",
                severity=Severity.LOW,
                confidence=0.70,
                recommendation=(
                    "Hardcoded backend URLs in native libraries indicate "
                    "the app speaks to these endpoints regardless of "
                    "build configuration. Verify each is intended for "
                    "production; staging or debug URLs leak environment "
                    "topology. For Flutter apps, these are typical in "
                    "libapp.so and represent the app's actual backend "
                    "surface."
                ),
                evidence={
                    "title": f"{len(urls)} URL(s) extracted from native code",
                    "hits": urls,
                },
            ))

        for label, hits in secrets_by_kind.items():
            sev, conf = secrets_meta[label]
            findings.append(self._make_finding(
                vuln_class=f"Secret in Native Library: {label}",
                severity=sev,
                confidence=conf,
                recommendation=(
                    f"A value matching the {label} format was found in "
                    "a shipped .so binary. If this is a live credential, "
                    "rotate immediately and move the secret to a "
                    "server-side proxy or short-lived token flow. "
                    "Embedding secrets in native libs only delays "
                    "extraction; `strings` plus this regex took seconds."
                ),
                evidence={
                    "title": f"Native-library secret: {label}",
                    "match_count": len(hits),
                    "hits": hits,
                },
            ))

        if anti_tamper:
            findings.append(self._make_finding(
                vuln_class="Anti-Tamper / Anti-Debug Signals in Native Code",
                severity=Severity.INFO,
                confidence=0.90,
                recommendation=(
                    "These signals indicate the app attempts runtime "
                    "tamper or debugger detection. Plan a Frida engagement "
                    "with anti-anti-Frida tooling (frida-gadget injection, "
                    "ptrace bypass, magisk-hide). Presence here does NOT "
                    "imply the protection actually works — it tells you "
                    "which checks to neutralise before DAST is reliable."
                ),
                evidence={
                    "title": (
                        f"{len(anti_tamper)} anti-tamper signal categories "
                        "detected"
                    ),
                    "signals": {
                        k: sorted(v) for k, v in anti_tamper.items()
                    },
                },
            ))

        if frameworks:
            findings.append(self._make_finding(
                vuln_class="Application Framework Detected",
                severity=Severity.INFO,
                confidence=0.95,
                recommendation=(
                    "The app uses one or more hybrid/native frameworks. "
                    "Java-only SAST will miss most of the logic. Use "
                    "framework-specific reversing: Doldrums or reFlutter "
                    "for Flutter; hermes-dec or react-native-decompiler "
                    "for RN; il2cpp_dumper for Unity; pe-dump for "
                    "Xamarin assemblies. Run NL_001 plus the static "
                    "Java agents — but expect coverage gaps."
                ),
                evidence={
                    "title": (
                        "Detected frameworks: "
                        + ", ".join(sorted(frameworks))
                    ),
                    "frameworks": {
                        k: sorted(v) for k, v in frameworks.items()
                    },
                },
            ))

        if jni_exports:
            findings.append(self._make_finding(
                vuln_class="JNI Surface Inventory",
                severity=Severity.INFO,
                confidence=0.90,
                recommendation=(
                    "Exported JNI symbols are the Java-to-native bridge. "
                    "Every Java_* symbol is a candidate native function "
                    "callable from Java. Audit each for: missing arg "
                    "validation, unsafe sscanf/sprintf, buffer overflows, "
                    "and side-channel returns. Use Ghidra/IDA on the .so "
                    "to map symbol → implementation."
                ),
                evidence={
                    "title": f"{len(jni_exports)} JNI export symbols",
                    "symbols": jni_exports[:50],
                    "truncated": len(jni_exports) > 50,
                },
            ))

        return findings


def _redact(value: bytes) -> str:
    """Show first 4 / last 4 chars of a matched secret, mask the middle."""
    text = value.decode("ascii", errors="replace")
    if len(text) <= 12:
        return text[:2] + "***" + text[-2:]
    return text[:4] + "..." + text[-4:]


__all__: Iterable[str] = ["NativeLibraryAgent"]
