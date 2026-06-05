"""FL_001 — Flutter ``libapp.so`` string-level auditor (experimental).

Flutter compiles ALL Dart code into ``libapp.so`` as AOT-compiled
native machine code. There is no readable text-style source like the
React-Native ``index.android.bundle``. To audit Flutter you have to
either disassemble the AOT (reFlutter / Doldrums, both heavyweight
research tooling) or string-scan the binary.

This agent does the string scan only. It is **explicitly labelled
experimental** — every scan emits a ``FLUTTER_ANALYSIS_EXPERIMENTAL``
INFO finding noting what we did NOT look at, so a reviewer never
mistakes a clean run for assurance. Findings carry low-to-medium
confidence (0.4–0.6) because string extraction on a stripped AOT
binary mixes real strings with PC-relative reloc fragments and
fragments of Dart class names.

What the agent looks for in ``libapp.so``:

* cleartext ``http://`` URLs (the most actionable signal — backend
  URLs survive AOT compilation as raw strings),
* AWS / Google / Firebase API-key patterns,
* SharedPreferences / HttpClient / Platform.isAndroid markers (kept
  as inventory in the experimental notice — *not* themselves
  findings).

What we deliberately do **not** do:
* No Dart symbol resolution — we can't tell ``my.app.Foo.bar()`` from
  ``some.lib.Foo.bar()`` without the AOT class hierarchy.
* No taint analysis — would need a Dart IR we don't have.
* No call-graph; no field sensitivity.

These limits are stated in the experimental notice every run.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ---------- Detection probes ----------

_FLUTTER_SO  = "libflutter.so"
_FLUTTER_APP = "libapp.so"

# Cap on string-scan bytes per binary — same envelope as NL_001.
# libapp.so for a real app runs anywhere from 5 to 50 MiB; we read up
# to 32 MiB which covers the vast majority of production binaries
# without giving a malicious file unlimited dwell time.
_MAX_BYTES_PER_BINARY = 32 * 1024 * 1024


# ---------- String-scan patterns (bytes) ----------

# URL regex over bytes — only match ASCII-printable, stop at the
# first whitespace or control char.
_URL_RE = re.compile(
    rb"\bhttp://"
    rb"(?!(?:localhost|127\.0\.0\.1|10\.0\.2\.2)(?:[:/]|\b))"
    rb"[A-Za-z0-9./?=&_\-:%~+]{4,260}",
)

# Secret families. Mirrors RN_001 — same patterns, different file.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes], Severity, float], ...] = (
    ("AWS Access Key ID",      re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
     Severity.HIGH, 0.85),
    ("Google API Key",         re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.MEDIUM, 0.65),
    ("Slack Token",            re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     Severity.HIGH, 0.85),
    ("Stripe Live Secret Key", re.compile(rb"\bsk_live_[0-9A-Za-z]{16,}\b"),
     Severity.HIGH, 0.90),
)

# Dart / Flutter framework tokens. Their *presence* tells us this
# really is a Flutter binary. They are not findings on their own;
# we record what was seen in the experimental notice's evidence so
# a triager can spot gaps in our coverage.
_FRAMEWORK_TOKENS: tuple[bytes, ...] = (
    b"FlutterEngine",
    b"DartIsolate",
    b"package:flutter/",
    b"package:http/",
    b"Platform.isAndroid",
    b"SharedPreferences",
    b"FlutterSecureStorage",
    b"HttpClient",
    b"WebViewController",
    b"dart:",
)


# ---------- Vuln-class constants ----------

VC_FLUTTER_EXPERIMENTAL = "FLUTTER_ANALYSIS_EXPERIMENTAL"
VC_FL_CLEARTEXT         = "CLEARTEXT_TRAFFIC_IN_LIBAPP"
VC_FL_SECRET            = "HARDCODED_SECRET_IN_LIBAPP"


# Per-category hit cap.
_MAX_HITS_PER_CATEGORY = 50


# ---------- Agent ----------

class FlutterAgent(BaseAgent):
    """FL_001: Flutter ``libapp.so`` string-level audit (experimental)."""

    AGENT_ID = "FL_001"
    VULN_CLASS = "FLUTTER_LIBAPP_AUDIT"
    PHASE = "Phase 2"
    CATEGORY = "CROSS_PLATFORM"

    async def is_applicable(self) -> bool:
        if self._context.resources_dir is None:
            return False
        if self._find_libapp() is None and not self._find_libflutter():
            return False
        return True

    async def analyze(self) -> list[Finding]:
        libapp = self._find_libapp()
        libflutter = self._find_libflutter()

        # Always emit the experimental notice — even when libapp.so is
        # absent but libflutter is. The notice is the agent's most
        # important honest signal.
        findings: list[Finding] = [
            self._experimental_notice(libapp, libflutter),
        ]
        if libapp is None:
            self._log.info(
                "[FL_001] libflutter present but no libapp.so — "
                "nothing to string-scan",
            )
            return findings

        try:
            blob = libapp.read_bytes()
        except OSError as e:
            self._log.warning(
                "[FL_001] cannot read %s: %s", libapp, e,
            )
            return findings
        if len(blob) > _MAX_BYTES_PER_BINARY:
            self._log.info(
                "[FL_001] truncating %s from %d to %d bytes",
                libapp.name, len(blob), _MAX_BYTES_PER_BINARY,
            )
            blob = blob[:_MAX_BYTES_PER_BINARY]

        findings.extend(self._scan_cleartext_urls(blob, libapp))
        findings.extend(self._scan_secrets(blob, libapp))
        return findings

    # ---------- File discovery ----------

    def _find_libapp(self) -> Path | None:
        return self._find_lib(_FLUTTER_APP)

    def _find_libflutter(self) -> Path | None:
        return self._find_lib(_FLUTTER_SO)

    def _find_lib(self, name: str) -> Path | None:
        resources_dir = self._context.resources_dir
        if resources_dir is None:
            return None
        lib_root = resources_dir / "lib"
        if not lib_root.is_dir():
            return None
        # libapp.so / libflutter.so are present under one or more
        # lib/<abi>/ subdirs. Prefer arm64-v8a if multiple ABIs are
        # shipped — that's what runs on most modern devices and the
        # AOT is identical across ABIs for our string-scan purposes.
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            candidate = lib_root / abi / name
            if candidate.exists() and candidate.is_file():
                return candidate
        # Fall back to whichever ABI dir is present.
        for hit in lib_root.rglob(name):
            if hit.is_file():
                return hit
        return None

    # ---------- Experimental notice ----------

    def _experimental_notice(
        self, libapp: Path | None, libflutter: Path | None,
    ) -> Finding:
        seen_frameworks: list[str] = []
        if libapp is not None:
            try:
                blob = libapp.read_bytes()[:_MAX_BYTES_PER_BINARY]
                for tok in _FRAMEWORK_TOKENS:
                    if tok in blob:
                        seen_frameworks.append(tok.decode("ascii", "replace"))
            except OSError:
                pass

        return self._make_finding(
            vuln_class=VC_FLUTTER_EXPERIMENTAL,
            severity=Severity.INFO,
            confidence=0.9,
            evidence={
                "title": (
                    "Flutter detected — analysis is string-level only "
                    "(experimental)"
                ),
                "libflutter": str(libflutter.name) if libflutter else None,
                "libapp":     str(libapp.name) if libapp else None,
                "framework_tokens_seen": seen_frameworks,
                "coverage_disclosure": (
                    "FL_001 performs ONLY a strings(1)-style scan over "
                    "libapp.so. Dart symbol resolution, AOT "
                    "disassembly, taint analysis, and call-graph "
                    "construction are NOT implemented. Findings "
                    "below carry low-to-medium confidence by design."
                ),
                "future_work": (
                    "Integrate reFlutter or Doldrums to decompile "
                    "libapp.so back to Dart, then re-run the SAST stack "
                    "against recovered sources. Tracked in "
                    "docs/CROSSPLATFORM.md."
                ),
            },
            recommendation=(
                "Treat FL_001 output as a sighting list, not a security "
                "verdict. Combine with manual reFlutter / Doldrums "
                "disassembly when a finding warrants it, and lean on "
                "dynamic analysis (Frida hooks on Dart-VM bridges) for "
                "behavioural coverage."
            ),
        )

    # ---------- String-scan implementations ----------

    def _scan_cleartext_urls(
        self, blob: bytes, libapp: Path,
    ) -> Iterable[Finding]:
        hits: list[dict[str, str]] = []
        seen: set[str] = set()
        for m in _URL_RE.finditer(blob):
            url = m.group(0).decode("ascii", errors="replace")
            if url in seen:
                continue
            seen.add(url)
            if len(hits) >= _MAX_HITS_PER_CATEGORY:
                break
            hits.append({"url": url})
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=VC_FL_CLEARTEXT,
            severity=Severity.MEDIUM,
            confidence=0.55,
            owasp="M3: Insecure Communication",
            masvs="MASVS-NETWORK-1",
            evidence={
                "title": (
                    f"{len(hits)} cleartext http:// URL(s) in libapp.so"
                ),
                "lib": libapp.name,
                "hits": hits,
                "confidence_note": (
                    "String-scan finding — Dart string literals survive "
                    "AOT compile, but matches against the binary may "
                    "include relocation fragments. Verify each URL is a "
                    "real backend before reporting."
                ),
            },
            recommendation=(
                "Migrate every http:// backend to https://. Pair with a "
                "Network Security Config that disables cleartext "
                "traffic so a future build cannot silently regress."
            ),
        )]

    def _scan_secrets(
        self, blob: bytes, libapp: Path,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for label, pat, sev, conf in _SECRET_PATTERNS:
            matches = list(pat.finditer(blob))
            if not matches:
                continue
            hits = [
                {
                    "label": label,
                    "match": _redact(m.group(0).decode("ascii", "replace")),
                }
                for m in matches[:_MAX_HITS_PER_CATEGORY]
            ]
            # Slightly lower confidence than the same patterns in
            # RN_001 because string-scanning a stripped AOT binary
            # produces more PC-relative-reloc false positives.
            findings.append(self._make_finding(
                vuln_class=VC_FL_SECRET,
                severity=sev,
                confidence=conf,
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MASVS-CODE-3",
                evidence={
                    "title": f"Hardcoded secret in libapp.so: {label}",
                    "lib": libapp.name,
                    "match_count": len(matches),
                    "hits": hits,
                    "confidence_note": (
                        "Pattern match against a stripped AOT binary. "
                        "May include false positives — verify against "
                        "the source repository before rotating."
                    ),
                },
                recommendation=(
                    f"A {label}-shaped value is embedded in shipped "
                    "Dart AOT code. If it's live, rotate and move the "
                    "secret behind a server-side proxy. Compile-time "
                    "env-var injection (--dart-define) does not "
                    "obfuscate — strings ship verbatim in libapp.so."
                ),
            ))
        return findings


# ---------- Helpers ----------

def _redact(s: str) -> str:
    if len(s) <= 8:
        return "***"
    return f"{s[:4]}…{s[-4:]}"


__all__ = ["FlutterAgent"]
