"""SCA_004 — Malicious third-party library behavior detector.

Standard SCA (CVE matching) misses two classes of supply-chain attack:

1. **Mission creep** — a utility library (UUID generator, image
   resizer) that quietly issues HTTP requests, reads SharedPreferences,
   or invokes reflection on application classes. The library is named
   innocuously enough that nobody audits it but its behaviour is
   nothing like what its name promises.

2. **Sleeper code** — a library that defers its malicious behaviour
   behind a delay or a `Build.PRODUCT.contains` check, so it only
   triggers on real devices. We can statically spot the presence of
   the dangerous primitives even when we can't prove the trigger.

This agent walks every third-party-library package (anything outside
the app's own `package` namespace, capped by depth) and flags packages
whose claimed purpose (inferred from package name) is incompatible
with the dangerous primitives they actually call.

Heuristic, not provable. Reports at LOW/MEDIUM and lists the specific
primitive call sites — the user audits.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# "Utility" package-name hints — when matched, network/reflection
# calls are unexpected and worth flagging.
_UTILITY_NAME_HINTS = (
    "util", "utils", "common", "helper", "format", "uuid", "string",
    "image", "color", "math", "date", "time", "lang", "io.lib",
    "graphics", "encoding", "base64", "hashing", "compression",
)

# Dangerous primitive patterns we look for in non-app packages
_PRIMITIVES: list[tuple[str, re.Pattern, Severity]] = [
    ("http_call",
     re.compile(r"(HttpURLConnection|OkHttpClient|Retrofit|Volley|HttpClient)"),
     Severity.MEDIUM),
    ("reflection",
     re.compile(r"Class\s*\.\s*forName|Method\s*\.\s*invoke|getDeclaredMethod"),
     Severity.MEDIUM),
    ("dex_loader",
     re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader"),
     Severity.HIGH),
    ("runtime_exec",
     re.compile(r"Runtime\s*\.\s*getRuntime|ProcessBuilder"),
     Severity.HIGH),
    ("shared_prefs_read",
     re.compile(r"getSharedPreferences|SharedPreferences"),
     Severity.LOW),
    ("device_id",
     re.compile(r"getDeviceId|getImei|ANDROID_ID|getSubscriberId"),
     Severity.HIGH),
    ("contacts_read",
     re.compile(r"ContactsContract"),
     Severity.HIGH),
    ("location_read",
     re.compile(r"LocationManager|FusedLocationProviderClient"),
     Severity.HIGH),
]

# Cap files scanned per library to keep big libs from dominating
_MAX_FILES_PER_LIB = 200
# Cap total libraries reported
_MAX_LIBS_REPORTED = 50


class MaliciousLibDetectorAgent(BaseAgent):
    """SCA_004: behavior-based third-party-library suspicion scorer."""

    AGENT_ID = "SCA_004"
    VULN_CLASS = "Suspicious Third-Party Library Behavior"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.decompiled_dir
            and ctx.decompiled_dir.exists()
            and ctx.manifest
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        # App's own package prefix derived from the manifest
        app_pkg = (ctx.manifest or {}).get("package", "") or ""
        app_pkg_parts = app_pkg.split(".") if app_pkg else []
        app_prefix = "/".join(app_pkg_parts[:3]) if app_pkg_parts else ""

        # Find candidate third-party library roots — the top-level
        # directories *not* in the app's own package tree.
        lib_roots = self._enumerate_lib_roots(root, app_prefix)
        if not lib_roots:
            return []

        findings: list[Finding] = []
        for lib_root, lib_name in lib_roots[:_MAX_LIBS_REPORTED]:
            primitives_found = self._scan_lib(lib_root)
            if not primitives_found:
                continue
            # Match against the utility-name heuristic
            is_utility = any(
                hint in lib_name.lower() for hint in _UTILITY_NAME_HINTS
            )
            for primitive, hits, sev in primitives_found:
                # Utility lib + dangerous primitive => escalate one tier
                if is_utility and sev == Severity.LOW:
                    sev = Severity.MEDIUM
                elif is_utility and sev == Severity.MEDIUM:
                    sev = Severity.HIGH
                findings.append(self._emit(lib_name, primitive, hits, sev, is_utility))
        return findings

    # ---------- enumeration ----------

    def _enumerate_lib_roots(
        self, root: Path, app_prefix: str,
    ) -> list[tuple[Path, str]]:
        """Find candidate third-party package roots."""
        out: list[tuple[Path, str]] = []
        # JADX layout typically places sources under either decompiled_dir
        # directly or decompiled_dir/sources.
        bases = [root]
        if (root / "sources").is_dir():
            bases.append(root / "sources")
        seen: set[str] = set()
        for base in bases:
            for top in base.iterdir() if base.is_dir() else []:
                if not top.is_dir():
                    continue
                # Skip the app's own root segment
                rel = str(top.relative_to(base))
                if app_prefix and rel == app_prefix.split("/")[0]:
                    continue
                # Walk one or two levels deeper to identify lib package
                for candidate in top.glob("*"):
                    if not candidate.is_dir():
                        continue
                    rel2 = str(candidate.relative_to(base))
                    if app_prefix and rel2.startswith(app_prefix):
                        continue
                    name = rel2.replace("/", ".")
                    if name in seen:
                        continue
                    seen.add(name)
                    out.append((candidate, name))
        return out

    # ---------- scanning ----------

    @staticmethod
    def _scan_lib(
        lib_root: Path,
    ) -> list[tuple[str, list[dict[str, Any]], Severity]]:
        """Return [(primitive, hits, severity)] for primitives present."""
        primitives_to_hits: dict[str, tuple[list[dict[str, Any]], Severity]] = {}
        scanned = 0
        for p in lib_root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES_PER_LIB:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for primitive, pattern, sev in _PRIMITIVES:
                m = pattern.search(text)
                if not m:
                    continue
                hits, _ = primitives_to_hits.setdefault(primitive, ([], sev))
                if len(hits) < 5:
                    hits.append({
                        "file": p.name,
                        "line": text[:m.start()].count("\n") + 1,
                        "match": m.group(0)[:80],
                    })
        return [
            (primitive, hits, sev)
            for primitive, (hits, sev) in primitives_to_hits.items()
        ]

    # ---------- emission ----------

    def _emit(
        self, lib_name: str, primitive: str,
        hits: list[dict[str, Any]], severity: Severity, is_utility: bool,
    ) -> Finding:
        title = (
            f"Suspicious `{primitive}` Calls in Third-Party Library"
            if not is_utility else
            f"`{primitive}` Calls in Utility-Named Library (Mission Creep)"
        )
        return self._make_finding(
            vuln_class=title,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"The third-party package `{lib_name}` invokes "
                f"`{primitive}` primitives. "
                f"{'The package name implies a utility/helper purpose, '
                   'making the presence of these primitives a strong '
                   'signal of mission creep.' if is_utility else ''} "
                "Audit the call sites and confirm the library's "
                "stated purpose; consider pinning to a vetted version "
                "or replacing with a first-party implementation."
            ),
            evidence={
                "library_package": lib_name,
                "primitive": primitive,
                "is_utility_named": is_utility,
                "hits": hits,
            },
        )


__all__ = ["MaliciousLibDetectorAgent"]
