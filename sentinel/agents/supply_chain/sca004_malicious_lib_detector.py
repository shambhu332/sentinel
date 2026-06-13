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
        # NetworkX behaviour graph: each library -> each dangerous
        # primitive it exercises. Node attributes carry the severity
        # and utility flag so the renderer can colour edges.
        graph_nodes: list[dict[str, Any]] = []
        graph_edges: list[dict[str, Any]] = []

        for lib_root, lib_name in lib_roots[:_MAX_LIBS_REPORTED]:
            primitives_found = self._scan_lib(lib_root)
            if not primitives_found:
                continue
            # Match against the utility-name heuristic
            is_utility = any(
                hint in lib_name.lower() for hint in _UTILITY_NAME_HINTS
            )
            graph_nodes.append({
                "id": f"lib:{lib_name}",
                "label": lib_name,
                "type": "library",
                "is_utility": is_utility,
                "primitive_count": len(primitives_found),
            })
            for primitive, hits, sev in primitives_found:
                # Utility lib + dangerous primitive => escalate one tier
                escalated_sev = sev
                if is_utility and sev == Severity.LOW:
                    escalated_sev = Severity.MEDIUM
                elif is_utility and sev == Severity.MEDIUM:
                    escalated_sev = Severity.HIGH
                findings.append(self._emit(
                    lib_name, primitive, hits, escalated_sev, is_utility,
                ))
                graph_edges.append({
                    "source": f"lib:{lib_name}",
                    "target": f"prim:{primitive}",
                    "severity": escalated_sev.value,
                    "hit_count": len(hits),
                })

        if graph_nodes and graph_edges:
            # Emit a single INFO finding that carries the graph payload.
            # Frontend renders it as a force-directed view.
            primitive_node_ids: set[str] = set()
            for e in graph_edges:
                primitive_node_ids.add(e["target"])
            for nid in sorted(primitive_node_ids):
                graph_nodes.append({
                    "id": nid,
                    "label": nid.split(":", 1)[1],
                    "type": "primitive",
                })
            findings.append(self._make_finding(
                vuln_class="Third-Party Library Behaviour Graph",
                severity=Severity.INFO,
                confidence=0.95,
                recommendation=(
                    "Aggregated NetworkX-style graph of every third-party "
                    "library and the dangerous primitives it touches. "
                    "Surface this to reviewers as a single visualisation."
                ),
                evidence={
                    "graph": {
                        "nodes": graph_nodes,
                        "edges": graph_edges,
                        "library_count": sum(
                            1 for n in graph_nodes if n.get("type") == "library"
                        ),
                        "primitive_count": len(primitive_node_ids),
                    },
                },
            ))
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
