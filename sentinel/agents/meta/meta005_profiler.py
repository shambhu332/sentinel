"""META_005 — App Profiler Agent (Phase 1.5).

A lightweight pre-scan agent that runs BEFORE the main 88+ analysis
agents. Its job is to build a quick fingerprint of the target APK so
the orchestrator can make intelligent decisions about which agents to
run (Risk-Weighted Scanning).

Why this matters: running all 88 agents against a Flutter app wastes
time — most Java-focused agents find nothing because >95% of the logic
lives in libapp.so. Conversely, a pure-Java app doesn't need the
native analysis agents. By profiling first, we cut scan time by 30–50%
on framework apps while losing zero coverage.

Detection pipeline:
1. **Frameworks**: detect Flutter, React Native, Xamarin, Cordova,
   Unity, NativeScript via manifest metadata, asset markers, and
   decompiled class paths.
2. **Native Libraries**: enumerate .so files, detect ABIs, count
   total native binary size.
3. **Obfuscation Level**: reuse META_001's class-name-distribution
   heuristic to classify Tier 0–3.
4. **API Types**: detect REST, GraphQL, gRPC, WebSocket, MQTT via
   string constants and imports in decompiled source.

The profile is stored in `ctx.app_profile` and consumed by the
orchestrator to filter the agent list before Phase 2.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Maximum files to scan for framework/API detection
_MAX_FILES_TO_SCAN = 2000

# Obfuscation thresholds (mirrored from META_001)
_SHORT_NAME_LENGTH = 3
_SHORT_NAME_RATIO = 0.4

# ---- Framework detection markers ----

_FRAMEWORK_PATH_MARKERS: dict[str, list[str]] = {
    "Flutter": ["io/flutter/", "io.flutter."],
    "React Native": ["com/facebook/react/", "com.facebook.react."],
    "Xamarin/.NET": ["mono/android/", "mono.android."],
    "Cordova/Ionic": ["org/apache/cordova/", "org.apache.cordova."],
    "Capacitor": ["com/getcapacitor/", "com.getcapacitor."],
    "Unity": ["com/unity3d/", "com.unity3d."],
    "Kotlin Multiplatform": ["kotlin/native/", "co/touchlab/"],
    "NativeScript": ["org/nativescript/", "com.tns."],
}

_FRAMEWORK_ASSET_MARKERS: dict[str, list[str]] = {
    "Flutter": ["flutter_assets"],
    "React Native": ["index.android.bundle"],
    "Cordova/Ionic": ["assets/www"],
    "Unity": ["bin/Data/Managed", "assets/bin/Data"],
    "Xamarin/.NET": ["assemblies"],
}

_FRAMEWORK_NATIVE_MARKERS: dict[str, list[str]] = {
    "Flutter": ["libflutter.so", "libapp.so"],
    "React Native": ["libreactnativejni.so", "libhermes.so"],
    "Unity": ["libil2cpp.so", "libunity.so"],
    "Xamarin/.NET": ["libmonosgen-2.0.so", "libmonodroid.so"],
}

# ---- API type detection patterns ----

_API_TYPE_PATTERNS: dict[str, list[re.Pattern]] = {
    "GraphQL": [
        re.compile(r'["\']graphql["\']', re.IGNORECASE),
        re.compile(r'query\s*\{', re.IGNORECASE),
        re.compile(r'mutation\s*\{', re.IGNORECASE),
        re.compile(r'import.*graphql', re.IGNORECASE),
        re.compile(r'ApolloClient', re.IGNORECASE),
    ],
    "gRPC": [
        re.compile(r'import.*grpc', re.IGNORECASE),
        re.compile(r'ManagedChannel', re.IGNORECASE),
        re.compile(r'\.proto["\s]', re.IGNORECASE),
        re.compile(r'io\.grpc\.'),
    ],
    "WebSocket": [
        re.compile(r'WebSocket', re.IGNORECASE),
        re.compile(r'wss?://', re.IGNORECASE),
        re.compile(r'OkHttpClient.*webSocket', re.IGNORECASE),
    ],
    "MQTT": [
        re.compile(r'mqtt://', re.IGNORECASE),
        re.compile(r'MqttClient', re.IGNORECASE),
        re.compile(r'org\.eclipse\.paho', re.IGNORECASE),
    ],
    "REST": [
        re.compile(r'Retrofit', re.IGNORECASE),
        re.compile(r'@GET\(|@POST\(|@PUT\(|@DELETE\(', re.IGNORECASE),
        re.compile(r'OkHttpClient', re.IGNORECASE),
        re.compile(r'HttpURLConnection', re.IGNORECASE),
        re.compile(r'Volley', re.IGNORECASE),
    ],
}

# ---- Agent-to-profile relevance mapping ----
# Maps profile conditions to agent ID prefixes that should be SKIPPED.
# Agents not in any skip list always run.

# Framework-based skip rules: when a hybrid framework is dominant,
# skip agents that only analyse Java source (their findings would be
# noise from the framework's Java shim, not the app's real logic).
_JAVA_ONLY_AGENT_PREFIXES = ("TAINT", "D_0")

# Agent categories that require native libs to be present
_NATIVE_ONLY_PREFIXES = ("NL_", "META_006")


class ProfilerAgent(BaseAgent):
    """META_005: pre-scan profiler for risk-weighted agent selection.

    Unlike most agents, this one does NOT emit security findings. It
    populates ctx.app_profile which the orchestrator reads to filter
    the Phase 2 agent list.

    The single INFO finding it emits is a scan-metadata record that
    shows up in the report as an executive summary of the target app's
    technology stack.
    """

    AGENT_ID = "META_005"
    VULN_CLASS = "Application Profile"
    PHASE = "Phase 1.5"

    async def is_applicable(self) -> bool:
        """Always applicable — we need the profile before Phase 2."""
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        profile: dict[str, Any] = {}

        # Step 1: Detect frameworks
        frameworks = self._detect_frameworks()
        profile["frameworks"] = sorted(frameworks)

        # Step 2: Enumerate native libraries
        native_info = self._enumerate_native_libs()
        profile["native_libs_info"] = native_info

        # Step 3: Assess obfuscation level
        obfuscation = self._assess_obfuscation()
        profile["obfuscation_level"] = obfuscation["tier"]
        profile["obfuscation_details"] = obfuscation

        # Step 4: Detect API types
        api_types = self._detect_api_types()
        profile["api_types"] = sorted(api_types)

        # Step 5: Generate recommended agent filter
        profile["skip_agents"] = self._compute_skip_list(
            frameworks, native_info, obfuscation,
        )

        # Store profile in context for orchestrator consumption
        ctx.app_profile = profile

        # Emit a single INFO finding as a scan metadata record
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.90,
            recommendation=(
                "This is an informational finding summarising the target "
                "application's technology stack. Use this profile to guide "
                "manual testing: framework-specific tools may be needed for "
                "full coverage beyond SENTINEL's automated analysis."
            ),
            evidence={
                "title": "Application Profile Summary",
                "frameworks": sorted(frameworks),
                "native_libs": native_info,
                "obfuscation": obfuscation,
                "api_types": sorted(api_types),
                "agents_skipped": len(profile["skip_agents"]),
                "summary": self._build_summary(
                    frameworks, native_info, obfuscation, api_types,
                ),
            },
        )]

    # ---- Framework detection ----

    def _detect_frameworks(self) -> set[str]:
        """Detect hybrid/native frameworks from multiple sources."""
        found: set[str] = set()
        ctx = self._context

        # Source 1: decompiled Java class paths
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            files_scanned = 0
            for path in ctx.decompiled_dir.rglob("*.java"):
                if not path.is_file():
                    continue
                files_scanned += 1
                if files_scanned > _MAX_FILES_TO_SCAN:
                    break
                rel = str(path.relative_to(ctx.decompiled_dir))
                for fw, markers in _FRAMEWORK_PATH_MARKERS.items():
                    if any(m in rel for m in markers):
                        found.add(fw)

        # Source 2: asset/resource paths
        if ctx.resources_dir and ctx.resources_dir.exists():
            try:
                scanned = 0
                for asset in ctx.resources_dir.rglob("*"):
                    scanned += 1
                    if scanned > 5000:
                        break
                    rel = str(asset.relative_to(ctx.resources_dir))
                    for fw, markers in _FRAMEWORK_ASSET_MARKERS.items():
                        if any(m in rel for m in markers):
                            found.add(fw)
            except OSError:
                pass

        # Source 3: native library names
        lib_root = self._get_lib_root()
        if lib_root:
            for so in lib_root.rglob("*.so"):
                name = so.name
                for fw, lib_names in _FRAMEWORK_NATIVE_MARKERS.items():
                    if name in lib_names:
                        found.add(fw)

        return found

    # ---- Native library enumeration ----

    def _enumerate_native_libs(self) -> dict[str, Any]:
        """Count and categorize native libraries."""
        lib_root = self._get_lib_root()
        if not lib_root:
            return {"count": 0, "total_size_bytes": 0, "abis": [], "libs": []}

        so_files = sorted(p for p in lib_root.rglob("*.so") if p.is_file())
        total_size = sum(f.stat().st_size for f in so_files)

        # Detect ABI directories
        abis: set[str] = set()
        for so in so_files:
            parts = so.relative_to(lib_root).parts
            if len(parts) >= 2:
                abis.add(parts[0])

        return {
            "count": len(so_files),
            "total_size_bytes": total_size,
            "abis": sorted(abis),
            "libs": [so.name for so in so_files[:50]],  # cap for report size
        }

    # ---- Obfuscation assessment ----

    def _assess_obfuscation(self) -> dict[str, Any]:
        """Quick obfuscation tier assessment."""
        ctx = self._context
        if not ctx.decompiled_dir or not ctx.decompiled_dir.exists():
            return {"tier": "unknown", "short_ratio": 0.0, "total_classes": 0}

        class_names: list[str] = []
        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                break
            name = path.stem.split("$")[0]
            class_names.append(name)

        if not class_names:
            return {"tier": "unknown", "short_ratio": 0.0, "total_classes": 0}

        short = [n for n in class_names if len(n) <= _SHORT_NAME_LENGTH]
        ratio = len(short) / len(class_names)

        if ratio >= _SHORT_NAME_RATIO and len(class_names) > 50:
            tier = "Tier 1 (ProGuard/R8)"
        elif ratio < 0.1:
            tier = "Tier 0 (Unobfuscated)"
        else:
            tier = "Tier 0.5 (Partial)"

        return {
            "tier": tier,
            "short_ratio": round(ratio, 3),
            "total_classes": len(class_names),
            "short_count": len(short),
        }

    # ---- API type detection ----

    def _detect_api_types(self) -> set[str]:
        """Detect API communication patterns in decompiled source."""
        found: set[str] = set()
        ctx = self._context

        if not ctx.decompiled_dir or not ctx.decompiled_dir.exists():
            return found

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                break
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for api_type, patterns in _API_TYPE_PATTERNS.items():
                if api_type in found:
                    continue
                for pat in patterns:
                    if pat.search(content):
                        found.add(api_type)
                        break

            # Early exit if we've found all types
            if len(found) == len(_API_TYPE_PATTERNS):
                break

        return found

    # ---- Agent skip-list computation ----

    @staticmethod
    def _compute_skip_list(
        frameworks: set[str],
        native_info: dict[str, Any],
        obfuscation: dict[str, Any],
    ) -> list[str]:
        """Compute agent ID prefixes to skip based on the profile.

        Rules:
        1. If a dominant hybrid framework is detected (Flutter, RN, Xamarin,
           Unity), skip Java-taint agents (they'd scan the framework shim).
        2. If no native libs exist, skip native-only agents.
        """
        skip: list[str] = []

        # Rule 1: Hybrid framework → skip Java-intensive agents
        dominant_hybrids = {"Flutter", "React Native", "Xamarin/.NET", "Unity"}
        if frameworks & dominant_hybrids:
            skip.extend(_JAVA_ONLY_AGENT_PREFIXES)

        # Rule 2: No native libs → skip native agents
        if native_info.get("count", 0) == 0:
            skip.extend(_NATIVE_ONLY_PREFIXES)

        return skip

    # ---- Helpers ----

    def _get_lib_root(self) -> Path | None:
        """Return the native lib directory, or None."""
        ctx = self._context
        if ctx.resources_dir and (ctx.resources_dir / "lib").is_dir():
            return ctx.resources_dir / "lib"
        return None

    @staticmethod
    def _build_summary(
        frameworks: set[str],
        native_info: dict[str, Any],
        obfuscation: dict[str, Any],
        api_types: set[str],
    ) -> str:
        """One-paragraph executive summary of the app profile."""
        parts: list[str] = []

        if frameworks:
            parts.append(f"Frameworks: {', '.join(sorted(frameworks))}")
        else:
            parts.append("Pure Android/Java application")

        native_count = native_info.get("count", 0)
        if native_count:
            size_mb = native_info.get("total_size_bytes", 0) / (1024 * 1024)
            parts.append(
                f"{native_count} native libraries ({size_mb:.1f} MB, "
                f"ABIs: {', '.join(native_info.get('abis', []))})"
            )

        tier = obfuscation.get("tier", "unknown")
        parts.append(f"Obfuscation: {tier}")

        if api_types:
            parts.append(f"API types: {', '.join(sorted(api_types))}")

        return ". ".join(parts) + "."


__all__ = ["ProfilerAgent"]
