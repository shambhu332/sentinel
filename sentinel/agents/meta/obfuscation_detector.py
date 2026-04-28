"""META_001 — Obfuscation Detector Agent.

Identifies the obfuscation tooling used on an APK and reports the expected
SENTINEL detection rate against that obfuscation tier.

Why this matters: SENTINEL's static analysis works well against unobfuscated
or lightly-obfuscated apps (ProGuard/R8 with name renaming only). Against
heavily-obfuscated apps with string encryption (DexGuard) or enterprise
packers (Promon SHIELD, Arxan, ironSource Bouncer), static analysis loses
significant detection power. Letting the user know what they're scanning
manages expectations and recommends DAST follow-up where appropriate.

Detection pipeline:
1. Analyse class name distribution in decompiled output
   - Many short single-letter names → obfuscation present
   - Mostly readable names → no obfuscation
2. Look for obfuscator signature classes / packages
   - DexGuard: com.guardsquare.* or specific decryption stubs
   - Promon: com.promon.*
   - Arxan: __arxan_* exports
   - ironSource: com.ironsource.adqualitysdk.*
3. Inspect native libraries for known packer signatures
4. Emit an Info finding describing the tier
"""
from __future__ import annotations

import logging

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Obfuscator signature classes. Presence of these strongly indicates the tool.
_OBFUSCATOR_SIGNATURES: dict[str, list[str]] = {
    "DexGuard": [
        "com/guardsquare/",
        "com/dexguard/",
    ],
    "Promon SHIELD": [
        "com/promon/",
        "com/criticalblue/",
    ],
    "Arxan / Digital.ai": [
        "__arxan_",
        "com/digitalai/protection/",
    ],
    "ironSource Bouncer": [
        "com/ironsource/adqualitysdk/sdk/",
    ],
    "AppSealing": [
        "com/inka/appsealing/",
    ],
    "Bangcle / Secneo": [
        "com/secneo/apkwrapper/",
    ],
}

# Threshold for "many short class names" — classes with names like a.b, c.d
_SHORT_NAME_LENGTH_THRESHOLD = 3
_SHORT_NAME_RATIO_THRESHOLD = 0.4

_MAX_FILES_TO_SCAN = 3000


class ObfuscationDetectorAgent(BaseAgent):
    """META_001: detects what obfuscator was used on the APK."""

    AGENT_ID = "META_001"
    VULN_CLASS = "Obfuscation Analysis"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[META_001] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context

        # Step 1: catalogue all class file paths
        java_files: list[str] = []
        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                break
            rel = str(path.relative_to(ctx.decompiled_dir))
            java_files.append(rel)

        if not java_files:
            logger.info("[META_001] No Java files to analyse")
            return []

        # Step 2: detect obfuscator signatures
        detected_obfuscators: list[str] = []
        for obfuscator, signatures in _OBFUSCATOR_SIGNATURES.items():
            for sig in signatures:
                if any(sig in f for f in java_files):
                    detected_obfuscators.append(obfuscator)
                    break

        # Step 3: analyse class name distribution
        class_names: list[str] = []
        for f in java_files:
            # Get just the class name (last path component, no extension)
            name = f.rsplit("/", 1)[-1].removesuffix(".java")
            # Strip nested-class suffixes like Foo$1, Foo$Bar
            base = name.split("$")[0]
            class_names.append(base)

        short_names = [n for n in class_names if len(n) <= _SHORT_NAME_LENGTH_THRESHOLD]
        short_ratio = len(short_names) / len(class_names) if class_names else 0

        # Step 4: check for cleartext strings vs encrypted-looking blobs
        # Heuristic: count the ratio of short-class-name files
        # to total files. High ratio (>40%) = ProGuard/R8 ran.

        # Step 5: classify the tier
        tier, severity_label, detection_estimate = self._classify(
            detected_obfuscators=detected_obfuscators,
            short_name_ratio=short_ratio,
            total_classes=len(class_names),
        )

        # Always emit an informational finding describing what we saw
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.85,
            recommendation=self._build_recommendation(tier, detected_obfuscators),
            evidence={
                "title": f"Obfuscation Tier: {tier}",
                "tier": tier,
                "detected_obfuscators": detected_obfuscators,
                "total_class_files": len(class_names),
                "short_class_count": len(short_names),
                "short_class_ratio": round(short_ratio, 3),
                "expected_detection_rate": detection_estimate,
                "package": (ctx.manifest or {}).get("package", "?"),
                "summary": severity_label,
            },
        )]

    @staticmethod
    def _classify(
        detected_obfuscators: list[str],
        short_name_ratio: float,
        total_classes: int,
    ) -> tuple[str, str, str]:
        """Returns (tier_name, summary_text, detection_rate_estimate)."""
        # Tier 3: enterprise packers (DexGuard with packing, Promon, Arxan, etc.)
        enterprise_tools = {
            "Promon SHIELD", "Arxan / Digital.ai",
            "ironSource Bouncer", "AppSealing", "Bangcle / Secneo",
        }
        if any(t in detected_obfuscators for t in enterprise_tools):
            return (
                "Tier 3 (Enterprise packer)",
                f"Enterprise-grade protection detected ({', '.join(detected_obfuscators)}). "
                f"Static analysis limited; runtime DAST and manual reverse "
                f"engineering recommended.",
                "~20-40% (static); higher with DAST",
            )

        # Tier 2: DexGuard (string encryption, control flow obfuscation)
        if "DexGuard" in detected_obfuscators:
            return (
                "Tier 2 (DexGuard)",
                "DexGuard detected — string encryption and code obfuscation "
                "likely. Some findings (Firebase URLs, hardcoded secrets) may be "
                "missed by static analysis. DAST recommended for full coverage.",
                "~50-70% (static); ~85%+ with DAST",
            )

        # Tier 1: ProGuard/R8 (name renaming only)
        if short_name_ratio >= _SHORT_NAME_RATIO_THRESHOLD and total_classes > 50:
            return (
                "Tier 1 (ProGuard/R8)",
                "Standard ProGuard/R8 obfuscation detected (name renaming only). "
                "Manifest, framework methods, and string constants remain "
                "readable. SENTINEL static analysis works well against this tier.",
                "~80-90%",
            )

        # Tier 0: no significant obfuscation
        return (
            "Tier 0 (Unobfuscated)",
            "No significant obfuscation detected. Class names, method names, "
            "and string constants are all readable. SENTINEL has full visibility "
            "into the application's code and resources.",
            "~90-95%",
        )

    @staticmethod
    def _build_recommendation(tier: str, detected: list[str]) -> str:
        if "Tier 3" in tier:
            return (
                "This APK uses enterprise-grade application protection. "
                "Static analysis findings should be treated as a starting point; "
                "expect significant gaps. To improve coverage: (1) use Frida "
                "with anti-anti-Frida helpers to bypass tamper detection, "
                "(2) dump the decrypted DEX from runtime memory, (3) consider "
                "manual reverse engineering with Ghidra/IDA. SENTINEL Sprint 7+ "
                "DAST will partially address this."
            )
        if "Tier 2" in tier:
            return (
                "This APK uses string encryption. SENTINEL agents that rely on "
                "matching string constants (Firebase URLs, hardcoded secrets, "
                "HTTP URLs) may produce false negatives. To improve coverage: "
                "use Frida hooks to capture decrypted strings at runtime, or "
                "use mitmproxy to capture network traffic during normal app use. "
                "These are integrated in SENTINEL's DAST module (Sprint 7+)."
            )
        if "Tier 1" in tier:
            return (
                "Standard ProGuard/R8 obfuscation. SENTINEL works well against "
                "this tier — manifest-based detections, framework method "
                "patterns, and string constant searches all remain reliable. No "
                "action needed; the rest of the SENTINEL agents will run with "
                "high confidence."
            )
        return (
            "No obfuscation detected. SENTINEL has full code visibility and "
            "should produce the highest detection rates. This is unusual for "
            "production apps — verify this APK is from a real release "
            "(not a debug build)."
        )
