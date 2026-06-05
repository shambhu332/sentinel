"""RES_001 — Anti-Tamper / RASP Inventory Agent.

Static inventory of every runtime tamper/root/debugger/emulator
detection signal we can find in the decompiled Java tree. Emits a
single Info finding describing the protection posture so a pentester
knows BEFORE starting DAST what bypass effort to plan for.

Why this matters: presence of these checks does not mean the app is
protected — it means the app *attempts* protection. A two-line
RootBeer call is trivial to neutralise with Frida. A Play Integrity
attestation flow is dramatically harder. Either way, the pentester
needs to know.

Detection: walk decompiled Java looking for known library names,
class references, and API patterns. Group hits by category.

Categories tracked:
- Root detection libraries: RootBeer, RootInspector, Scottyab
- Root detection by hand: /system/xbin/su, su binary checks,
  /sbin/.magisk, getprop ro.debuggable, /proc/mounts inspection
- Debugger detection: Debug.isDebuggerConnected, ApplicationInfo
  FLAG_DEBUGGABLE check, ptrace via JNI
- Emulator detection: Build.FINGERPRINT contains generic/google/sdk;
  /dev/qemu_pipe, ro.kernel.qemu reads
- Frida detection: by string match on 'frida-server',
  'gum-js-loop', enumerating /proc/<pid>/maps for libfrida
- Attestation flows: SafetyNetClient.attest, IntegrityManager
  (Play Integrity API), DeviceCheck
- Generic tamper checks: package signature validation,
  PackageManager.getPackageInfo(GET_SIGNATURES)
"""
from __future__ import annotations

import logging
import re
from typing import Iterable

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Each category maps to a list of regex/literal token patterns. We use
# compiled re for case-insensitive substring scanning; literal needles
# are still expressed as re for uniformity.
_CATEGORY_PATTERNS: dict[str, list[re.Pattern]] = {
    "Root detection (library)": [
        re.compile(r"\bcom\.scottyab\.rootbeer\b"),
        re.compile(r"\bRootBeer\b"),
        re.compile(r"\bcom\.kimchangyoun\.rootbeerFresh\b"),
        re.compile(r"\bcom\.duct\.rootinspector\b"),
    ],
    "Root detection (manual)": [
        re.compile(r"/system/(?:x?bin|sbin)/su\b"),
        re.compile(r"/sbin/\.magisk"),
        re.compile(r"\bmagisk\b", re.IGNORECASE),
        re.compile(r"Runtime\s*\.\s*getRuntime\(\)\s*\.\s*exec\(\s*\"su"),
        re.compile(r"ro\.debuggable"),
        re.compile(r"test-keys"),
    ],
    "Debugger detection": [
        re.compile(r"Debug\.isDebuggerConnected\(\)"),
        re.compile(r"ApplicationInfo\.FLAG_DEBUGGABLE"),
        re.compile(r"android:debuggable"),
        # JNI-side ptrace anti-attach
        re.compile(r"PT_DENY_ATTACH"),
    ],
    "Emulator detection": [
        re.compile(r"Build\.FINGERPRINT"),
        re.compile(r"goldfish|ranchu|vbox86|genymotion", re.IGNORECASE),
        re.compile(r"/dev/qemu_pipe"),
        re.compile(r"ro\.kernel\.qemu"),
    ],
    "Frida detection": [
        re.compile(r"\bfrida-server\b"),
        re.compile(r"\bgum-js-loop\b"),
        re.compile(r"\bre\.frida\.server\b"),
        re.compile(r"linjector", re.IGNORECASE),
    ],
    "Integrity attestation": [
        re.compile(r"\bSafetyNetClient\b"),
        re.compile(r"\bSafetyNet\.getClient\b"),
        re.compile(r"\bIntegrityManager\b"),
        re.compile(r"\bPlayIntegrity\b"),
        re.compile(r"\bIntegrityTokenRequest\b"),
        re.compile(r"\bDeviceCheck\b"),
    ],
    "Signature validation": [
        re.compile(r"GET_SIGNATURES"),
        re.compile(r"GET_SIGNING_CERTIFICATES"),
        re.compile(r"getPackageInfo\(.*,\s*PackageManager\."
                   r"GET_SIGN"),
    ],
    "Anti-hook (Xposed/Substrate)": [
        re.compile(r"de\.robv\.android\.xposed"),
        re.compile(r"\bXposedBridge\b"),
        re.compile(r"\bcom\.saurik\.substrate\b"),
    ],
}

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_CATEGORY = 10


class AntiTamperAgent(BaseAgent):
    """RES_001: inventories root/debug/Frida/attestation detection signals."""

    AGENT_ID = "RES_001"
    VULN_CLASS = "Anti-Tamper Posture"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[RES_001] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        hits: dict[str, list[dict]] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for category, patterns in _CATEGORY_PATTERNS.items():
                bucket = hits.setdefault(category, [])
                if len(bucket) >= _MAX_HITS_PER_CATEGORY:
                    continue
                for pat in patterns:
                    if pat.search(text):
                        bucket.append({
                            "file": rel,
                            "matched_pattern": pat.pattern,
                        })
                        break  # one hit per file per category is enough

        # Strip empty buckets
        hits = {k: v for k, v in hits.items() if v}

        if not hits:
            # No detection signals AT ALL is itself worth reporting —
            # the app has zero RASP posture and any Frida hook will
            # work first try.
            return [self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.INFO,
                confidence=0.80,
                recommendation=(
                    "No root, debugger, emulator, Frida, or attestation "
                    "detection found in the decompiled Java tree. The "
                    "app has zero anti-tamper posture and is a soft "
                    "target for runtime instrumentation. If this is a "
                    "financial or healthcare app, this is a finding in "
                    "its own right — consider integrating Play Integrity "
                    "API or RootBeer at minimum."
                ),
                evidence={
                    "title": "No anti-tamper signals detected",
                    "files_scanned": files_scanned,
                    "categories_present": [],
                    "tier": "None",
                },
            )]

        tier, summary = self._classify_tier(hits)

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.90,
            recommendation=(
                "This finding is an inventory, not a vulnerability. "
                "Use it to scope DAST effort: most categories are "
                "trivially bypassed with Frida hooks. Integrity "
                "attestation (Play Integrity / SafetyNet) is harder — "
                "if those are present, plan for either Magisk Hide + "
                "Play Integrity Fix module, or test on hardware that "
                "passes attestation while still rooted. Categories "
                "discovered: " + ", ".join(sorted(hits.keys())) + "."
            ),
            evidence={
                "title": f"Anti-tamper posture: {tier}",
                "tier": tier,
                "summary": summary,
                "categories_present": sorted(hits.keys()),
                "files_scanned": files_scanned,
                "hits": {
                    k: v[:_MAX_HITS_PER_CATEGORY]
                    for k, v in hits.items()
                },
            },
        )]

    @staticmethod
    def _classify_tier(
        hits: dict[str, list[dict]],
    ) -> tuple[str, str]:
        if "Integrity attestation" in hits:
            return (
                "Strong (attestation present)",
                "App uses Play Integrity / SafetyNet. Bypass requires "
                "either a known-good device or specific Magisk modules. "
                "Plan extra setup time before DAST is reliable.",
            )
        # Need 3+ categories to call it "moderate"
        if len(hits) >= 3:
            return (
                "Moderate (multiple RASP signals)",
                "Multiple detection mechanisms present but no attestation. "
                "Frida bypass scripts can typically neutralise each in "
                "minutes once identified.",
            )
        if hits:
            return (
                "Weak (basic checks only)",
                "Only basic detection logic present. Standard Frida "
                "anti-detection should be sufficient.",
            )
        return ("None", "No detection signals found.")


__all__: Iterable[str] = ["AntiTamperAgent"]
