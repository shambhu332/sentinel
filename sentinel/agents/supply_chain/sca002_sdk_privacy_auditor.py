"""SCA_002 — Third-party SDK privacy auditor.

Identifies third-party SDKs by their package signatures and flags when
the app's declared permissions look excessive for the SDK's stated
purpose. Example: an analytics or ad SDK should not pull SMS access.

The detection logic is conservative: we only flag when (a) the SDK is
definitively present (package path observed in decompiled output) and
(b) at least one of the SDK's "excessive" permissions is declared in
the manifest. We don't try to attribute the permission request to the
SDK at the bytecode level — that's a manual-review job.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Known SDKs, keyed by display name.
#   path_markers: substrings expected in decompiled file paths.
#   purpose:      one-liner for the report.
#   excessive:    permissions that should NOT be requested by an SDK of
#                 this category. Real-world incidents we've seen:
#                 ad SDKs pulling READ_SMS, analytics pulling
#                 READ_CONTACTS, etc.
_SDK_CATALOG: dict[str, dict[str, Any]] = {
    "Facebook SDK": {
        "path_markers": ["com/facebook/", "com.facebook."],
        "purpose": "Social login / analytics / ads",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.SEND_SMS",
        },
    },
    "Adjust": {
        "path_markers": ["com/adjust/sdk", "com.adjust.sdk"],
        "purpose": "Mobile attribution / install tracking",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        },
    },
    "AppsFlyer": {
        "path_markers": ["com/appsflyer/", "com.appsflyer."],
        "purpose": "Mobile attribution",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
        },
    },
    "Branch": {
        "path_markers": ["io/branch/", "io.branch."],
        "purpose": "Deep linking / attribution",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
        },
    },
    "Mixpanel": {
        "path_markers": ["com/mixpanel/android", "com.mixpanel.android"],
        "purpose": "Product analytics",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
        },
    },
    "Amplitude": {
        "path_markers": ["com/amplitude/", "com.amplitude."],
        "purpose": "Product analytics",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
        },
    },
    "AdMob": {
        "path_markers": ["com/google/android/gms/ads", "com.google.android.gms.ads"],
        "purpose": "Ad serving",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        },
    },
    "OneSignal": {
        "path_markers": ["com/onesignal/", "com.onesignal."],
        "purpose": "Push notifications",
        "excessive": {
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
        },
    },
}

# Cap files probed for SDK detection
_MAX_PROBES = 3000


class SDKPrivacyAuditorAgent(BaseAgent):
    """SCA_002: flags third-party SDKs paired with excessive permissions."""

    AGENT_ID = "SCA_002"
    VULN_CLASS = "Third-Party SDK Privacy Mismatch"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.manifest
            and (
                (ctx.decompiled_dir and ctx.decompiled_dir.exists())
                or ctx.has_androguard()
            )
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        permissions = set(ctx.permissions or [])

        present_sdks = self._detect_sdks()
        if not present_sdks:
            return []

        findings: list[Finding] = []
        for sdk_name in present_sdks:
            spec = _SDK_CATALOG[sdk_name]
            offending = sorted(permissions & spec["excessive"])
            if not offending:
                continue
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.70,
                recommendation=(
                    f"The {sdk_name} SDK is bundled; its category is "
                    f"\"{spec['purpose']}\". The manifest declares "
                    f"permission(s) typically considered excessive for "
                    f"this category. Either remove the permission(s), "
                    f"confirm a separate first-party feature requires "
                    f"them, or replace the SDK with a privacy-respecting "
                    f"alternative."
                ),
                evidence={
                    "sdk": sdk_name,
                    "purpose": spec["purpose"],
                    "excessive_permissions": offending,
                    "all_permissions_count": len(permissions),
                },
            ))
        return findings

    def _detect_sdks(self) -> list[str]:
        ctx = self._context
        present: set[str] = set()

        # Path-based detection via decompiled tree
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            scanned = 0
            for path in ctx.decompiled_dir.rglob("*.java"):
                scanned += 1
                if scanned > _MAX_PROBES:
                    break
                rel = str(path.relative_to(ctx.decompiled_dir))
                for sdk, spec in _SDK_CATALOG.items():
                    if sdk in present:
                        continue
                    if any(m in rel for m in spec["path_markers"]):
                        present.add(sdk)
                if len(present) == len(_SDK_CATALOG):
                    break

        # Bytecode-based detection via Androguard classes (covers obfuscated APKs)
        if len(present) < len(_SDK_CATALOG):
            androguard = ctx.sources.get("androguard")
            if androguard is not None:
                try:
                    classes = androguard.get_all_classes()
                except Exception:  # noqa: BLE001
                    classes = []
                for cls in classes:
                    cls_str = str(cls)
                    for sdk, spec in _SDK_CATALOG.items():
                        if sdk in present:
                            continue
                        if any(m in cls_str for m in spec["path_markers"]):
                            present.add(sdk)
                    if len(present) == len(_SDK_CATALOG):
                        break

        return sorted(present)


__all__ = ["SDKPrivacyAuditorAgent"]
