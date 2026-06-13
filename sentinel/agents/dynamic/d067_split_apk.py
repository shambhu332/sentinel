"""D_067 — SplitInstallManager malicious-split (Dynamic Testing Target)."""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_SPLIT_INSTALL_RE = re.compile(
    r"\bSplitInstallManager\b|\bSplitInstallRequest\b"
    r"|\bcom\.google\.android\.play\.core\.splitinstall\b"
)
_VERIFICATION_RE = re.compile(
    r"PackageManager\.getInstaller|verifySplit|checkSignature"
    r"|PackageManager\.SIGNATURE_MATCH"
)


class SplitApkAgent(BaseAgent):
    AGENT_ID = "D_067"
    VULN_CLASS = "Split APK Hijack (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        users: set[str] = set()
        verified: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _SPLIT_INSTALL_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            users.add(rel)
            if _VERIFICATION_RE.search(text):
                verified.add(rel)
        if not users:
            return []
        unverified = sorted(users - verified)
        severity = Severity.HIGH if unverified else Severity.LOW
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"{len(users)} SplitInstallManager call site(s); "
                f"{len(verified)} verify split signature, "
                f"{len(unverified)} do not. The Frida hook will simulate "
                "a malicious split-APK install via SplitInstallManager "
                "and observe whether the unverified code path executes. "
                "Always verify the split package signature against the "
                "host APK signature before invoking any new code."
            ),
            evidence={
                "split_install_files": sorted(users)[:10],
                "verified_files": sorted(verified)[:5],
                "unverified_files": unverified[:10],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_target":
                        "com.google.android.play.core.splitinstall."
                        "SplitInstallManager.startInstall",
                    "simulate_malicious_split": True,
                    "safety_budget": {
                        "max_actions_total": 3,
                        "max_actions_per_sec": 0.3,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 1,
                    },
                },
            },
        )]


__all__ = ["SplitApkAgent"]
