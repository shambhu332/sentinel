"""D_062 — Binder transaction fuzzer (Dynamic Testing Target).

Strict safety: this is the most device-bricking-prone fuzzer in the
catalog. Hard-capped at 10 transactions, 1 per second, 30s wall-clock,
2 consecutive crashes trips the breaker.
"""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_AIDL_RE = re.compile(r"\bextends\s+(android\.os\.)?Binder\b|\bIInterface\b")
_TRANS_RE = re.compile(r"\bonTransact\s*\(\s*int\s+code\s*,\s*Parcel")


class BinderBombAgent(BaseAgent):
    AGENT_ID = "D_062"
    VULN_CLASS = "Binder Transaction DoS Probe (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        binder_files: set[str] = set()
        ontransact_files: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _AIDL_RE.search(text):
                rel = str(path.relative_to(root))
                binder_files.add(rel)
                if _TRANS_RE.search(text):
                    ontransact_files.add(rel)
        if not binder_files:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.MEDIUM,
            confidence=0.60,
            recommendation=(
                f"{len(binder_files)} Binder / IInterface implementation(s) "
                f"detected; {len(ontransact_files)} expose onTransact. "
                "The Frida hook will fuzz with OVERSIZED Parcels (up to "
                "1MB capped) and report any kernel panic or "
                "DeadObjectException — but only 10 transactions total, "
                "1 per second, with hard breaker. Validate every parcel "
                "size + transaction code in onTransact; reject "
                "out-of-range codes explicitly."
            ),
            evidence={
                "binder_files": sorted(binder_files)[:10],
                "ontransact_files": sorted(ontransact_files)[:10],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_target": "android.os.Binder.onTransact",
                    "fuzz_sizes_bytes": [1024, 10240, 102400, 1048576],
                    "out_of_range_codes": [-1, 0xFFFFFF, 9999999],
                    "safety_budget": {
                        "max_actions_total": 10,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["BinderBombAgent"]
