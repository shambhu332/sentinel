"""D_064 — JobScheduler hijacker (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_JOB_BUILDER_RE = re.compile(
    r"JobInfo\.Builder|JobScheduler\s*\.\s*schedule"
    r"|extends\s+JobService"
)
_EXTRAS_READ_RE = re.compile(
    r"params\.getExtras\s*\(|getPersistableExtras\s*\("
)
_TRUST_USE_RE = re.compile(
    r"params\.getExtras\(\)\.getString\s*\(.*?(role|user|action|cmd|target)",
    re.IGNORECASE,
)


class JobHijackerAgent(BaseAgent):
    AGENT_ID = "D_064"
    VULN_CLASS = "JobScheduler Extras Hijack (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
            and self._context.manifest
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        if root is None:
            return []
        # Find exported JobServices via the manifest
        services = (self._context.manifest or {}).get("services", []) or []
        exported_job_services = []
        for s in services:
            if not isinstance(s, dict):
                continue
            if s.get("exported") is True:
                exported_job_services.append(s.get("name", ""))
        # Find JobService implementations in code
        job_files: set[str] = set()
        trust_routes: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _JOB_BUILDER_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            job_files.add(rel)
            if _TRUST_USE_RE.search(text):
                trust_routes.add(rel)
        if not job_files:
            return []
        severity = Severity.HIGH if (trust_routes and exported_job_services) else Severity.MEDIUM
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"{len(job_files)} JobScheduler usage site(s); "
                f"{len(exported_job_services)} exported JobService(s); "
                f"{len(trust_routes)} route(s) trust extras for privileged "
                "decisions. The Frida hook will schedule the job with "
                "attacker-controlled PersistableBundle extras via "
                "JobScheduler.schedule from a controlled context. Treat "
                "every getPersistableExtras() value as untrusted."
            ),
            evidence={
                "job_files": sorted(job_files)[:10],
                "exported_job_services": exported_job_services[:5],
                "extras_trust_routes": sorted(trust_routes)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "hijack_extras": {
                        "role": "admin",
                        "user": "0",
                        "action": "wipe",
                        "target": "all",
                        "cmd": "exec",
                    },
                    "exported_job_services": exported_job_services,
                    "safety_budget": {
                        "max_actions_total": 10,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["JobHijackerAgent"]
