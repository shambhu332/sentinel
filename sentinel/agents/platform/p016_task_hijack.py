"""P_016 — Recent-task / StrandHogg-style task hijack.

A malicious app that declares a matching ``taskAffinity`` can be
placed into the victim app's task stack on launch. When the user
brings the victim app to the foreground, Android may actually surface
the attacker's activity — a classic phishing / overlay attack
(StrandHogg, StrandHogg 2.0, task-affinity reparenting).

Detection (manifest-only — no source needed):

* ``taskAffinity`` set to a string other than the app's own package
  AND the activity is ``exported=true``.
* ``allowTaskReparenting="true"`` on any activity that handles
  sensitive intent filters (LOGIN, VIEW deep links).
* ``launchMode="singleTask"`` / ``"singleInstance"`` AND
  ``exported=true`` AND no required permission.
"""
from __future__ import annotations

from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity


_HIJACK_LAUNCH_MODES = {"singleTask", "singleInstance"}


class TaskHijackAgent(BaseAgent):
    AGENT_ID = "P_016"
    VULN_CLASS = "Recent-Task Hijack (StrandHogg)"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        return bool((self._context.manifest or {}).get("activities"))

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        package = manifest.get("package", "")
        findings: list[Finding] = []

        for activity in manifest.get("activities", []) or []:
            if not isinstance(activity, dict):
                continue
            name = activity.get("name", "?")
            exported = bool(activity.get("exported"))
            permission = activity.get("permission")
            task_affinity = activity.get("taskAffinity")
            launch_mode = activity.get("launchMode") or "standard"
            reparent = bool(activity.get("allowTaskReparenting"))

            issues: list[str] = []
            if (
                task_affinity is not None
                and task_affinity != ""
                and task_affinity != package
                and exported
            ):
                issues.append(
                    f"taskAffinity={task_affinity!r} != package {package!r}",
                )
            if reparent:
                issues.append("allowTaskReparenting=true")
            if (
                launch_mode in _HIJACK_LAUNCH_MODES
                and exported
                and not permission
            ):
                issues.append(
                    f"launchMode={launch_mode!r} exported with no permission",
                )

            if not issues:
                continue

            severity = (
                Severity.HIGH if launch_mode in _HIJACK_LAUNCH_MODES
                else Severity.MEDIUM
            )
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.72,
                recommendation=(
                    f"Activity `{name}` exposes a task-hijack surface: "
                    f"{'; '.join(issues)}. Mitigate by setting "
                    "`android:taskAffinity=\"\"` on every exported "
                    "activity, removing `allowTaskReparenting`, and "
                    "avoiding `singleTask`/`singleInstance` for "
                    "externally reachable entry points. On Android 11+ "
                    "set `android:launchMode=\"singleInstancePerTask\"` "
                    "only where genuinely required."
                ),
                evidence={
                    "activity": name,
                    "exported": exported,
                    "launch_mode": launch_mode,
                    "task_affinity": task_affinity,
                    "allow_task_reparenting": reparent,
                    "issues": issues,
                },
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-1",
            ))
        return findings
