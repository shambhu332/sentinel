"""D_074 — Deep-link scheme-confusion probe target.

Static half of the hybrid DAST flow:

* enumerate manifest activities that accept VIEW deep links;
* collect http/https/custom schemes and declared hosts;
* emit a Frida payload that probes how ``android.net.Uri.parse``
  interprets confusion payloads like
  ``scheme://evil.com@trusted.com/path``.

The runtime hook does not fuzz arbitrary URLs. It uses one bounded,
reviewable confusion shape per scheme/host pair and reports host vs
userInfo parsing back to Python.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_TARGETS = 100
_DEFAULT_TRUSTED_HOST = "trusted.com"


class SchemeConfuserAgent(BaseAgent):
    """D_074: flag deep-link activities for Uri scheme-confusion probing."""

    AGENT_ID = "D_074"
    VULN_CLASS = "Deep Link Scheme Confusion Probe"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.manifest)

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        package = manifest.get("package", "")
        targets = _collect_targets(manifest)
        findings: list[Finding] = []
        for target in targets[:_MAX_TARGETS]:
            payload = _build_payload(package, target)
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.72,
                recommendation=(
                    f"Activity `{target['activity']}` accepts deep-link "
                    f"scheme(s) {target['schemes']}. The Frida runtime "
                    "probe will parse confusion URLs of the form "
                    "`scheme://evil.com@trusted.com/path` and report "
                    "whether business logic may be checking the authority "
                    "string instead of the parsed host/userInfo fields. "
                    "Fix by validating Uri.getScheme() and Uri.getHost() "
                    "against exact allow-lists, rejecting non-empty "
                    "Uri.getUserInfo(), and avoiding raw string "
                    "contains/endsWith host checks."
                ),
                evidence={
                    "activity": target["activity"],
                    "schemes": target["schemes"],
                    "hosts": target["hosts"],
                    "exported": target["exported"],
                    "dynamic_target": True,
                    "frida_payload": payload,
                },
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-3",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            ))
        return findings


def _collect_targets(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for activity in manifest.get("activities", []) or []:
        if not isinstance(activity, dict):
            continue
        schemes: set[str] = set()
        hosts: set[str] = set()
        handles_view = False
        for intent_filter in activity.get("intent_filters", []) or []:
            if not isinstance(intent_filter, dict):
                continue
            actions = intent_filter.get("actions") or []
            action = intent_filter.get("action")
            if (
                action == "android.intent.action.VIEW"
                or "android.intent.action.VIEW" in actions
            ):
                handles_view = True
            _add_strings(schemes, intent_filter.get("schemes"))
            _add_strings(hosts, intent_filter.get("hosts"))
            if isinstance(intent_filter.get("scheme"), str):
                schemes.add(intent_filter["scheme"])
            if isinstance(intent_filter.get("host"), str):
                hosts.add(intent_filter["host"])
        if handles_view and schemes:
            targets.append({
                "activity": activity.get("name", ""),
                "schemes": sorted(schemes),
                "hosts": sorted(hosts),
                "exported": bool(activity.get("exported")),
            })
    return targets


def _add_strings(out: set[str], value: Any) -> None:
    if isinstance(value, str):
        out.add(value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                out.add(item)


def _build_payload(package: str, target: dict[str, Any]) -> dict[str, Any]:
    hosts = target["hosts"] or [_DEFAULT_TRUSTED_HOST]
    probes = []
    for scheme in target["schemes"]:
        for host in hosts[:3]:
            probes.append(f"{scheme}://evil.com@{host}/sentinel-probe")
    return {
        "type": "scheme_probe",
        "package": package,
        "activity": target["activity"],
        "schemes": target["schemes"],
        "hosts": target["hosts"],
        "confusion_payloads": probes[:12],
        "safety_budget": {
            "max_actions_total": 12,
            "max_actions_per_sec": 4,
            "wall_clock_budget_s": 30,
            "max_consecutive_crashes": 3,
        },
    }


__all__ = ["SchemeConfuserAgent"]
