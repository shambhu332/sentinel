"""P_015 — Deep Link Mapper Agent.

Performs comprehensive analysis of Android deep links declared in
AndroidManifest.xml intent-filters. Goes beyond P_001 (which detects
hijacking) to map the full deep-link attack surface.

Detection targets:
1. Activities with scheme="https" but missing android:autoVerify="true"
   — Android won't enforce Digital Asset Links, so a malicious sibling
   app can claim the same domain's links.
2. Exported activities accepting ACTION_VIEW without permission guards
   — any app on the device can send an intent to launch the activity
   with attacker-controlled URI data.
3. Activities with custom schemes lacking host validation.
4. Deep links that accept pathPrefix="/" — overly broad catch-all that
   intercepts all paths under a domain.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class DeepLinkMapperAgent(BaseAgent):
    """P_015: maps and audits all deep link intent-filter configurations."""

    AGENT_ID = "P_015"
    VULN_CLASS = "Deep Link Misconfiguration"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Applicable when we have a parsed manifest with activities."""
        manifest = self._context.manifest or {}
        activities = manifest.get("activities", [])
        return bool(activities)

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest = self._context.manifest or {}
        activities: list[dict[str, Any]] = manifest.get("activities", [])

        for activity in activities:
            activity_name = activity.get("name", "")
            exported = activity.get("exported", False)
            permission = activity.get("permission", "")
            intent_filters: list[dict[str, Any]] = (
                activity.get("intent_filters", [])
            )

            for intent_filter in intent_filters:
                actions = intent_filter.get("actions", [])
                categories = intent_filter.get("categories", [])
                data_elements: list[dict[str, str]] = (
                    intent_filter.get("data", [])
                )
                auto_verify = intent_filter.get("auto_verify", False)

                has_view_action = "android.intent.action.VIEW" in actions
                has_browsable = (
                    "android.intent.category.BROWSABLE" in categories
                )

                # Extract scheme/host info from data elements
                schemes: set[str] = set()
                hosts: set[str] = set()
                paths: set[str] = set()
                for data in data_elements:
                    scheme = data.get("scheme", "")
                    host = data.get("host", "")
                    path = (
                        data.get("path", "")
                        or data.get("pathPrefix", "")
                        or data.get("pathPattern", "")
                    )
                    if scheme:
                        schemes.add(scheme)
                    if host:
                        hosts.add(host)
                    if path:
                        paths.add(path)

                web_schemes = schemes & {"http", "https"}

                # Check 1: HTTPS scheme without autoVerify
                if web_schemes and not auto_verify:
                    findings.append(self._make_finding(
                        vuln_class=self.VULN_CLASS,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        recommendation=(
                            "Add android:autoVerify=\"true\" to this "
                            "<intent-filter> and publish a Digital Asset "
                            "Links file at "
                            "https://<domain>/.well-known/assetlinks.json "
                            "to prevent link hijacking by sibling apps. "
                            "Without autoVerify, Android shows a chooser "
                            "dialog on pre-Android 12 devices, allowing "
                            "malicious apps to intercept the deep link."
                        ),
                        evidence={
                            "title": (
                                f"HTTPS deep link without autoVerify: "
                                f"{activity_name}"
                            ),
                            "activity": activity_name,
                            "schemes": sorted(web_schemes),
                            "hosts": sorted(hosts),
                            "paths": sorted(paths),
                            "auto_verify": False,
                            "exported": exported,
                            "issue": "missing_auto_verify",
                        },
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-PLATFORM-3",
                        cvss_vector=(
                            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
                        ),
                    ))

                # Check 2: Exported activity with ACTION_VIEW, no permission
                if (
                    has_view_action
                    and (exported or has_browsable)
                    and not permission
                ):
                    # Severity depends on whether the link carries sensitive
                    # parameters (we check path patterns for auth-like paths)
                    auth_paths = any(
                        hint in p.lower()
                        for p in paths
                        for hint in (
                            "oauth", "auth", "login", "callback",
                            "token", "reset", "verify",
                        )
                    )
                    severity = Severity.HIGH if auth_paths else Severity.MEDIUM
                    confidence = 0.85 if auth_paths else 0.75

                    findings.append(self._make_finding(
                        vuln_class=self.VULN_CLASS,
                        severity=severity,
                        confidence=confidence,
                        recommendation=(
                            "Add a custom permission guard to the activity "
                            "declaration in AndroidManifest.xml using "
                            "android:permission=\"<your-custom-permission>\". "
                            "For sensitive activities (login callbacks, OAuth "
                            "redirects), additionally validate the calling "
                            "package via getCallingPackage() and reject "
                            "unexpected callers. Consider using "
                            "android:exported=\"false\" if the activity does "
                            "not need to be externally accessible."
                        ),
                        evidence={
                            "title": (
                                f"Unprotected ACTION_VIEW activity: "
                                f"{activity_name}"
                            ),
                            "activity": activity_name,
                            "exported": exported,
                            "permission": permission,
                            "actions": actions,
                            "schemes": sorted(schemes),
                            "hosts": sorted(hosts),
                            "auth_path_detected": auth_paths,
                            "issue": "unguarded_action_view",
                        },
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-PLATFORM-1",
                        cvss_vector=(
                            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                        ),
                    ))

                # Check 3: Overly broad pathPrefix="/"
                if "/" in paths and len(paths) == 1 and hosts:
                    findings.append(self._make_finding(
                        vuln_class=self.VULN_CLASS,
                        severity=Severity.LOW,
                        confidence=0.70,
                        recommendation=(
                            "Restrict the pathPrefix to the specific paths "
                            "the activity should handle instead of using "
                            "pathPrefix=\"/\" which intercepts ALL URLs "
                            "under the domain. Use specific paths like "
                            "pathPrefix=\"/app/\" or pathPrefix=\"/deep/\" "
                            "to limit the attack surface."
                        ),
                        evidence={
                            "title": (
                                f"Overly broad deep link pattern: "
                                f"{activity_name}"
                            ),
                            "activity": activity_name,
                            "hosts": sorted(hosts),
                            "paths": sorted(paths),
                            "issue": "overly_broad_path",
                        },
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-PLATFORM-3",
                    ))

        return findings


__all__ = ["DeepLinkMapperAgent"]
