"""P_001: Deep Link Hijacking Detection.

Inspects parsed manifest deep-link intent filters for three independent
hijack vectors:

1. Custom-scheme deep links without an ``android:host`` filter — any other
   app on the device can register the same scheme and silently intercept
   the URI.
2. ``https://`` / ``http://`` deep links lacking ``android:autoVerify=true``
   — App Links are not domain-bound, so on pre-Android 12 devices the
   resolver shows a chooser and a sibling app can claim the link.
3. The above gain a severity boost when the receiving activity reads
   sensitive parameters (``token``, ``code``, ``redirect``, ``state``,
   ``otp``) without validation — OAuth code interception is the canonical
   high-impact case.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

WEB_SCHEMES = {"http", "https"}
SENSITIVE_PARAMS = ("token", "code", "redirect", "state", "otp", "auth")
SENSITIVE_PARAM_PATTERN = re.compile(
    r'getQueryParameter\s*\(\s*"(' + "|".join(SENSITIVE_PARAMS) + r')"\s*\)',
    re.IGNORECASE,
)


class DeepLinkHijackAgent(BaseAgent):
    """Detect hijackable deep link intent filters."""

    AGENT_ID = "P_001"
    VULN_CLASS = "Deep Link Hijacking"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        manifest = self._context.manifest or {}
        return bool(manifest.get("deep_links"))

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest = self._context.manifest or {}
        deep_links: list[dict[str, Any]] = manifest.get("deep_links") or []

        for entry in deep_links:
            activity = entry.get("activity") or ""
            auto_verify = bool(entry.get("auto_verify"))
            data_elements: list[dict[str, str]] = (
                entry.get("data_elements") or []
            )

            schemes = sorted({
                d.get("scheme") for d in data_elements if d.get("scheme")
            })
            has_host = any(d.get("host") for d in data_elements)
            web_schemes = [s for s in schemes if s in WEB_SCHEMES]
            custom_schemes = [s for s in schemes if s not in WEB_SCHEMES]

            sensitive = self._activity_reads_sensitive_params(activity)

            if custom_schemes and not has_host:
                findings.append(self._build_finding(
                    activity=activity,
                    issue=(
                        f"Custom scheme(s) {custom_schemes} with no host "
                        "filter — any app can register the same scheme"
                    ),
                    schemes=custom_schemes,
                    vector="custom-scheme-no-host",
                    sensitive=sensitive,
                ))

            if web_schemes and not auto_verify:
                findings.append(self._build_finding(
                    activity=activity,
                    issue=(
                        f"App Link {web_schemes} without "
                        "android:autoVerify=true — Digital Asset Links not "
                        "enforced; resolver chooser exposed on pre-Android 12"
                    ),
                    schemes=web_schemes,
                    vector="applink-unverified",
                    sensitive=sensitive,
                ))

        return findings

    def _build_finding(
        self,
        *,
        activity: str,
        issue: str,
        schemes: list[str],
        vector: str,
        sensitive: bool,
    ) -> Finding:
        severity = Severity.HIGH if sensitive else Severity.MEDIUM
        confidence = 0.85 if sensitive else 0.70
        recommendation = (
            "Add an explicit android:host filter and validate received URIs "
            "in the handler. For https schemes, set android:autoVerify=true "
            "on the <intent-filter> and publish "
            "/.well-known/assetlinks.json on the domain to bind the link "
            "via Digital Asset Links."
        )
        if sensitive:
            recommendation += (
                " The activity reads auth-flow parameters (token/code/etc.) "
                "— treat all deep-link inputs as untrusted and validate "
                "redirect URIs against an allowlist before navigation."
            )

        return self._make_finding(
            vuln_class="Deep Link Hijacking",
            severity=severity,
            confidence=confidence,
            evidence={
                "activity": activity,
                "schemes": schemes,
                "vector": vector,
                "reads_sensitive_params": sensitive,
                "issue": issue,
            },
            recommendation=recommendation,
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector=(
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                if sensitive
                else "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
            ),
        )

    def _activity_reads_sensitive_params(self, activity: str) -> bool:
        decompiled = self._context.decompiled_dir
        if not decompiled or not activity:
            return False

        # Activity FQN → expected Java file suffix
        class_name = activity.rsplit(".", 1)[-1]
        if not class_name:
            return False

        for java_file in decompiled.rglob(f"{class_name}.java"):
            try:
                content = java_file.read_text(errors="replace")
            except OSError:
                continue
            if SENSITIVE_PARAM_PATTERN.search(content):
                return True
        return False
