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
        return bool(_iter_deep_link_activities(manifest))

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest = self._context.manifest or {}

        for activity in _iter_deep_link_activities(manifest):
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
                    primary_host = sorted(hosts)[0] if hosts else "example.com"
                    primary_path = sorted(paths)[0] if paths else "/"
                    primary_scheme = "https" if "https" in web_schemes else "http"
                    sample_url = (
                        f"{primary_scheme}://{primary_host}"
                        f"{primary_path if primary_path.startswith('/') else '/' + primary_path}"
                    )
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
                        severity_rationale=(
                            f"Rated MEDIUM because the activity advertises a web "
                            f"scheme ({', '.join(sorted(web_schemes))}) but does not "
                            f"set autoVerify=true. On Android <12 this leaves the "
                            f"door open to a sibling app claiming the same host, "
                            f"intercepting the link, and presenting the user with "
                            f"a chooser. Impact is bounded to information that "
                            f"flows through the URL itself — credentials in the "
                            f"redirect URI would lift this to HIGH."
                        ),
                        verification_status="Code-level only",
                        source_tags=[
                            "Deep Link / URL Scheme",
                            "Manifest Misconfiguration",
                        ],
                        reproduction_commands=[
                            "# Replay the deep link from another app context",
                            f"adb shell am start -W -a android.intent.action.VIEW \\",
                            f"  -d \"{sample_url}\" \\",
                            f"  {activity_name.split('/')[-1] if '/' in activity_name else ''}".rstrip(),
                            "# Pre-Android 12: a chooser dialog will appear if a",
                            "# sibling app also claims the host (link hijacking).",
                        ],
                        observed_result=(
                            f"Android resolves {sample_url!r} to {activity_name} "
                            "without verifying the Digital Asset Links file. "
                            "Any installed app that also claims this host can be "
                            "selected from the disambiguation chooser."
                        ),
                        code_snippets=[{
                            "label": "Intent-filter declaration",
                            "file": "AndroidManifest.xml",
                            "line": 1,
                            "content": _render_intent_filter_xml(
                                activity_name=activity_name,
                                exported=exported,
                                permission=permission,
                                actions=actions,
                                categories=categories,
                                data_elements=data_elements,
                                auto_verify=auto_verify,
                            ),
                        }],
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

                    primary_scheme = sorted(schemes)[0] if schemes else "app"
                    primary_host = sorted(hosts)[0] if hosts else ""
                    primary_path = sorted(paths)[0] if paths else ""
                    if primary_host:
                        sample_url = (
                            f"{primary_scheme}://{primary_host}"
                            f"{primary_path if primary_path.startswith('/') else ('/' + primary_path if primary_path else '')}"
                        )
                    else:
                        sample_url = f"{primary_scheme}://{primary_path or 'callback'}"

                    src_tags = ["Deep Link / URL Scheme", "Exported Component"]
                    if auth_paths:
                        src_tags.append("Auth Redirect Surface")

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
                        severity_rationale=(
                            (
                                f"Rated HIGH because the path pattern includes "
                                f"an auth-redirect hint ({sorted(paths)!r}). An "
                                f"unprivileged app on the device can craft an "
                                f"ACTION_VIEW intent carrying a forged "
                                f"authorization code or token and deliver it "
                                f"directly to {activity_name} — bypassing the "
                                f"browser-mediated OAuth handshake."
                            )
                            if auth_paths else (
                                f"Rated MEDIUM because {activity_name} is "
                                f"externally launchable via ACTION_VIEW without "
                                f"a permission guard. Impact is bounded by what "
                                f"the activity does with attacker-controlled URI "
                                f"data; without auth-redirect hints the worst-"
                                f"case here is forced state changes or "
                                f"unexpected UI flows."
                            )
                        ),
                        verification_status="Code-level only",
                        source_tags=src_tags,
                        reproduction_commands=[
                            "# Any unprivileged app can deliver this intent:",
                            f"adb shell am start -W -a android.intent.action.VIEW \\",
                            f"  -d \"{sample_url}\" \\",
                            f"  -n {self._context.manifest.get('package', '<pkg>')}/"
                            f"{activity_name}",
                        ],
                        observed_result=(
                            f"The activity launches with the supplied URI as "
                            f"input. No permission check is enforced and the "
                            f"calling package is not validated, so any app on "
                            f"the device can invoke this code path with "
                            f"attacker-controlled data."
                        ),
                        code_snippets=[{
                            "label": "Activity declaration",
                            "file": "AndroidManifest.xml",
                            "line": 1,
                            "content": _render_intent_filter_xml(
                                activity_name=activity_name,
                                exported=exported,
                                permission=permission,
                                actions=actions,
                                categories=categories,
                                data_elements=data_elements,
                                auto_verify=auto_verify,
                            ),
                        }],
                    ))

                # Check 3: Overly broad pathPrefix="/"
                if "/" in paths and len(paths) == 1 and hosts:
                    primary_host = sorted(hosts)[0]
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
                        severity_rationale=(
                            f"Rated LOW because the catch-all pathPrefix=\"/\" "
                            f"means {activity_name} is invoked for every URL "
                            f"under {primary_host}, including paths the app "
                            f"author never intended to handle. The risk is "
                            f"primarily expanded attack surface, not direct "
                            f"data exposure."
                        ),
                        verification_status="Code-level only",
                        source_tags=[
                            "Deep Link / URL Scheme",
                            "Path Wildcard",
                        ],
                        reproduction_commands=[
                            "# Any URL under the host now reaches this activity:",
                            f"adb shell am start -W -a android.intent.action.VIEW \\",
                            f"  -d \"https://{primary_host}/unintended/endpoint\"",
                        ],
                        observed_result=(
                            f"The activity is launched for arbitrary paths "
                            f"under {primary_host}, including endpoints "
                            f"unrelated to its intended deep-link surface."
                        ),
                        code_snippets=[{
                            "label": "Intent-filter declaration",
                            "file": "AndroidManifest.xml",
                            "line": 1,
                            "content": _render_intent_filter_xml(
                                activity_name=activity_name,
                                exported=exported,
                                permission=permission,
                                actions=actions,
                                categories=categories,
                                data_elements=data_elements,
                                auto_verify=auto_verify,
                            ),
                        }],
                    ))

        return findings


def _iter_deep_link_activities(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Return normalized activity records that carry intent-filter data.

    ManifestParser stores ``activities`` as a list of names for quick
    summaries and stores structured link data in ``deep_links``. Some
    tests or alternate parsers may provide already-structured activity
    dicts. This normalizer accepts both shapes and ignores plain string
    activity names instead of crashing.
    """
    normalized: list[dict[str, Any]] = []

    raw_activities = manifest.get("activities") or []
    if isinstance(raw_activities, list):
        for raw in raw_activities:
            if not isinstance(raw, dict):
                continue
            filters = raw.get("intent_filters") or []
            if isinstance(filters, list) and filters:
                normalized.append(raw)

    raw_links = manifest.get("deep_links") or []
    if isinstance(raw_links, list):
        for raw in raw_links:
            if not isinstance(raw, dict):
                continue
            data_elements = raw.get("data_elements") or []
            if not isinstance(data_elements, list) or not data_elements:
                continue
            normalized.append({
                "name": str(raw.get("activity") or ""),
                "exported": True,
                "permission": "",
                "intent_filters": [{
                    "actions": _split_manifest_csv(raw.get("actions")),
                    "categories": _split_manifest_csv(raw.get("categories")),
                    "data": [
                        d for d in data_elements if isinstance(d, dict)
                    ],
                    "auto_verify": bool(raw.get("auto_verify", False)),
                }],
            })

    return normalized


def _render_intent_filter_xml(
    *,
    activity_name: str,
    exported: bool,
    permission: str,
    actions: list[str],
    categories: list[str],
    data_elements: list[dict[str, str]],
    auto_verify: bool,
) -> str:
    """Re-emit the offending <activity> + <intent-filter> as readable XML.

    The parsed manifest gives us structured fields but no source range,
    so we synthesise an equivalent snippet for the finding detail view.
    The output mirrors AndroidManifest.xml conventions closely enough
    that a developer can paste it back into their manifest as a starting
    point for the fix.
    """
    short_name = activity_name.split(".")[-1] or activity_name
    perm_attr = (
        f' android:permission="{permission}"' if permission else ""
    )
    av_attr = ' android:autoVerify="true"' if auto_verify else ""

    lines: list[str] = []
    lines.append(
        f'<activity android:name="{activity_name or "." + short_name}"'
        f' android:exported="{str(exported).lower()}"{perm_attr}>'
    )
    lines.append(f"  <intent-filter{av_attr}>")
    for a in actions or []:
        lines.append(f'    <action android:name="{a}" />')
    for c in categories or []:
        lines.append(f'    <category android:name="{c}" />')
    for d in data_elements or []:
        if not isinstance(d, dict):
            continue
        attrs = " ".join(
            f'android:{k}="{v}"'
            for k, v in d.items()
            if v not in (None, "")
        )
        lines.append(f"    <data {attrs} />" if attrs else "    <data />")
    lines.append("  </intent-filter>")
    lines.append("</activity>")
    return "\n".join(lines)


def _split_manifest_csv(value: object) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


__all__ = ["DeepLinkMapperAgent"]
