"""P_001 — Deep Link Hijacking Agent.

Detects Android applications with deep links (custom URI schemes or
App Links) that are vulnerable to hijacking by malicious apps. The
classic attack: app A registers `myapp://` as a custom URI scheme.
Malware app B also registers `myapp://`. When the user clicks a link,
Android shows a chooser, and many users tap the malicious app — which
then receives whatever sensitive data was meant for app A (auth
tokens in OAuth callbacks, password reset codes, payment confirmations).

Why this matters: deep link hijacking has caused real account takeover
incidents at Twitter, Instagram, Slack, and dozens of fintech apps.
The bounty range is $1,000-$5,000 typical, $10,000+ for confirmed
account takeover. The fix (autoVerify + Digital Asset Links) is well
understood and required by Android 12+ for App Links.

Detection pipeline:
1. Read the manifest's deep_links list (already extracted by manifest parser)
2. For each intent-filter, check:
   - Is it a custom scheme (not http/https)? → Critical hijack risk
   - If http/https, does it have android:autoVerify="true"? → Lower risk
   - If autoVerify, does it have a corresponding assetlinks.json? (warned)
3. Severity scales: Critical for OAuth-style custom schemes,
   Medium for autoVerify=false, Low for missing assetlinks
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Custom URI schemes commonly used for OAuth callbacks and deep auth flows.
# These are highest-risk hijack targets because they carry authentication
# data in the URL.
_AUTH_SCHEME_HINTS = (
    "oauth", "auth", "login", "callback", "sso", "signin",
    "reset", "verify", "confirm", "magic",
)


class DeepLinkHijackAgent(BaseAgent):
    """P_001: detects deep link hijack vulnerabilities."""

    AGENT_ID = "P_001"
    VULN_CLASS = "Deep Link Hijacking"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if not ctx.manifest:
            logger.info("[P_001] No manifest — skipping")
            return False
        deep_links = ctx.manifest.get("deep_links", [])
        if not deep_links:
            logger.info("[P_001] No deep links declared — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        manifest = ctx.manifest or {}
        deep_links: list[dict[str, Any]] = manifest.get("deep_links", [])
        package = manifest.get("package", "?")

        if not deep_links:
            return []

        # Bucket the deep links by risk level
        custom_scheme_links: list[dict[str, Any]] = []
        http_no_autoverify: list[dict[str, Any]] = []
        http_autoverify: list[dict[str, Any]] = []

        for dl in deep_links:
            scheme = (dl.get("scheme") or "").lower()
            host = dl.get("host", "")
            auto_verify = dl.get("auto_verify", False)
            activity = dl.get("activity", "")

            entry = {
                "scheme": scheme,
                "host": host,
                "activity": activity,
                "auto_verify": auto_verify,
                "path_pattern": dl.get("path_pattern") or dl.get("path") or "",
            }

            if scheme in ("http", "https"):
                if auto_verify:
                    http_autoverify.append(entry)
                else:
                    http_no_autoverify.append(entry)
            elif scheme:
                # Custom scheme — always hijackable on Android
                custom_scheme_links.append(entry)

        findings: list[Finding] = []

        # Bucket 1: Custom schemes (highest risk)
        if custom_scheme_links:
            # Severity: Critical if any scheme has auth-related hints,
            # otherwise High
            has_auth_scheme = any(
                any(hint in entry["scheme"] or hint in entry["host"]
                    for hint in _AUTH_SCHEME_HINTS)
                for entry in custom_scheme_links
            )

            severity = Severity.CRITICAL if has_auth_scheme else Severity.HIGH

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.85,
                recommendation=self._build_custom_scheme_recommendation(),
                evidence={
                    "title": "Hijackable Custom URI Scheme Deep Links",
                    "summary": (
                        f"Application registers {len(custom_scheme_links)} "
                        "deep link(s) using custom URI scheme(s). Custom schemes "
                        "are NOT exclusive — any other app can register the "
                        "same scheme and intercept incoming intents. "
                        + ("AUTH-RELATED SCHEME DETECTED — likely carries "
                           "OAuth tokens, password reset codes, or magic links."
                           if has_auth_scheme else "")
                    ),
                    "package": package,
                    "auth_scheme_detected": has_auth_scheme,
                    "deep_links": custom_scheme_links[:20],
                    "vector": (
                        "Build a malicious app declaring the same scheme:\n"
                        "  <intent-filter>\n"
                        f"    <data android:scheme=\"{custom_scheme_links[0]['scheme']}\" />\n"
                        "    <action android:name=\"android.intent.action.VIEW\" />\n"
                        "    <category android:name=\"android.intent.category.DEFAULT\" />\n"
                        "    <category android:name=\"android.intent.category.BROWSABLE\" />\n"
                        "  </intent-filter>\n"
                        "Install the malicious app on a victim device. When a "
                        "deep link is clicked, Android shows a chooser. If the "
                        "victim taps the malicious app (or it has higher "
                        "priority via android:priority), the malicious app "
                        "receives the URL — including OAuth codes, reset "
                        "tokens, or whatever sensitive data was in the URL."
                    ),
                },
            ))

        # Bucket 2: HTTP/HTTPS deep links without autoVerify (Medium)
        if http_no_autoverify:
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.75,
                recommendation=self._build_autoverify_recommendation(),
                evidence={
                    "title": "App Links Without autoVerify",
                    "summary": (
                        f"Application has {len(http_no_autoverify)} HTTP/HTTPS "
                        "deep link(s) declared as App Links but without "
                        "android:autoVerify=\"true\". Without autoVerify, "
                        "Android shows a chooser dialog and other apps can "
                        "claim the same domain, leading to user-confusion "
                        "hijacking."
                    ),
                    "package": package,
                    "deep_links": http_no_autoverify[:20],
                    "vector": (
                        "Same hijack pattern as custom schemes, but the attack "
                        "requires the user to tap a malicious app in the "
                        "chooser dialog rather than the legitimate one. "
                        "Effective when the malicious app has a similar name "
                        "or icon."
                    ),
                },
            ))

        # Bucket 3: autoVerify present but assetlinks.json verification
        # is the developer's responsibility — we can flag this as Low
        # informational so the developer is aware they need to host the
        # JSON file at /.well-known/assetlinks.json.
        if http_autoverify:
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.LOW,
                confidence=0.50,
                recommendation=(
                    "App Links are using android:autoVerify=\"true\" — verify "
                    "that /.well-known/assetlinks.json is correctly hosted on "
                    "every declared host with the app's signing certificate "
                    "SHA-256 fingerprint. Without the assetlinks.json file, "
                    "Android downgrades the deep link to a regular intent and "
                    "shows the chooser, defeating autoVerify's protection. "
                    "Test with: adb shell pm get-app-links " + package
                ),
                evidence={
                    "title": "App Links with autoVerify (verify assetlinks.json)",
                    "summary": (
                        "Application uses autoVerify for App Links — this is "
                        "the correct configuration. SENTINEL cannot statically "
                        "verify that the /.well-known/assetlinks.json file is "
                        "actually hosted. This finding is informational; "
                        "manual verification is needed."
                    ),
                    "package": package,
                    "deep_links": http_autoverify[:20],
                },
            ))

        return findings

    @staticmethod
    def _build_custom_scheme_recommendation() -> str:
        return (
            "Replace custom URI schemes with App Links (verified HTTPS deep "
            "links). App Links are exclusive to your app once you host "
            "/.well-known/assetlinks.json on your domain with your signing "
            "certificate's SHA-256 fingerprint. Custom schemes (myapp://) "
            "cannot be made exclusive on Android — any app can register the "
            "same scheme.\n"
            "Migration steps:\n"
            "1. Replace <data android:scheme=\"myapp\" /> with "
            "<data android:scheme=\"https\" android:host=\"app.example.com\" />\n"
            "2. Add android:autoVerify=\"true\" to the intent-filter.\n"
            "3. Generate assetlinks.json: keytool -list -v -keystore "
            "release.keystore  →  copy SHA-256.\n"
            "4. Host at https://app.example.com/.well-known/assetlinks.json "
            "with content type application/json (HTTPS REQUIRED).\n"
            "5. For OAuth callbacks specifically, use the AppAuth-Android "
            "library which handles the redirect URI security properly."
        )

    @staticmethod
    def _build_autoverify_recommendation() -> str:
        return (
            "Add android:autoVerify=\"true\" to every HTTP/HTTPS intent-filter "
            "in your manifest. This is required by Android 12+ for verified "
            "App Links and prevents other apps from claiming your domain. "
            "After adding the attribute, host /.well-known/assetlinks.json on "
            "each host with your release-build signing certificate's SHA-256 "
            "fingerprint. Verify using: adb shell pm get-app-links <package>. "
            "The output should show 'verified=true' for each domain."
        )
