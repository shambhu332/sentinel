"""N_001 — Cleartext Traffic Agent.

Detects when an Android application is configured to allow unencrypted HTTP
traffic, either through manifest flags or through hardcoded http:// URLs in
decompiled code.

Why this matters: HTTP traffic on a user's network can be intercepted, read,
and modified by an attacker on the same WiFi network. Modern Android (28+)
disables cleartext traffic by default; apps that explicitly re-enable it
are accepting a real risk. Bug bounty programs typically pay $200-$1000
for confirmed cleartext traffic findings on production apps that handle
sensitive data.

Detection pipeline:
1. Check manifest for android:usesCleartextTraffic="true"
2. Scan decompiled Java for hardcoded http:// URLs (excluding localhost,
   schema definitions, namespace URIs, and well-known development hosts)
3. Severity scales: Critical if both signals present, High if manifest only,
   Medium if code-only with sensitive-looking endpoints
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Match http:// URLs but exclude common false positives:
#   - XML namespace URIs (xmlns="http://schemas.android.com/...")
#   - localhost / 127.0.0.1 / 10.0.2.2 (Android emulator host)
#   - schema definition references in XML/manifests
_HTTP_URL_RE = re.compile(
    r'http://(?!'
    r'(?:'
    r'localhost|'
    r'127\.0\.0\.1|'
    r'10\.0\.2\.2|'
    r'schemas\.android\.com|'
    r'xmlns\.|'
    r'www\.w3\.org|'
    r'java\.sun\.com|'
    r'apache\.org|'
    r'jcp\.org|'
    r'ns\.adobe\.com'
    r')'
    r')'
    r'[a-zA-Z0-9./_\-:?=&%~#]+',
    re.IGNORECASE,
)

# Files that we shouldn't bother scanning for HTTP URLs (high false positive)
_SKIP_PATTERNS = {
    "BuildConfig.java",
    "R.java",
}

# Cap files scanned for performance — large APKs can have 5000+ source files
_MAX_FILES_TO_SCAN = 3000

# Don't include more than this many sample URLs per finding (keeps reports readable)
_MAX_URL_SAMPLES = 10


class CleartextTrafficAgent(BaseAgent):
    """N_001: detects insecure HTTP traffic configurations."""

    AGENT_ID = "N_001"
    VULN_CLASS = "Cleartext Traffic"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        """Run when manifest exists; decompiled source is optional but preferred."""
        ctx = self._context
        if not ctx.manifest:
            logger.info("[N_001] No manifest — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Check manifest flag and scan decompiled source for http:// URLs."""
        findings: list[Finding] = []
        ctx = self._context
        manifest = ctx.manifest or {}

        manifest_flag = bool(manifest.get("uses_cleartext_traffic"))

        # Scan decompiled source for http:// URLs (only if available)
        http_urls: set[str] = set()
        url_locations: dict[str, list[str]] = {}
        self._first_hit: dict[str, Any] | None = None

        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            self._scan_directory(ctx.decompiled_dir, http_urls, url_locations, ".java")

        # If no manifest flag and no http URLs found, no finding
        if not manifest_flag and not http_urls:
            logger.info("[N_001] No cleartext traffic indicators found")
            return findings

        # Build a single combined finding
        findings.append(self._make_finding_for_results(
            manifest_flag=manifest_flag,
            http_urls=http_urls,
            url_locations=url_locations,
            package=manifest.get("package", "?"),
        ))

        return findings

    def _scan_directory(
        self,
        root: Path,
        urls: set[str],
        locations: dict[str, list[str]],
        suffix: str,
    ) -> None:
        """Walk a directory looking for http:// URLs in matching files."""
        files_scanned = 0
        for path in root.rglob(f"*{suffix}"):
            if not path.is_file():
                continue
            if path.name in _SKIP_PATTERNS:
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[N_001] Stopped scanning after %d files (perf cap)",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            for match in _HTTP_URL_RE.finditer(text):
                url = match.group(0).rstrip(".,;:'\"")
                if not url or len(url) < 12:
                    continue
                urls.add(url)
                rel = str(path.relative_to(root))
                if url not in locations:
                    locations[url] = []
                if rel not in locations[url]:
                    locations[url].append(rel)
                # First occurrence drives the FindingDetailView code
                # snippet — line/col derived from the regex span.
                if not hasattr(self, "_first_hit") or self._first_hit is None:
                    line_start = max(0, text.rfind("\n", 0, match.start()) + 1)
                    line_end = text.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(text)
                    self._first_hit = {
                        "file": rel,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "start_col": match.start() - line_start,
                        "end_col": (
                            match.start() - line_start
                            + (match.end() - match.start())
                        ),
                        "content": text[line_start:line_end].strip()[:200],
                    }

    def _make_finding_for_results(
        self,
        manifest_flag: bool,
        http_urls: set[str],
        url_locations: dict[str, list[str]],
        package: str,
    ) -> Finding:
        """Construct a finding scaled to the evidence found."""
        url_count = len(http_urls)

        # Severity logic
        if manifest_flag and url_count > 0:
            severity = Severity.HIGH
            confidence = 0.90
            summary = (
                f"manifest declares android:usesCleartextTraffic=\"true\" AND "
                f"{url_count} hardcoded http:// URL(s) found in code"
            )
        elif manifest_flag:
            severity = Severity.MEDIUM
            confidence = 0.80
            summary = (
                "manifest declares android:usesCleartextTraffic=\"true\" — "
                "app permits cleartext network traffic globally"
            )
        else:
            # URLs only, no manifest flag
            severity = Severity.MEDIUM if url_count >= 5 else Severity.LOW
            confidence = 0.70
            summary = (
                f"{url_count} hardcoded http:// URL(s) found in decompiled code "
                f"(no manifest flag set)"
            )

        # Build a sample list of URLs with their locations
        sample_urls = sorted(http_urls)[:_MAX_URL_SAMPLES]
        evidence_urls = []
        for url in sample_urls:
            locations = url_locations.get(url, [])
            evidence_urls.append({
                "url": url,
                "locations": locations[:3],  # cap files-per-url
            })

        first_hit = getattr(self, "_first_hit", None)
        code_snippets = self._build_code_snippets(
            first_hit=first_hit,
            manifest_flag=manifest_flag,
            evidence_urls=evidence_urls,
        )

        sample_url = sample_urls[0] if sample_urls else None

        source_tags = ["Cleartext Traffic", "Network Misconfiguration"]
        if manifest_flag:
            source_tags.append("Manifest Flag")
        if url_count > 0:
            source_tags.append("Hardcoded URL")

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(manifest_flag, url_count),
            code_snippet=first_hit,
            code_snippets=code_snippets or None,
            severity_rationale=self._build_severity_rationale(
                severity, manifest_flag, url_count, package,
            ),
            verification_status="Code-level only",
            source_tags=source_tags,
            reproduction_commands=self._build_repro_commands(
                manifest_flag, sample_url, package,
            ),
            observed_result=self._build_observed_result(
                manifest_flag, url_count, sample_url,
            ),
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            evidence={
                "title": f"Cleartext Traffic in {package}",
                "summary": summary,
                "package": package,
                "manifest_uses_cleartext_traffic": manifest_flag,
                "http_urls_count": url_count,
                "http_urls_sample": evidence_urls,
                "vector": (
                    "Run the application on a device using a hostile WiFi network "
                    "(or via a transparent proxy like mitmproxy). All HTTP traffic "
                    "is visible in plaintext and can be modified by the attacker."
                ),
            },
        )

    # ---------- new-field builders ----------

    @staticmethod
    def _build_code_snippets(
        *,
        first_hit: dict[str, Any] | None,
        manifest_flag: bool,
        evidence_urls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Materialise the offending sources as numbered snippets.

        First snippet (if available): the actual Java line that hits the
        regex, with line/column highlight so the detail view points at
        the exact substring. Second snippet (when the manifest flag is
        on): the synthesised <application> declaration so reviewers can
        see the global opt-in alongside the local example.
        """
        out: list[dict[str, Any]] = []
        if first_hit:
            out.append({
                "label": "Hardcoded URL",
                "file": first_hit.get("file", ""),
                "line": first_hit.get("line", 1),
                "start_col": first_hit.get("start_col"),
                "end_col": first_hit.get("end_col"),
                "content": first_hit.get("content", ""),
            })
        if manifest_flag:
            out.append({
                "label": "Manifest opt-in",
                "file": "AndroidManifest.xml",
                "line": 1,
                "content": (
                    "<application\n"
                    "    android:usesCleartextTraffic=\"true\"\n"
                    "    ... >\n"
                    "    <!-- All HTTP traffic permitted app-wide -->\n"
                    "</application>"
                ),
            })
        return out

    @staticmethod
    def _build_severity_rationale(
        severity: Severity,
        manifest_flag: bool,
        url_count: int,
        package: str,
    ) -> str:
        if manifest_flag and url_count > 0:
            return (
                f"Rated {severity.value} because {package} both opts into "
                f"cleartext traffic at the manifest level AND ships "
                f"{url_count} hardcoded http:// endpoint(s) that exercise "
                f"that opt-in. An on-path attacker on the user's WiFi can "
                f"read and modify every request flowing through these "
                f"endpoints — including any tokens, session IDs, or PII "
                f"the app sends in headers or bodies."
            )
        if manifest_flag:
            return (
                f"Rated {severity.value} because the manifest globally "
                f"permits cleartext traffic. No http:// endpoints were "
                f"found in decompiled code, so the actual attack surface "
                f"depends on runtime calls (WebViews, dynamically built "
                f"URLs, third-party SDKs). Treat the manifest flag as a "
                f"latent risk that becomes exploitable the moment any "
                f"plaintext request is issued."
            )
        return (
            f"Rated {severity.value} because {url_count} hardcoded "
            f"http:// URL(s) were found in decompiled code without an "
            f"accompanying manifest opt-in. On API 28+ these requests "
            f"will be blocked at runtime — but a Network Security Config "
            f"or a debug build can re-enable them silently. Treat this "
            f"as evidence of a development pattern that needs to be "
            f"removed before it ships globally."
        )

    @staticmethod
    def _build_repro_commands(
        manifest_flag: bool,
        sample_url: str | None,
        package: str,
    ) -> list[str]:
        target = sample_url or "http://api.example.com/endpoint"
        cmds = [
            "# 1. Start mitmproxy on the laptop (port 8080):",
            "mitmdump -p 8080",
            "",
            "# 2. Route the device's traffic through the laptop:",
            "adb shell settings put global http_proxy $(hostname -I | awk '{print $1}'):8080",
            "",
            f"# 3. Launch the target app:",
            f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1",
            "",
            "# 4. Confirm the request is visible in plaintext:",
            f"#    Expect mitmproxy to log a GET/POST to {target}",
        ]
        if manifest_flag:
            cmds += [
                "",
                "# 5. Verify the manifest opt-in is what permits this:",
                "aapt dump xmltree app.apk AndroidManifest.xml | grep -i cleartext",
            ]
        return cmds

    @staticmethod
    def _build_observed_result(
        manifest_flag: bool,
        url_count: int,
        sample_url: str | None,
    ) -> str:
        target = sample_url or "the configured HTTP endpoint"
        if manifest_flag and url_count > 0:
            return (
                f"With the device proxy pointed at mitmproxy, the request "
                f"to {target} appears in the proxy log unencrypted. All "
                f"request and response headers, the URL query string, "
                f"and any body content are readable and modifiable."
            )
        if manifest_flag:
            return (
                "The manifest's usesCleartextTraffic=\"true\" flag is "
                "confirmed; no specific plaintext request was captured "
                "during static analysis. Any runtime HTTP request will "
                "succeed (where it would otherwise be blocked by the "
                "Android 9+ default)."
            )
        return (
            f"Decompiled source contains hardcoded http:// URLs "
            f"({target}). On API 28+ these specific requests will fail "
            f"unless the app also adds a Network Security Config "
            f"exemption — but the URLs themselves disclose backend "
            f"endpoints that may not yet be hardened."
        )

    def _build_recommendation(self, manifest_flag: bool, url_count: int) -> str:
        """Class-aware remediation guidance."""
        steps: list[str] = []

        if manifest_flag:
            steps.append(
                "Remove android:usesCleartextTraffic=\"true\" from "
                "AndroidManifest.xml (or set it to \"false\"). On Android 9+ "
                "(API 28+), cleartext traffic is disabled by default."
            )

        if url_count > 0:
            steps.append(
                "Replace all hardcoded http:// URLs with https:// equivalents. "
                "If a backend service does not yet support TLS, add it as a "
                "deployment requirement before the next release. As a temporary "
                "measure, configure a Network Security Configuration "
                "(res/xml/network_security_config.xml) that whitelists only the "
                "specific domains that require cleartext, instead of allowing it "
                "globally."
            )

        steps.append(
            "Use a Network Security Configuration with HTTPS-only by default. "
            "See: https://developer.android.com/training/articles/security-config"
        )

        return " ".join(steps)
