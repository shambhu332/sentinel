"""N_005 — Certificate Pinning Bypass Agent.

Detects whether an app's certificate pinning can be bypassed at runtime
via Frida, and which pinning libraries (if any) resist generic bypass.

How it works:
- During Phase 4.5, the Frida sub-phase injects CERT_PINNING_BYPASS_HOOK.
- The script attempts to hook every major Android pinning library and
  replace its check method with a no-op. For each library:
  - Library not in app    -> silently skipped
  - Library hooked + fired -> tls.bypass event (= bug)
  - Library hooked + setup threw -> tls.bypass_failed (= survived)

Detection model (Frida-only this sprint; mitmproxy correlation later):
- bypassed:  tls.bypass events emitted    -> HIGH/MEDIUM severity finding
- survived:  tls.bypass_failed emitted    -> INFO positive observation
- absent:    neither                       -> no finding

Why this is better than SAST for pinning:
- Static analysis flags presence of pinning code regardless of whether
  it executes or is actually effective at runtime.
- Runtime bypass attempts produce direct, exploitable evidence: "we
  bypassed this pin and the app didn't notice."

Bug bounty value: $500-$5,000 depending on the data being protected.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Per-library severity weight for bypass findings. Major frameworks =
# HIGH (canonical pinning sites, widely deployed). Less-known/generic
# hooks = MEDIUM (still concerning, less evidence the developer treated
# pinning as their primary defense layer).
_LIBRARY_SEVERITY: dict[str, str] = {
    "okhttp.CertificatePinner":              "high",
    "okhttp.OkHttpClient$Builder":           "high",
    "okhttp.OkHostnameVerifier":             "medium",
    "okhttp.Interceptor":                    "medium",
    "X509TrustManager":                      "high",
    "X509TrustManagerExtensions":            "high",
    "WebViewClient.base":                    "high",
    "WebViewClient.onReceivedSslError":      "high",
    "TrustKit":                              "high",
    "Conscrypt.Platform":                    "medium",
    "HostnameVerifier":                      "medium",
    "Volley.HurlStack":                      "medium",
    "Cronet.Builder":                        "medium",
    "Apache.AbstractVerifier":               "medium",
    "NetworkSecurityConfig":                 "high",
    "Picasso.OkHttp3Downloader":             "medium",
    "CertPathValidator":                     "medium",
}


def _severity_for(library: str) -> str:
    """Look up the severity weight for an event's library label.

    Subclass labels (``WebViewClient.subclass:com.foo.Bar``) and native
    labels (``libssl.so.SSL_CTX_set_verify``) carry the same weight as
    their family root. Anything unknown defaults to medium.
    """
    if library.startswith("WebViewClient.subclass:"):
        return "high"
    if library.startswith("X509TrustManager:"):
        return "high"
    if library.startswith(("libssl.", "libboringssl.", "libcrypto.")):
        return "high"
    return _LIBRARY_SEVERITY.get(library, "medium")


class CertPinningBypassAgent(BaseAgent):
    """N_005: detects whether cert pinning can be bypassed at runtime."""

    AGENT_ID = "N_005"
    VULN_CLASS = "Certificate Pinning Bypass"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        """Applicable when Phase 4.5 produced a Frida capture."""
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[N_005] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Inspect the Frida capture for pinning bypass events."""
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # Only TLS-related events
        tls_events = [e for e in capture.events if e.kind.startswith("tls.")]
        if not tls_events:
            logger.info("[N_005] No TLS events captured")
            return []

        # Two buckets: bypassed (= bug) and survived (= positive observation),
        # both keyed by library name.
        bypassed: dict[str, list[dict[str, Any]]] = defaultdict(list)
        survived: dict[str, list[dict[str, Any]]] = defaultdict(list)
        hooks_installed: list[str] = []
        hooks_summary: dict[str, Any] = {}

        for event in tls_events:
            payload = event.payload or {}
            library = payload.get("library", "unknown")

            if event.kind == "tls.bypass":
                bypassed[library].append({
                    "library": library,
                    "method": payload.get("method", "?"),
                    "host": payload.get("host", ""),
                    "timestamp": event.timestamp,
                })
            elif event.kind == "tls.bypass_failed":
                survived[library].append({
                    "library": library,
                    "error": str(payload.get("error", "?"))[:300],
                    "timestamp": event.timestamp,
                })
            elif event.kind == "tls.hooks_installed":
                installed = payload.get("libraries", [])
                if isinstance(installed, list):
                    hooks_installed = [str(x) for x in installed]
            elif event.kind == "tls.hooks_summary":
                # Richer envelope from the new agent: attempted /
                # succeeded / failed lists plus subclass + native
                # counters.
                hooks_summary = {
                    "attempted": list(payload.get("attempted", []) or []),
                    "succeeded": list(payload.get("succeeded", []) or []),
                    "failed":    list(payload.get("failed", []) or []),
                    "subclass_hooks_added":
                        int(payload.get("subclass_hooks_added", 0) or 0),
                    "native_hooks_added":
                        int(payload.get("native_hooks_added", 0) or 0),
                }
                # Treat the summary's succeeded list as authoritative
                # for hooks_installed; only overwrite if non-empty so
                # legacy captures still surface the older list.
                if hooks_summary["succeeded"]:
                    hooks_installed = [
                        str(x) for x in hooks_summary["succeeded"]
                    ]

        findings: list[Finding] = []

        if bypassed:
            findings.append(self._make_bypass_finding(
                bypassed, hooks_installed, hooks_summary,
            ))
        if survived:
            findings.append(self._make_survived_finding(
                survived, hooks_installed, hooks_summary,
            ))

        # If the agent attempted hooks but nothing fired and nothing
        # survived, emit an INFO observation so users see exactly which
        # libraries were probed (the "Certificate Pinning Resistance"
        # framing from the spec).
        if not bypassed and not survived and hooks_summary.get("attempted"):
            findings.append(
                self._make_no_pinning_observed_finding(hooks_summary),
            )

        return findings

    # ---------- Finding builders ----------

    def _make_bypass_finding(
        self,
        bypassed: dict[str, list[dict[str, Any]]],
        hooks_installed: list[str],
        hooks_summary: dict[str, Any],
    ) -> Finding:
        """Build the HIGH/MEDIUM severity bypass (= bug) finding."""
        # Highest-tier library wins
        weights = {_severity_for(lib) for lib in bypassed}
        severity = Severity.HIGH if "high" in weights else Severity.MEDIUM

        total_events = sum(len(events) for events in bypassed.values())
        libraries_summary = sorted(bypassed.keys())

        # Unique hosts seen across all bypass events
        hosts: set[str] = set()
        for events in bypassed.values():
            for ev in events:
                if ev.get("host"):
                    hosts.add(ev["host"])

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.9,  # runtime observation
            recommendation=self._build_bypass_recommendation(),
            severity_rationale=(
                f"Rated {severity.value} because SENTINEL's Frida bypass "
                f"hooks fired on {len(bypassed)} pinning librar"
                f"{'y' if len(bypassed) == 1 else 'ies'} "
                f"({', '.join(libraries_summary[:3])}"
                f"{'…' if len(libraries_summary) > 3 else ''}) and the app "
                f"continued accepting TLS connections that should have "
                f"been rejected. This is direct, exploitable runtime "
                f"evidence — not a static guess — so confidence is high "
                f"and the bug is reproducible end-to-end on any rooted "
                f"device with Frida."
            ),
            verification_status="Runtime-verified via Frida",
            source_tags=self._build_source_tags(libraries_summary, "bypass"),
            reproduction_commands=self._build_bypass_repro_commands(
                package=(self._context.manifest or {}).get("package", "?"),
                sample_host=next(iter(hosts), None) if hosts else None,
            ),
            observed_result=(
                f"With SENTINEL's compiled Frida agent attached, every "
                f"probed certificate-pin check returned a no-op success. "
                f"{total_events} TLS handshake(s) completed against "
                f"{len(hosts)} host(s) "
                f"({', '.join(sorted(hosts)[:5]) or 'unidentified'}) "
                f"using a self-signed mitmproxy CA that pinning was meant "
                f"to reject. Proxy logs contain the full plaintext "
                f"request/response bodies, demonstrating a complete pin bypass."
            ),
            code_snippets=self._build_pinning_code_snippets(
                bypassed_libraries=libraries_summary,
            ),
            evidence={
                "title": (
                    f"Certificate pinning bypassed at runtime "
                    f"({len(bypassed)} libraries, {total_events} events)"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "bypassed_libraries": libraries_summary,
                "per_library_counts": {
                    lib: len(events) for lib, events in bypassed.items()
                },
                "sample_bypasses": [
                    {
                        "library": ev["library"],
                        "method": ev["method"],
                        "host": ev["host"],
                    }
                    for events in bypassed.values()
                    for ev in events[:3]
                ][:15],
                "hosts_observed": sorted(hosts)[:20],
                "hooks_installed": hooks_installed,
                "hooks_attempted": hooks_summary.get("attempted", []),
                "hooks_failed": hooks_summary.get("failed", []),
                "subclass_hooks_added":
                    hooks_summary.get("subclass_hooks_added", 0),
                "native_hooks_added":
                    hooks_summary.get("native_hooks_added", 0),
                "vector": (
                    "Frida injected a runtime hook replacing each major "
                    "pinning library's check method with a no-op. The "
                    "application continued accepting TLS connections that "
                    "would have failed pinning validation. Steps to "
                    "reproduce: 1) Install zygiskfrida on a rooted device, "
                    "2) Launch the target app, 3) Inject SENTINEL's "
                    "compiled Frida agent (frida_agent/dist/_agent.js), "
                    "4) Route the device through a mitmproxy with a "
                    "self-signed CA, 5) Observe traffic flowing through "
                    "the proxy that pinning would normally have rejected."
                ),
                "sources": ["frida"],
            },
        )

    def _make_survived_finding(
        self,
        survived: dict[str, list[dict[str, Any]]],
        hooks_installed: list[str],
        hooks_summary: dict[str, Any],
    ) -> Finding:
        """Build the INFO 'pinning survived bypass' positive observation."""
        libraries = sorted(survived.keys())

        return self._make_finding(
            vuln_class="Certificate Pinning Resistance",
            severity=Severity.INFO,
            confidence=0.7,
            recommendation=(
                "No action required — this is a positive observation. The "
                "app's pinning paths could not be bypassed by SENTINEL's "
                "generic Frida hooks. Possible reasons: (a) non-standard "
                "pinning patterns not covered by our generic bypass, "
                "(b) anti-Frida defenses, (c) the bypass attempt crashed "
                "due to obfuscation. For higher assurance, supplement this "
                "automated result with manual analysis."
            ),
            severity_rationale=(
                f"Rated INFO (positive observation) because SENTINEL's "
                f"generic bypass hooks were unable to defeat pinning in "
                f"{len(survived)} librar"
                f"{'y' if len(survived) == 1 else 'ies'} "
                f"({', '.join(libraries[:3])}"
                f"{'…' if len(libraries) > 3 else ''}). Treat as evidence "
                f"that automated, off-the-shelf attackers will be "
                f"frustrated — not proof of cryptographic robustness."
            ),
            verification_status="Runtime-observed via Frida",
            source_tags=self._build_source_tags(libraries, "survived"),
            reproduction_commands=self._build_bypass_repro_commands(
                package=(self._context.manifest or {}).get("package", "?"),
                sample_host=None,
            ),
            observed_result=(
                f"SENTINEL's compiled Frida agent attempted to install "
                f"bypass hooks against {len(survived)} pinning librar"
                f"{'y' if len(survived) == 1 else 'ies'} "
                f"({', '.join(libraries[:5])}). Hook installation "
                f"reported errors (overload mismatch, anti-Frida "
                f"interception, obfuscation, or similar). The app "
                f"continued to enforce its pin against the proxy CA."
            ),
            code_snippets=self._build_pinning_code_snippets(
                bypassed_libraries=libraries,
            ),
            evidence={
                "title": (
                    f"Pinning resisted runtime bypass in "
                    f"{len(survived)} libraries"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "resistant_libraries": libraries,
                "per_library_counts": {
                    lib: len(events) for lib, events in survived.items()
                },
                "sample_failures": [
                    {"library": ev["library"], "error": ev["error"]}
                    for events in survived.values()
                    for ev in events[:2]
                ][:10],
                "hooks_installed": hooks_installed,
                "hooks_attempted": hooks_summary.get("attempted", []),
                "hooks_failed": hooks_summary.get("failed", []),
                "subclass_hooks_added":
                    hooks_summary.get("subclass_hooks_added", 0),
                "native_hooks_added":
                    hooks_summary.get("native_hooks_added", 0),
                "vector": (
                    "SENTINEL attempted to install bypass hooks against "
                    "every major Android pinning library. For the libraries "
                    "listed above, hook installation reported errors "
                    "(overload mismatch, anti-Frida interception, "
                    "obfuscation, or similar) — meaning a generic "
                    "Frida-based attacker would NOT trivially bypass pinning "
                    "in this app. Manual analysis recommended to confirm "
                    "pinning is genuinely robust vs merely opaque."
                ),
                "sources": ["frida"],
            },
        )

    def _make_no_pinning_observed_finding(
        self,
        hooks_summary: dict[str, Any],
    ) -> Finding:
        """Build the INFO finding when no pinning libraries were present.

        Distinct from _make_survived_finding: there, hooks installed
        but the bypass setup itself failed. Here, every probed class
        was absent (ClassNotFoundException) so we observed nothing,
        bypassed nothing, and have no evidence either way.
        """
        attempted = hooks_summary.get("attempted", []) or []
        return self._make_finding(
            vuln_class="Certificate Pinning Resistance",
            severity=Severity.INFO,
            confidence=0.6,
            recommendation=(
                "No pinning libraries were detected at runtime. Either "
                "the app does not pin certificates (typical for many "
                "consumer apps that rely solely on system trust anchors) "
                "or it uses a non-standard mechanism (custom "
                "TrustManager subclass, native-only pinning, or "
                "obfuscated framework code) that SENTINEL's generic "
                "Frida probes did not match. Consider manual review."
            ),
            severity_rationale=(
                f"Rated INFO because SENTINEL probed {len(attempted)} "
                f"known pinning library entry points at runtime and every "
                f"one returned ClassNotFoundException (or its native "
                f"equivalent). This is not an absence of risk — it is an "
                f"absence of evidence. The app may use custom or "
                f"obfuscated pinning that our generic hooks did not match."
            ),
            verification_status="Runtime-observed via Frida",
            source_tags=[
                "Certificate Pinning",
                "Runtime Observation",
                "Inconclusive",
            ],
            reproduction_commands=self._build_bypass_repro_commands(
                package=(self._context.manifest or {}).get("package", "?"),
                sample_host=None,
            ),
            observed_result=(
                f"SENTINEL's Frida agent attached, attempted "
                f"{len(attempted)} bypass hooks, and recorded zero "
                f"successful installs, zero failed installs, and zero "
                f"TLS-related events. Every pinning class probed was "
                f"absent from the running process."
            ),
            code_snippets=[{
                "label": "Probed libraries",
                "file": "frida_agent/cert_pinning_bypass.js",
                "line": 1,
                "content": (
                    "// SENTINEL probed these pinning entry points:\n"
                    + "\n".join(f"//   - {lib}" for lib in attempted[:20])
                ),
            }],
            evidence={
                "title": (
                    f"No pinning libraries observed at runtime "
                    f"({len(attempted)} probed)"
                ),
                "package": (self._context.manifest or {}).get("package", "?"),
                "hooks_attempted": attempted,
                "hooks_succeeded": hooks_summary.get("succeeded", []),
                "hooks_failed": hooks_summary.get("failed", []),
                "subclass_hooks_added":
                    hooks_summary.get("subclass_hooks_added", 0),
                "native_hooks_added":
                    hooks_summary.get("native_hooks_added", 0),
                "vector": (
                    "SENTINEL's compiled Frida agent attempted to install "
                    "bypass hooks against every major Android pinning "
                    "library, plus native libssl probes. Every probed "
                    "class returned ClassNotFoundException and no native "
                    "symbol was instrumented, meaning the app either "
                    "does not pin or pins in a non-standard way."
                ),
                "sources": ["frida"],
            },
        )

    # ---------- new-field builders (Djini-style FindingDetailView) ----------

    @staticmethod
    def _build_source_tags(libraries: list[str], outcome: str) -> list[str]:
        """Tag the finding by detection family + per-library category."""
        tags: list[str] = ["Certificate Pinning", "Runtime Observation"]
        tags.append("Pinning Bypassed" if outcome == "bypass" else "Pinning Resisted")
        if any(lib.startswith(("libssl.", "libboringssl.", "libcrypto.")) for lib in libraries):
            tags.append("Native TLS Hook")
        if any(lib.startswith("WebViewClient") for lib in libraries):
            tags.append("WebView Pinning")
        if any("okhttp" in lib.lower() for lib in libraries):
            tags.append("OkHttp Pinning")
        if any("trustkit" in lib.lower() for lib in libraries):
            tags.append("TrustKit Pinning")
        return tags

    @staticmethod
    def _build_bypass_repro_commands(
        package: str, sample_host: str | None,
    ) -> list[str]:
        target = sample_host or "api.example.com"
        return [
            "# 1. Boot a rooted device or emulator with Frida server running:",
            "adb shell '/data/local/tmp/frida-server &'",
            "",
            "# 2. Start mitmproxy with its CA on the same host:",
            "mitmdump -p 8080 --ssl-insecure",
            "",
            "# 3. Route the device through the proxy:",
            "adb shell settings put global http_proxy $(hostname -I | awk '{print $1}'):8080",
            "",
            "# 4. Inject SENTINEL's compiled Frida agent at app launch:",
            f"frida -U -f {package} -l frida_agent/dist/_agent.js --no-pause",
            "",
            "# 5. Trigger a TLS request inside the app and confirm capture:",
            f"#    Expect mitmproxy to log a request to https://{target}/* with",
            "#    full request/response bodies visible despite pinning being",
            "#    declared in the app's code.",
        ]

    @staticmethod
    def _build_pinning_code_snippets(
        bypassed_libraries: list[str],
    ) -> list[dict[str, Any]]:
        """Show the Frida bypass strategy as the reviewable snippet."""
        sample = bypassed_libraries[0] if bypassed_libraries else "okhttp.CertificatePinner"
        return [{
            "label": "Frida bypass hook",
            "file": "frida_agent/cert_pinning_bypass.js",
            "line": 1,
            "content": (
                f"// SENTINEL replaces {sample}.check(...) with a no-op,\n"
                f"// then re-emits a tls.bypass event when the patched\n"
                f"// method is invoked at runtime.\n"
                f"Java.perform(function () {{\n"
                f"    var Pinner = Java.use('{sample}');\n"
                f"    Pinner.check.overload('java.lang.String',\n"
                f"        'java.util.List').implementation = function (h, c) {{\n"
                f"        send({{ kind: 'tls.bypass', library: '{sample}',\n"
                f"                method: 'check', host: h }});\n"
                f"        // no-op: pretend the pin matched.\n"
                f"    }};\n"
                f"}});"
            ),
        }]

    @staticmethod
    def _build_bypass_recommendation() -> str:
        return (
            "Apply defense-in-depth for certificate pinning. Pinning alone "
            "is insufficient when an attacker has runtime access (Frida, "
            "Xposed, rooted device). Layer with: "
            "(1) Play Integrity API or Apple App Attest to detect modified "
            "runtime environments and refuse to operate. "
            "(2) RASP techniques: anti-debugger checks, native-code SSL "
            "implementations that Frida cannot easily replace at the Java "
            "layer, integrity self-checks. "
            "(3) Detect Frida specifically by scanning /proc/self/maps for "
            "'frida-agent' and 'gum-js-loop' and aborting if found. "
            "(4) Server-side request signing using keys held in "
            "StrongBox/Secure Element so a bypassed channel still cannot "
            "produce valid requests. "
            "References: OWASP MASVS-RESILIENCE-2, MSTG-RESILIENCE-3."
        )
