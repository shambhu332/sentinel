"""D_083 — Mobile SSRF Prober (Dynamic Testing Target).

Identifies methods that pull a URL from user input or a deep-link
extra and pass it to a network sink (`OkHttpClient.newCall`,
`Retrofit.create`, `HttpURLConnection`, `WebView.loadUrl`, `Glide`,
`Picasso`). Emits a Frida payload directing the DAST hook to swap
the destination with the curated cloud-metadata + RFC1918 probe list
and observe whether the app actually retrieves data.

Safety boundaries enforced in BOTH halves:
  * Python agent: the probe list is hard-coded to local / private /
    cloud-metadata IPs. The agent never sends external addresses.
  * TS hook (separate file): rejects any candidate URL whose host
    isn't on the allow-list of safe probe destinations.

Curated probe destinations (limit to ~12 — small enough that an
operator can reason about them, big enough to cover the main
managed-cloud + private-network targets):

  * 169.254.169.254  — AWS IMDS / GCP metadata
  * 100.100.100.200  — Alibaba Cloud metadata
  * metadata.google.internal — GCP metadata via DNS
  * 127.0.0.1 / localhost — loopback (Redis, etcd, …)
  * 10.0.0.1 / 192.168.1.1 — common gateway
  * 169.254.0.0/16 — link-local
  * file:// + content:// for URL-scheme bypasses
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Network-sink patterns we want the hook to intercept.
# Each tuple is (label, primary_re, optional_secondary_re). When
# secondary_re is set, the FILE must match both — the line where
# OkHttpClient is constructed and the line where .newCall is invoked
# are typically separate. Keeping the two-marker pattern prevents a
# stray `import` of an unrelated `Foo.newCall` from being flagged.
_SINKS: list[tuple[str, "re.Pattern", "re.Pattern | None"]] = [
    ("okhttp_newcall",
     re.compile(r"\bOkHttpClient\b"),
     re.compile(r"\.newCall\s*\(")),
    ("retrofit_build",
     re.compile(r"Retrofit\.Builder\b|\.baseUrl\s*\("),
     None),
    ("httpurlconn",
     re.compile(r"\bopenConnection\s*\(\s*\)"),
     re.compile(r"\.connect\s*\(\)")),
    ("webview_load",
     re.compile(r"\.loadUrl\s*\("),
     None),
    ("glide_load",
     re.compile(r"\bGlide\b"),
     re.compile(r"\.load\s*\(")),
    ("picasso_load",
     re.compile(r"\bPicasso\b"),
     re.compile(r"\.load\s*\(")),
]

# Taint-source patterns we want to see flowing into the sink: deep-link
# / Intent-extra / Uri-parameter / push-notification payload.
_TAINT_SOURCES = (
    "getStringExtra",
    "getQueryParameter",
    "getData()",
    "intent.getData",
    "getDataString",
    "Uri.parse",
    "getMessage().getData",  # FCM payload
)

# Hard-coded safe probe destinations — these go into the frida_payload
# and the TS hook enforces them as a whitelist.
_PROBE_DESTINATIONS = [
    "http://169.254.169.254/latest/meta-data/",        # AWS IMDS v1
    "http://169.254.169.254/computeMetadata/v1/",      # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",        # Alibaba
    "http://127.0.0.1:6379/",                          # Redis
    "http://127.0.0.1:2379/",                          # etcd
    "http://127.0.0.1:9200/",                          # Elasticsearch
    "http://localhost/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "file:///etc/hosts",
    "content://com.android.providers.settings/secure",
]

_MAX_FILES = 2500


class MobileSsrfAgent(BaseAgent):
    """D_083: identify URL-fetch sinks fed by user input -> SSRF probe."""

    AGENT_ID = "D_083"
    VULN_CLASS = "Mobile SSRF (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        if root is None:
            return []

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Need at least one sink in the file before we look at sources.
            matched_sinks: list[str] = []
            for name, primary, secondary in _SINKS:
                if not primary.search(text):
                    continue
                if secondary is not None and not secondary.search(text):
                    continue
                matched_sinks.append(name)
            if not matched_sinks:
                continue
            taint_present = any(t in text for t in _TAINT_SOURCES)
            if not taint_present:
                continue

            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]
            severity = (
                Severity.HIGH if "webview_load" in matched_sinks
                or "okhttp_newcall" in matched_sinks
                else Severity.MEDIUM
            )

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.65,
                recommendation=(
                    f"`{class_name}` routes user-supplied URL strings "
                    f"(via {sorted({t for t in _TAINT_SOURCES if t in text})[:3]}) "
                    f"into network sinks ({matched_sinks}). The Frida "
                    "DAST hook will, at request-time, rewrite the URL to "
                    "each of the curated probe destinations (AWS IMDS, "
                    "GCP metadata, loopback Redis/etcd, RFC1918 gateway, "
                    "file://, content://) and observe whether any "
                    "response indicates the request actually reached the "
                    "internal target. Fix by validating the host against "
                    "a strict allow-list before any fetch — reject "
                    "private/link-local IP literals, file:/content: "
                    "schemes, and DNS rebinding shapes."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "matched_sinks": matched_sinks,
                    "taint_sources_present": sorted(
                        {t for t in _TAINT_SOURCES if t in text}
                    )[:5],
                    "dynamic_target": True,
                    "frida_payload": self._build_payload(
                        class_name, matched_sinks,
                    ),
                },
            ))
        return findings

    @staticmethod
    def _build_payload(
        class_name: str, matched_sinks: list[str],
    ) -> dict[str, Any]:
        return {
            "target_class": class_name,
            "monitor_sinks": matched_sinks,
            "probe_destinations": _PROBE_DESTINATIONS,
            # The TS hook enforces these. Anything not matching is
            # silently passed through without rewriting.
            "allowed_destination_prefixes": [
                "http://169.254.",
                "http://100.100.100.200",
                "http://metadata.google.internal",
                "http://127.",
                "http://localhost",
                "http://10.",
                "http://192.168.",
                "http://172.16.", "http://172.17.", "http://172.18.",
                "http://172.19.", "http://172.20.", "http://172.21.",
                "http://172.22.", "http://172.23.", "http://172.24.",
                "http://172.25.", "http://172.26.", "http://172.27.",
                "http://172.28.", "http://172.29.", "http://172.30.",
                "http://172.31.",
                "file://",
                "content://",
            ],
            # Brief's safety guidance: do NOT scan external hosts.
            "block_external": True,
            "response_capture_bytes": 256,
            "safety_budget": {
                "max_actions_total": 12,
                "max_actions_per_sec": 1,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                "// D_083 — rewrite outbound URLs to safe probe targets\n"
                "// rpc.exports.mobilessrf(payload) is the entry\n",
        }


__all__ = ["MobileSsrfAgent"]
