"""D_050 — TLS pinning defense-in-depth stress test (Dynamic Testing Target).

A well-protected app stacks multiple pinning layers (system
TrustManager, OkHttp CertificatePinner, Conscrypt, TrustKit,
WebViewClient.onReceivedSslError). Real attackers disable layers one
at a time looking for the weakest link. D_050 maps that posture by
identifying every pinning implementation present in code, then
emitting a Frida bypass plan that disables them one at a time and
fires a known canary request after each disable.

Output for the C-suite: "Your app has 4 pinning layers; the
attacker needs to bypass 3 simultaneously before traffic flows to a
rogue CA."

SAST inventory targets:
  * X509TrustManager + checkServerTrusted overrides
  * okhttp3.CertificatePinner.add / setCertificatePinner
  * com.datatheorem.android.trustkit.config
  * org.conscrypt.Conscrypt usage with custom params
  * WebViewClient.onReceivedSslError -> proceed()
  * Network Security Config <pin-set> entries (res/xml/network_security_config)

The Frida hook (d050_pinning_stress_test.ts) iterates the detected
layers, disables one (replacing the verifier with `() => true`),
fires a canary GET to a known clean-fingerprint endpoint, records
the result, restores the original, and moves to the next.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Each layer is (name, regex marker, hook strategy hint)
_LAYERS: list[tuple[str, re.Pattern, str]] = [
    (
        "x509_trust_manager",
        re.compile(
            r"\b(X509TrustManager|HostnameVerifier|checkServerTrusted)\b"
        ),
        "javax.net.ssl.X509TrustManager.checkServerTrusted -> noop",
    ),
    (
        "okhttp_certificate_pinner",
        re.compile(r"\bCertificatePinner\.Builder\b|\.add\([^)]*\"sha256/"),
        "okhttp3.CertificatePinner.check$1 -> noop",
    ),
    (
        "conscrypt",
        re.compile(r"\borg\.conscrypt\.|Conscrypt\."),
        "org.conscrypt.Conscrypt.* -> standard hook",
    ),
    (
        "trustkit",
        re.compile(r"\bcom\.datatheorem\.android\.trustkit\b"),
        "TrustKit.getInstance().initializeWithNetworkSecurityConfiguration -> noop",
    ),
    (
        "webview_ssl_error",
        re.compile(
            r"\bonReceivedSslError\s*\([^)]*\)\s*\{[^}]*\.proceed\s*\("
        ),
        "WebViewClient.onReceivedSslError -> noop",
    ),
]

_MAX_FILES = 3000


class PinningStressTestAgent(BaseAgent):
    """D_050: map pinning defense-in-depth and emit a stress test."""

    AGENT_ID = "D_050"
    VULN_CLASS = "TLS Pinning Defense-in-Depth Map (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        if root is None:
            return []

        # Stage 1: code-side inventory
        layers_present: dict[str, dict[str, Any]] = {}
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            for name, pat, hint in _LAYERS:
                if pat.search(text):
                    entry = layers_present.setdefault(name, {
                        "hook_strategy": hint, "files": [],
                    })
                    if len(entry["files"]) < 5:
                        entry["files"].append(rel)

        # Stage 2: Network Security Config <pin-set>
        nsc_pins = self._parse_network_security_config(ctx.resources_dir)
        if nsc_pins:
            layers_present["network_security_config"] = {
                "hook_strategy": "android.security.NetworkSecurityConfig "
                                 "-> swap pin-set to permissive",
                "pin_count": nsc_pins,
            }

        if not layers_present:
            return []

        # Severity bands by stack depth
        n_layers = len(layers_present)
        if n_layers >= 3:
            severity = Severity.INFO   # strong posture
        elif n_layers >= 2:
            severity = Severity.LOW
        else:
            severity = Severity.MEDIUM  # only one layer = easy bypass

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.85,
            recommendation=(
                f"{n_layers} pinning layer(s) detected. The Frida stress "
                "hook will disable each one in turn, fire a canary HTTPS "
                "request, and record whether traffic flowed. A single-"
                "layer posture is trivially bypassed at runtime; 3+ "
                "layers raise the cost meaningfully. Consider adding "
                "Network Security Config pin-set entries if missing."
            ),
            evidence={
                "layer_count": n_layers,
                "layers": layers_present,
                "dynamic_target": True,
                "frida_payload": {
                    "layers": list(layers_present.keys()),
                    "canary_url": "https://www.gstatic.com/generate_204",
                    "expected_status": 204,
                    "safety_budget": {
                        "max_actions_total": 20,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 5,
                    },
                    "frida_script_hint":
                        "// D_050 — disable each pinning layer, "
                        "fire canary, restore.\n"
                        "// rpc.exports.pinningstress(payload) is the entry\n",
                },
            },
        )]

    # ---------- NSC parsing ----------

    @staticmethod
    def _parse_network_security_config(resources_dir: Path | None) -> int:
        if not resources_dir:
            return 0
        nsc = resources_dir / "res" / "xml" / "network_security_config.xml"
        if not nsc.is_file():
            return 0
        try:
            tree = ET.parse(nsc)
        except (ET.ParseError, OSError):
            return 0
        pin_count = 0
        for elt in tree.iter():
            tag = elt.tag.split("}")[-1] if "}" in elt.tag else elt.tag
            if tag == "pin":
                pin_count += 1
        return pin_count


__all__ = ["PinningStressTestAgent"]
