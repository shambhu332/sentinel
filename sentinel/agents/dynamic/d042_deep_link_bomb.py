"""D_042 — Deep-Link bomb (Dynamic Testing Target).

Identifies every activity that handles `android.intent.action.VIEW`
with a scheme/host registered in `<intent-filter>` and emits a Frida
trigger payload containing 50 curated malformed deep-link probes.

The DAST hook fires the probes via `am start -a VIEW -d <probe>` in
rapid succession (bounded by SafetyBudget) while monitoring `logcat`
for FATAL EXCEPTION lines. Each crash adds a result row: `{probe,
exception, in_target_app}`.

Probe families (50 total):
  * Oversized strings — 8 / 64 / 8192 / 65535 chars
  * SQLi-shaped — `' OR 1=1--`, `1; DROP TABLE x--`
  * XSS-shaped — `<script>alert(1)</script>`, javascript: URIs
  * Path traversal — `../../etc/hosts`
  * Unicode confusables / RTL override (U+202E)
  * Control chars — NUL, BEL, LF
  * Null/missing host, missing scheme
  * Double-encoded — `%252e%252e`
  * Schema confusion — `https:javascript:`
  * Recursive — deep-link inside deep-link

Output finding carries `dynamic_target=True` and a `frida_payload`
with the SafetyBudget envelope.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Curated probe set — kept inline for review-friendliness.
_PROBES: list[str] = [
    # Oversized
    "A" * 8,
    "A" * 64,
    "A" * 8192,
    "A" * 65535,
    # SQLi
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "x' UNION SELECT 1--",
    # XSS / JS
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Path traversal
    "../../etc/hosts",
    "../../../../system/build.prop",
    "..%2f..%2fsecrets",
    # Unicode
    "‮txt.evil",   # RTL override
    "ev​il",       # zero-width space
    "foo",        # NUL
    "fbar",       # BEL
    "f\noo",            # LF
    # Empty / null hosts
    "",
    " ",
    "://",
    "://noscheme",
    "no_scheme_here",
    # Double-encoded
    "%252e%252e%2fetc",
    "%2500evil",
    # Schema confusion
    "https:javascript:alert(1)",
    "intent://#Intent;scheme=javascript;end",
    "intent:#Intent;action=android.intent.action.VIEW;launchFlags=0x10000000;end",
    # Recursive
    "myapp://deep?next=myapp://deep?next=myapp://deep",
    # Common bypass shapes
    "myapp://login?token=admin&isAdmin=true",
    "myapp:///etc/passwd",
    "myapp://%00.host",
    "myapp://host:99999999",     # invalid port
    "myapp://[::1]",             # IPv6
    # Boundaries / weird chars
    "myapp://\x00",
    "myapp://?a=" + ("&b=" * 200),
    "myapp://#" + "X" * 4000,
    "myapp://?json=" + "{" * 2000,
    "myapp://?eq=%3D%3D%3D",
    # Heavy query
    "myapp://search?q=" + "%20" * 500,
    "myapp://search?q=" + "&q=" * 300,
    # File scheme variants
    "file:///etc/hosts",
    "file:///data/data/com.app/databases/auth.db",
    # Reserved / forbidden chars
    "myapp://?a=<>:\"|*?",
    # Crash-shaped
    "myapp://%c0%80",
    "myapp://%e2%80%a8",        # line separator
    "myapp://%ee%80%80",
    "myapp://" + ("a" * 100) + "?" + ("b=" * 100),
    # Mid-string scheme override
    "myapp://example.com/@evil.com/",
    "myapp://attacker.com\\@example.com/",
]


class DeepLinkBombAgent(BaseAgent):
    """D_042: enumerate deep-link surface + emit fuzz trigger payload."""

    AGENT_ID = "D_042"
    VULN_CLASS = "Deep-Link Crash / Bypass Fuzz (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.manifest)

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        targets = self._collect_deep_link_targets(manifest)
        if not targets:
            return []

        package = manifest.get("package", "")
        findings: list[Finding] = []
        for target in targets:
            payload = self._build_payload(package, target)
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.65,
                recommendation=(
                    f"Activity `{target['activity']}` handles deep links "
                    f"on scheme(s) {target['schemes']} / host(s) "
                    f"{target['hosts']}. The DAST phase will fire "
                    f"{len(_PROBES)} curated probe deep-links under "
                    "SafetyBudget guardrails and report any logcat "
                    "FATAL EXCEPTION. Harden by rejecting "
                    "non-allow-listed schemes, validating host/path "
                    "against a strict regex, and bounding extras lengths."
                ),
                evidence={
                    "activity": target["activity"],
                    "schemes": target["schemes"],
                    "hosts": target["hosts"],
                    "exported": target["exported"],
                    "probe_count": len(_PROBES),
                    "dynamic_target": True,
                    "frida_payload": payload,
                },
            ))
        return findings

    # ---------- target enumeration ----------

    @staticmethod
    def _collect_deep_link_targets(
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        for act in manifest.get("activities", []) or []:
            if not isinstance(act, dict):
                continue
            filters = act.get("intent_filters") or []
            schemes: set[str] = set()
            hosts: set[str] = set()
            handles_view = False
            for f in filters:
                if not isinstance(f, dict):
                    continue
                actions = f.get("actions") or []
                if "android.intent.action.VIEW" in actions \
                   or f.get("action") == "android.intent.action.VIEW":
                    handles_view = True
                for s in (f.get("schemes") or []):
                    if isinstance(s, str):
                        schemes.add(s)
                for h in (f.get("hosts") or []):
                    if isinstance(h, str):
                        hosts.add(h)
                # Some parsers emit flat keys 'scheme' / 'host'
                if isinstance(f.get("scheme"), str):
                    schemes.add(f["scheme"])
                if isinstance(f.get("host"), str):
                    hosts.add(f["host"])
            if handles_view and schemes:
                targets.append({
                    "activity": act.get("name", ""),
                    "schemes": sorted(schemes),
                    "hosts": sorted(hosts),
                    "exported": bool(act.get("exported")),
                })
        return targets

    # ---------- payload ----------

    @staticmethod
    def _build_payload(
        package: str, target: dict[str, Any],
    ) -> dict[str, Any]:
        scheme = (target["schemes"] or [""])[0]
        host = (target["hosts"] or [""])[0]
        # Rewrite the placeholder `myapp://` in the probe set to the
        # target's actual scheme/host so the deep-link actually
        # resolves to this activity.
        prefix = (
            f"{scheme}://{host}/" if scheme and host
            else f"{scheme}://" if scheme else ""
        )
        rewritten = [
            (p.replace("myapp://", prefix) if "myapp://" in p else p)
            for p in _PROBES
        ]
        return {
            "package": package,
            "activity": target["activity"],
            "probes": rewritten,
            "safety_budget": {
                "max_actions_total": 50,
                "max_actions_per_sec": 5,
                "wall_clock_budget_s": 60,
                "max_consecutive_crashes": 5,
            },
            "frida_script_hint":
                "// D_042 — fire deep-link probes via am start\n"
                f"// activity = {target['activity']}\n"
                "// rpc.exports.deeplinkbomb(payload) is the entry\n",
        }


__all__ = ["DeepLinkBombAgent"]
