"""N_013: Insecure WebSocket Connection Detection.

WebSocket traffic over ``ws://`` is cleartext — anyone on the network
path sees the full frame contents. For real-time apps that often
carry bearer credentials (auth tokens in the handshake's
``Authorization`` header, ``Cookie`` headers, or first-message
login), this is straightforward credential theft.

The fix is universally ``wss://`` (WebSocket Secure, TLS-wrapped).
N_001 / N_002 only cover ``http://`` URLs; without this agent the
``ws://`` URL slips through.

Detection
=========

We flag three shapes:

* OkHttp ``Request.Builder().url("ws://…")`` followed by an
  ``OkHttpClient.newWebSocket`` call.
* ``new WebSocketClient(new URI("ws://…"))`` (the Java-WebSocket
  library).
* Android-native ``Network.openConnection`` style with a ``ws://``
  URL literal.

A finding fires when the URL literal starts with ``ws://`` (case-
insensitive). The exception: ``ws://localhost`` / ``ws://127.0.0.1``
/ ``ws://10.0.2.2`` (Android emulator host alias) → MEDIUM severity
because the cleartext traffic doesn't leave the device.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_WS_URL_LITERAL = re.compile(
    r'"(ws://[A-Za-z0-9._\-:/@?&=%~+#]+)"',
    re.IGNORECASE,
)
_LOOPBACK_HOSTS = re.compile(
    r"^ws://(localhost|127\.0\.0\.1|10\.0\.2\.2)(?::\d+)?(?:/|$)",
    re.IGNORECASE,
)
_WS_CONTEXT_MARKERS = re.compile(
    r"\b(newWebSocket|WebSocketClient|WebSocketListener|"
    r'okhttp3\.WebSocket|"Upgrade",\s*"websocket")',
    re.IGNORECASE,
)


class InsecureWebSocketAgent(BaseAgent):
    """Flag WebSocket connections over ws:// (cleartext)."""

    AGENT_ID = "N_013"
    VULN_CLASS = "Cleartext WebSocket"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            seen_urls: set[str] = set()
            for m in _WS_URL_LITERAL.finditer(source):
                url = m.group(1)
                if url.lower() in seen_urls:
                    continue
                seen_urls.add(url.lower())

                # Require some WebSocket context in the file so a stray
                # ws:// URL in a comment / unrelated config doesn't fire.
                if not _WS_CONTEXT_MARKERS.search(source):
                    continue

                rel = str(java_file.relative_to(decompiled))
                is_loopback = bool(_LOOPBACK_HOSTS.match(url))
                severity = (
                    Severity.MEDIUM if is_loopback else Severity.HIGH
                )
                confidence = 0.65 if is_loopback else 0.90

                findings.append(self._make_finding(
                    vuln_class="Cleartext WebSocket",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "url": url[:200],
                        "loopback_host": is_loopback,
                        "issue": (
                            "WebSocket URL uses the ``ws://`` scheme "
                            "(cleartext). Auth headers and frame "
                            "payloads ride the connection in plain "
                            "text, observable to anyone on the "
                            "network path."
                            + (
                                " The host is loopback / emulator-only, "
                                "so the traffic doesn't leave the device "
                                "— still surfaced for audit completeness."
                                if is_loopback else ""
                            )
                        ),
                    },
                    recommendation=(
                        "Switch the URL to the ``wss://`` scheme and "
                        "confirm the server presents a valid TLS "
                        "certificate. If the backend requires a "
                        "different port for TLS (e.g. 443 vs 80), "
                        "update the URL accordingly. For staging-only "
                        "loopback URLs, guard the constant behind a "
                        "BuildConfig.DEBUG check."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        if not is_loopback
                        else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
                    ),
                ))
        return findings
