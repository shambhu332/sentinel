"""D_041 — Notification / Toast Flooding (Tap-Jacking Setup).

A burst of notifications or toasts dispatched in quick succession is
the canonical setup for a tap-jacking attack: each post draws the
user's attention to a particular screen region, and the attacker's
overlay slides into the same region while the user's tap is still
in flight. The technique also doubles as a generic UX-abuse pattern
(ad pop-spam, fake-system-alert).

D_012 ``NotificationLeakAgent`` looks at *content* of individual
notifications. This agent looks at *volume* — the rate of
``NotificationManager.notify`` calls in a single capture.

Detection
---------

We re-consume the ``notification.posted`` event already emitted by
D_012's existing hook. No new Frida hook required. Payload field
used:

* ``timestamp`` — the FridaHookEvent's wall-clock timestamp.

Severity matrix:

* **HIGH** — >= 10 ``notification.posted`` events with timestamps
  inside a single 5-second window.
* **MEDIUM** — >= 5 events inside a 5-second window (warning rate,
  not yet attack-shape).
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_WINDOW_S = 5.0
_HIGH_THRESHOLD = 10
_MEDIUM_THRESHOLD = 5


class NotificationFloodAgent(BaseAgent):
    """D_041: catch high-rate notification bursts."""

    AGENT_ID = "D_041"
    VULN_CLASS = "Notification / Toast Flood"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_041] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # Slide a window across the timestamp stream and record the
        # highest count seen.
        window: deque[float] = deque()
        peak = 0
        peak_window_start = 0.0
        peak_window_end = 0.0
        post_count = 0

        for ev in capture.events:
            if ev.kind != "notification.posted":
                continue
            ts = float(ev.timestamp or 0.0)
            window.append(ts)
            while window and (ts - window[0]) > _WINDOW_S:
                window.popleft()
            post_count += 1
            if len(window) > peak:
                peak = len(window)
                peak_window_start = window[0]
                peak_window_end = ts

        if peak < _MEDIUM_THRESHOLD:
            return []

        severity = (
            Severity.HIGH if peak >= _HIGH_THRESHOLD else Severity.MEDIUM
        )
        sample = {
            "peak_count": peak,
            "window_seconds": _WINDOW_S,
            "window_start": peak_window_start,
            "window_end": peak_window_end,
            "total_notifications": post_count,
        }
        return [self._finding(sample, severity)]

    def _finding(self, sample: dict[str, Any], severity: Severity) -> Finding:
        threshold = (
            _HIGH_THRESHOLD if severity == Severity.HIGH
            else _MEDIUM_THRESHOLD
        )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.75 if severity == Severity.HIGH else 0.55,
            evidence={
                "issue": (
                    f"The application posted at least {threshold} "
                    f"notifications inside a {int(_WINDOW_S)}-second "
                    "window during this capture. A burst of this "
                    "shape is the canonical setup for tap-jacking "
                    "(the user's attention is drawn to a region just "
                    "before an attacker's overlay arrives) and is "
                    "also flagged by Play Console as a UX-abuse "
                    "pattern."
                ),
                "samples": [sample],
                "vector": (
                    "Slid a 5-second window across "
                    "notification.posted timestamps and recorded the "
                    "peak post count."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Rate-limit notification dispatch. Group related "
                "notifications via NotificationManager.notifyGroup / "
                "setGroup so the user sees a single summary instead "
                "of a burst. Reserve foreground-service "
                "notifications for genuinely ongoing work."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        )
