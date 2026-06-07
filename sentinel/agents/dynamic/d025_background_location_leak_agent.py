"""D_025 — Background Location Request from Non-Foreground Context.

Android 10 introduced the ``ACCESS_BACKGROUND_LOCATION`` permission to
make silent background-location tracking visible to the user. Apps
sidestep that gate two ways at runtime:

1. **Request location from a Service / BroadcastReceiver** while the
   process is *not* in a foreground-importance state. The ``location``
   APIs do not themselves enforce the foreground-only contract — the
   OS only rejects the *delivery* of updates when the process drops
   below ``IMPORTANCE_FOREGROUND_SERVICE`` on later API levels, and
   even then policy varies wildly between OEMs.

2. **Hop through a JobScheduler / WorkManager worker** that requests
   one fix and exits. Each individual fix is short enough that the
   foreground-importance heuristic doesn't trip, but the periodic
   cadence amounts to a track.

Detection
---------

We consume one Frida event kind:

* ``location.update_requested`` — emitted from
  ``LocationManager.requestLocationUpdates`` (all overloads) and
  ``FusedLocationProviderClient.requestLocationUpdates`` (Play
  Services). Payload:
  ``{api, caller_class, importance, interval_ms, priority, stack}``.

``importance`` is the value from ``ActivityManager.RunningAppProcessInfo
.importance`` at the moment the hook fires:

* ``100`` IMPORTANCE_FOREGROUND
* ``125`` IMPORTANCE_FOREGROUND_SERVICE
* ``200`` IMPORTANCE_VISIBLE
* ``230`` IMPORTANCE_PERCEPTIBLE
* ``300`` IMPORTANCE_SERVICE
* ``400`` IMPORTANCE_CACHED / BACKGROUND

Severity matrix:

* **HIGH** — importance >= 300 (SERVICE / CACHED / BACKGROUND) **and**
  the caller class is a Service, Receiver, or Worker subclass. This
  is the silent-tracking primitive — the user's foreground state is
  irrelevant, the app is sampling location from a background context.
* **MEDIUM** — importance >= 300 but the caller class is unclear,
  *or* importance is 230 (PERCEPTIBLE) with a Service / Receiver
  caller. Lower confidence the request is truly background-only.
* (INFO is dropped — we only want the cases that warrant follow-up.)
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Mirrors android.app.ActivityManager.RunningAppProcessInfo constants.
IMPORTANCE_FOREGROUND_SERVICE = 125
IMPORTANCE_VISIBLE = 200
IMPORTANCE_PERCEPTIBLE = 230
IMPORTANCE_SERVICE = 300


_BACKGROUND_CALLER_HINTS = (
    "Service",
    "Receiver",
    "Worker",
    "JobService",
    "JobIntentService",
    "WorkRequest",
)

_FOREGROUND_CALLER_HINTS = (
    "Activity",
    "Fragment",
    "Dialog",
)


class BackgroundLocationLeakAgent(BaseAgent):
    """D_025: catch location requests from non-foreground contexts."""

    AGENT_ID = "D_025"
    VULN_CLASS = "Background Location Request"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_025] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        high_hits: list[dict[str, Any]] = []
        medium_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "location.update_requested":
                continue
            payload = ev.payload or {}
            importance = _coerce_int(payload.get("importance"))
            caller = str(payload.get("caller_class") or "")
            caller_kind = _classify_caller(caller)

            sample = {
                "api": str(payload.get("api") or ""),
                "caller_class": caller[:200],
                "caller_kind": caller_kind,
                "importance": importance,
                "interval_ms": payload.get("interval_ms"),
                "priority": payload.get("priority"),
                "stack": payload.get("stack"),
            }

            if importance is None:
                # Can't classify without an importance reading. Skip
                # rather than fire a noisy finding.
                continue

            if importance >= IMPORTANCE_SERVICE and caller_kind == "background":
                high_hits.append(sample)
            elif importance >= IMPORTANCE_SERVICE:
                medium_hits.append(sample)
            elif (importance >= IMPORTANCE_PERCEPTIBLE
                    and caller_kind == "background"):
                medium_hits.append(sample)

        findings: list[Finding] = []
        if high_hits:
            findings.append(self._high_finding(high_hits))
        if medium_hits:
            findings.append(self._medium_finding(medium_hits))
        return findings

    def _high_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.88,
            evidence={
                "issue": (
                    "The application requested location updates from a "
                    "Service / BroadcastReceiver / Worker class while "
                    "the process importance was at or below "
                    "IMPORTANCE_SERVICE — the user has no UI on screen "
                    "tying the request to their action. This is the "
                    "silent-tracking primitive ACCESS_BACKGROUND_"
                    "LOCATION was introduced to surface."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on LocationManager.requestLocationUpdates "
                    "and FusedLocationProviderClient.requestLocationUpdates "
                    "captured ActivityManager.RunningAppProcessInfo."
                    "importance at call time."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move the location request onto a foreground Service "
                "with the ``location`` foregroundServiceType set, and "
                "post a persistent notification while it runs. If the "
                "use-case is a periodic background poll, switch to "
                "FusedLocationProviderClient with a low-frequency "
                "PRIORITY_BALANCED_POWER_ACCURACY request and request "
                "ACCESS_BACKGROUND_LOCATION explicitly so the user is "
                "informed."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-PLATFORM-1",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _medium_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Background-Importance Location Request (Caller Unclear)",
            severity=Severity.MEDIUM,
            confidence=0.65,
            evidence={
                "issue": (
                    "Location updates were requested while the process "
                    "importance suggested the app was not actively in "
                    "the foreground. Either the calling class could "
                    "not be classified or the importance was at the "
                    "PERCEPTIBLE boundary, so we cannot be certain "
                    "this is a silent track — but it warrants review."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on requestLocationUpdates captured "
                    "process importance at call time."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Confirm the request lives on a code path that runs "
                "while the user has a visible foreground experience. "
                "If it doesn't, migrate it to a foreground Service "
                "with ``location`` foregroundServiceType."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-PLATFORM-1",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )


def _classify_caller(caller_class: str) -> str:
    if not caller_class:
        return "unknown"
    for hint in _BACKGROUND_CALLER_HINTS:
        if hint in caller_class:
            return "background"
    for hint in _FOREGROUND_CALLER_HINTS:
        if hint in caller_class:
            return "foreground"
    return "unknown"


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
