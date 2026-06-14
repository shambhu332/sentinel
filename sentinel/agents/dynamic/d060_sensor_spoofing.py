"""D_060 — Sensor & location spoofing (Dynamic Testing Target)."""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_SENSOR_MARKERS_RE = re.compile(
    r"\bLocationManager\b|\bFusedLocationProviderClient\b"
    r"|\bSensorManager\b|\bSensorEventListener\b"
)
_GEOFENCE_RE = re.compile(
    r"\bGeofenc\w*\b|\bisWithin\w*\b|\.distanceTo\s*\("
)
_STEP_PEDOMETER_RE = re.compile(
    r"TYPE_STEP_COUNTER|TYPE_STEP_DETECTOR"
)


class SensorSpoofingAgent(BaseAgent):
    AGENT_ID = "D_060"
    VULN_CLASS = "Sensor / Location Spoof (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        sensor_files: set[str] = set()
        geofence_files: set[str] = set()
        step_files: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _SENSOR_MARKERS_RE.search(text):
                rel = str(path.relative_to(root))
                sensor_files.add(rel)
                if _GEOFENCE_RE.search(text):
                    geofence_files.add(rel)
                if _STEP_PEDOMETER_RE.search(text):
                    step_files.add(rel)
        if not sensor_files:
            return []
        severity = (
            Severity.HIGH if (geofence_files or step_files)
            else Severity.MEDIUM
        )
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.65,
            recommendation=(
                f"{len(sensor_files)} sensor / location read site(s). "
                f"{len(geofence_files)} geofence check(s) and "
                f"{len(step_files)} pedometer reader(s) — both are commonly "
                "used as trust signals. The Frida hook will replace "
                "LocationManager.getLastKnownLocation, "
                "FusedLocationProviderClient.getLastLocation, and "
                "SensorEventListener.onSensorChanged with attacker-"
                "controlled values. Move all such decisions server-side; "
                "client sensors are trivially spoofable."
            ),
            evidence={
                "sensor_files": sorted(sensor_files)[:10],
                "geofence_files": sorted(geofence_files)[:5],
                "step_files": sorted(step_files)[:5],
                "dynamic_target": True,
                "frida_payload": {
                    "hook_targets": [
                        "android.location.LocationManager.getLastKnownLocation",
                        "com.google.android.gms.location.FusedLocationProviderClient.getLastLocation",
                        "android.hardware.SensorEventListener.onSensorChanged",
                    ],
                    "spoof_location": {"lat": 37.7749, "lon": -122.4194, "accuracy": 5.0},
                    "spoof_step_count": 100000,
                    "safety_budget": {
                        "max_actions_total": 20,
                        "max_actions_per_sec": 2,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["SensorSpoofingAgent"]
