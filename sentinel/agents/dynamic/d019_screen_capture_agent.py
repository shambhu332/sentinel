"""D_019 — MediaProjection / Screen-Capture Observer.

Android's MediaProjection API lets an app capture the device's
screen — every other app's UI, the keyboard the user is typing on,
the lock screen, and so on. The user grants per-session consent
through the system dialog, but once granted:

* The app keeps reading frames until it calls ``stop()`` — there is
  no foreground gating after the prompt.
* Frames can be saved to disk, encoded with ``MediaRecorder``,
  uploaded over the network, or fed into ML pipelines.
* On Android < 14 the consent grant survives an Activity finish
  (screen capture continues running in a Service).

Legitimate uses: screen recorders, presentation tools, accessibility
narrators. Banking-Trojan-grade uses: silent capture of every screen
the user views, including third-party banking apps' balances, OTPs,
and password fields.

Detection
---------

We consume Frida events of kind:

* ``screen.projection_started`` — emitted on
  ``MediaProjectionManager.getMediaProjection`` succeeding.
  Payload: ``{result_code, intent_extras}``.
* ``screen.virtual_display_created`` — emitted on
  ``MediaProjection.createVirtualDisplay``. Payload:
  ``{width, height, surface_type, dpi}``.
* ``screen.image_reader_used`` — emitted on
  ``ImageReader.acquireLatestImage`` / ``acquireNextImage``.
* ``screen.media_recorder_set_video_source`` — emitted when the
  recorder is configured with ``setVideoSource(SURFACE)``.
* ``screen.image_uploaded`` — emitted when an image / video file
  produced by the projection session is uploaded over HTTP / HTTPS.
  Heuristic — see :mod:`d013_third_party_pii_leak_agent` for the
  network correlator.

Findings:

* **HIGH** — projection started AND at least one VirtualDisplay
  created AND ImageReader frame acquisition observed. The capture
  pipeline is alive.
* **CRITICAL** — same as HIGH, AND a MediaRecorder with
  ``VideoSource.SURFACE`` was configured (the session is being
  encoded to a persistent file or stream).
* **MEDIUM** — projection started but no frame acquisition
  observed in the session — possibly a defensive check, possibly
  the user denied consent. Worth review.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class ScreenCaptureAgent(BaseAgent):
    """D_019: classify the runtime screen-capture pipeline."""

    AGENT_ID = "D_019"
    VULN_CLASS = "Screen Capture / MediaProjection Pipeline"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_019] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        projection_started = False
        virtual_displays: list[dict[str, Any]] = []
        image_reads: int = 0
        recorder_surface = False

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "screen.projection_started":
                projection_started = True
            elif ev.kind == "screen.virtual_display_created":
                virtual_displays.append({
                    "width": payload.get("width"),
                    "height": payload.get("height"),
                    "surface_type": payload.get("surface_type"),
                    "dpi": payload.get("dpi"),
                })
            elif ev.kind == "screen.image_reader_used":
                image_reads += 1
            elif ev.kind == "screen.media_recorder_set_video_source":
                if str(payload.get("source")) in ("2", "SURFACE"):
                    recorder_surface = True

        if not projection_started:
            return []

        pipeline_active = bool(virtual_displays) and image_reads > 0

        if pipeline_active and recorder_surface:
            return [self._encoded_finding(
                virtual_displays, image_reads,
            )]
        if pipeline_active:
            return [self._streaming_finding(
                virtual_displays, image_reads,
            )]
        return [self._consent_only_finding()]

    def _encoded_finding(
        self,
        displays: list[dict[str, Any]],
        image_reads: int,
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application configured a MediaProjection "
                    "session, created a VirtualDisplay, read frames "
                    "with ImageReader, AND attached a MediaRecorder "
                    "configured with VideoSource.SURFACE. This is a "
                    "fully-encoded screen-recording pipeline — every "
                    "third-party app on screen (including banking, "
                    "messaging, OTP screens) is captured to a "
                    "persistent file or stream."
                ),
                "virtual_displays": displays[:3],
                "image_reads_observed": image_reads,
                "vector": (
                    "Frida hooks on MediaProjectionManager."
                    "getMediaProjection, MediaProjection."
                    "createVirtualDisplay, ImageReader."
                    "acquireLatestImage, and MediaRecorder."
                    "setVideoSource."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Gate every frame read on an explicit user-visible "
                "indicator (persistent foreground notification + "
                "active recording badge). Stop the projection on "
                "Activity.onPause unless the feature is explicitly a "
                "background screen recorder. On Android 14+ use the "
                "scoped MediaProjection API "
                "(``createScreenCaptureIntent`` with the "
                "``isSingleApp`` host-app filter) so the session is "
                "constrained to the host's own UI. Never persist or "
                "upload captured frames without a per-frame user "
                "gesture."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        )

    def _streaming_finding(
        self,
        displays: list[dict[str, Any]],
        image_reads: int,
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application configured a MediaProjection "
                    "session, created a VirtualDisplay, and read "
                    "frames with ImageReader. The capture pipeline "
                    "is alive even though no MediaRecorder was "
                    "observed — the frames are presumably going "
                    "into a custom encoder, an ML pipeline, or an "
                    "in-memory upload."
                ),
                "virtual_displays": displays[:3],
                "image_reads_observed": image_reads,
                "vector": (
                    "Frida hooks captured projection start, virtual "
                    "display creation, and frame acquisition; no "
                    "MediaRecorder surface attached in the session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "If the feature is screen recording, attach a "
                "MediaRecorder so the user can see the resulting "
                "file. If the feature is a screen reader / "
                "accessibility narrator, drop the raw frame access "
                "and use the AccessibilityService text channel "
                "instead. Stop the projection on Activity.onPause."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        )

    def _consent_only_finding(self) -> Finding:
        return self._make_finding(
            vuln_class="Screen Capture Consent Without Frame Read",
            severity=Severity.MEDIUM,
            confidence=0.70,
            evidence={
                "issue": (
                    "MediaProjection consent was granted at runtime "
                    "but the session never read any frames during "
                    "the Frida capture window. This may be a "
                    "defensive pre-flight check, a denied consent, "
                    "or capture happening outside the observation "
                    "window. Worth manual review to confirm whether "
                    "frames are read in a later code path."
                ),
                "vector": (
                    "Frida hook on MediaProjectionManager."
                    "getMediaProjection observed the result_code=OK "
                    "path; no subsequent ImageReader / "
                    "VirtualDisplay activity in the session."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Confirm the consent grant is gated behind an "
                "explicit user action (a recording-button tap) and "
                "that no code path silently triggers it on app "
                "launch."
            ),
            owasp="M10: Extraneous Functionality",
            masvs="MSTG-CODE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        )
