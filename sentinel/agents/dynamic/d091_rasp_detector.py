"""D_091 — Runtime Defense Analysis (RDA) RASP Detector.

Runs during Phase 2 (SAST pass). Inspects decompiled APK sources for
RASP/runtime-defense SDK signatures and maps each detected defense to
the Frida bypass scripts needed to circumvent it in an authorized lab.

Detected defenses are informational (severity: info) — they represent
hardening capability present in the app, not a vulnerability in
themselves. The findings act as a capability map for the pentest team.
"""
from __future__ import annotations

import logging

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.verify.rda.analyzer import DetectorResult, RdaReport, RuntimeDefenseAnalyzer

logger = logging.getLogger(__name__)

AGENT_ID = "D_091"


class D091RaspDetectorAgent(BaseAgent):
    AGENT_ID = "D_091"
    VULN_CLASS = "Runtime Defense (RASP) Detection"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        sources = self._context.sources or {}
        has_jadx = bool(sources.get("jadx_output"))
        has_manifest = bool(sources.get("manifest"))
        if not has_jadx and not has_manifest:
            logger.info("[D_091] No decompiled sources or manifest — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        sources = self._context.sources or {}
        analyzer = RuntimeDefenseAnalyzer()
        report: RdaReport = analyzer.analyze(sources)

        if report.detectors_detected == 0:
            logger.info("[D_091] No RASP SDKs detected in static sources")
            return []

        findings: list[Finding] = []

        for result in report.results:
            if result.status != "detected":
                continue
            findings.append(self._finding_for_result(result))

        findings.append(self._summary_finding(report))
        return findings

    # ------------------------------------------------------------------

    def _finding_for_result(self, result: DetectorResult) -> Finding:
        scripts_text = (
            ", ".join(result.bypass_scripts)
            if result.bypass_scripts
            else "none identified"
        )
        description = (
            f"The app statically references {result.name} ({result.category} SDK). "
            f"Signatures matched: {', '.join(result.evidence)}. "
            f"Lab bypass scripts available: {scripts_text}."
        )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.85,
            title=f"Runtime Defense Detected: {result.name}",
            description=description,
            evidence={
                "detector": result.detector_id,
                "bypass_scripts": result.bypass_scripts,
                "status": result.status,
                "matched_signatures": result.evidence,
            },
            recommendation=(
                "This is an informational finding. The detected RASP SDK "
                "provides hardening that a tester must account for during "
                "dynamic analysis. Use the listed Frida bypass scripts in "
                "an authorized lab environment to proceed with assessment."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MASVS-RESILIENCE-1",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        )

    def _summary_finding(self, report: RdaReport) -> Finding:
        detected_names = [
            r.name for r in report.results if r.status == "detected"
        ]
        description = (
            f"RDA scan complete. {report.detectors_run} RASP detectors evaluated; "
            f"{report.detectors_detected} SDK(s) found: {', '.join(detected_names)}. "
        )
        if report.bypass_command_preview:
            description += (
                f"Consolidated bypass command (authorized lab only): "
                f"{report.bypass_command_preview}"
            )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.90,
            title="RDA Summary: Runtime Defense Capability Map",
            description=description,
            evidence=report.as_dict(),
            recommendation=(
                "Review the detected RASP defenses before starting dynamic "
                "analysis. Apply the corresponding Frida bypass scripts in "
                "sequence for a complete assessment. Backend-validated "
                "attestation (e.g. Approov, Play Integrity) requires "
                "server-side configuration — client bypass alone is "
                "insufficient."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MASVS-RESILIENCE-1",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        )
