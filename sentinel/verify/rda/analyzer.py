"""RDA static analyzer — detects RASP SDK presence from decompiled APK sources."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sentinel.verify.rda.catalog import BYPASS_PROFILES, DETECTOR_CATALOG

# Categories whose detectors are inherently server-side/backend — mark
# not_applicable regardless of whether signatures appear in the APK.
_NOT_APPLICABLE_CATEGORIES = frozenset({"not-applicable"})

# Approov is backend-validated even though its client SDK ships in the APK.
_FORCE_NOT_APPLICABLE = frozenset({"approov", "contrast", "imperva", "dynatrace", "accuknox"})


@dataclass
class DetectorResult:
    detector_id: str
    name: str
    category: str
    status: Literal["detected", "not_detected", "not_applicable", "error"]
    evidence: list[str] = field(default_factory=list)
    bypass_scripts: list[str] = field(default_factory=list)


@dataclass
class RdaReport:
    detectors_run: int
    detectors_detected: int
    results: list[DetectorResult]
    bypass_command_preview: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "detectors_run": self.detectors_run,
            "detectors_detected": self.detectors_detected,
            "bypass_command_preview": self.bypass_command_preview,
            "results": [
                {
                    "detector_id": r.detector_id,
                    "name": r.name,
                    "category": r.category,
                    "status": r.status,
                    "evidence": r.evidence,
                    "bypass_scripts": r.bypass_scripts,
                }
                for r in self.results
            ],
        }

    def summary_text(self) -> str:
        detected = [r for r in self.results if r.status == "detected"]
        not_applicable = [r for r in self.results if r.status == "not_applicable"]
        lines = [
            f"RDA: {self.detectors_run} detectors run, "
            f"{self.detectors_detected} detected.",
        ]
        if detected:
            names = ", ".join(r.name for r in detected)
            lines.append(f"Detected SDKs: {names}.")
        if not_applicable:
            names = ", ".join(r.name for r in not_applicable)
            lines.append(f"Not applicable (server-side): {names}.")
        if self.bypass_command_preview:
            lines.append(f"Bypass preview: {self.bypass_command_preview}")
        return " ".join(lines)


class RuntimeDefenseAnalyzer:
    """Static analysis pass — inspects decompiled APK sources for RASP SDK signatures."""

    def analyze(self, ctx_sources: dict[str, Any]) -> RdaReport:
        corpus = self._build_corpus(ctx_sources)
        results: list[DetectorResult] = []

        for entry in DETECTOR_CATALOG:
            det_id: str = entry["id"]
            category: str = entry["category"]

            if category in _NOT_APPLICABLE_CATEGORIES or det_id in _FORCE_NOT_APPLICABLE:
                results.append(DetectorResult(
                    detector_id=det_id,
                    name=entry["name"],
                    category=category,
                    status="not_applicable",
                ))
                continue

            signatures: list[str] = entry.get("detection_method") or []
            if not signatures:
                results.append(DetectorResult(
                    detector_id=det_id,
                    name=entry["name"],
                    category=category,
                    status="not_applicable",
                ))
                continue

            matched = [sig for sig in signatures if sig and sig.lower() in corpus]

            if matched:
                profile = BYPASS_PROFILES.get(det_id, {})
                bypass_scripts: list[str] = profile.get("scripts") or []
                results.append(DetectorResult(
                    detector_id=det_id,
                    name=entry["name"],
                    category=category,
                    status="detected",
                    evidence=matched,
                    bypass_scripts=bypass_scripts,
                ))
            else:
                results.append(DetectorResult(
                    detector_id=det_id,
                    name=entry["name"],
                    category=category,
                    status="not_detected",
                ))

        detectors_run = sum(1 for r in results if r.status != "not_applicable")
        detectors_detected = sum(1 for r in results if r.status == "detected")
        bypass_preview = self._build_bypass_preview(results)

        return RdaReport(
            detectors_run=detectors_run,
            detectors_detected=detectors_detected,
            results=results,
            bypass_command_preview=bypass_preview,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_corpus(self, ctx_sources: dict[str, Any]) -> str:
        parts: list[str] = []

        jadx = ctx_sources.get("jadx_output")
        if isinstance(jadx, str):
            parts.append(jadx)
        elif isinstance(jadx, (list, tuple)):
            parts.extend(str(s) for s in jadx)

        manifest = ctx_sources.get("manifest")
        if isinstance(manifest, dict):
            import json
            parts.append(json.dumps(manifest))
        elif isinstance(manifest, str):
            parts.append(manifest)

        apktool = ctx_sources.get("apktool_output")
        if isinstance(apktool, str):
            # apktool_output is typically a directory path; we accept
            # pre-read string blobs here for static analysis.
            parts.append(apktool)

        return "\n".join(parts).lower()

    def _build_bypass_preview(self, results: list[DetectorResult]) -> str:
        all_scripts: list[str] = []
        seen: set[str] = set()
        for r in results:
            if r.status == "detected":
                for s in r.bypass_scripts:
                    if s not in seen:
                        all_scripts.append(s)
                        seen.add(s)

        if not all_scripts:
            return ""

        script_flags = " ".join(f"-l {s}" for s in all_scripts)
        return f"frida -U {script_flags} com.target.app"
