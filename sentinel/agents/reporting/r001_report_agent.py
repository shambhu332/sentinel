"""R_001: Professional VAPT Report Generator.

Pulls every finding for the current session out of memory, runs them
through the ``builder`` to produce a ``ReportData``, then renders
three artifacts side-by-side in ``<workspace>/reports/``:

* ``VAPT_Report_<session>.md`` — GitHub-flavoured Markdown
* ``VAPT_Report_<session>.html`` — single-file styled HTML
* ``VAPT_Report_<session>.json`` — machine-readable export

Each finding's section pulls the RAG-sourced ``_rag_mapping`` and
``_rag_passage_ids`` that the LLM triager persisted during Phase 3,
so the report renders authoritative standards references inline
without re-querying the knowledge base.

The agent itself emits a single INFO meta-finding pointing at the
three artifacts so the orchestrator's summary table and the API can
surface the report locations.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sentinel.agents.base import BaseAgent
from sentinel.agents.reporting.builder import build_coverage, build_report_data
from sentinel.agents.reporting.enrich import enrich_sections
from sentinel.agents.reporting.models import (
    BUCKET_AI_POWERED,
    BUCKET_STATIC_TOOL,
    ReportData,
    bucket_for_section,
)
from sentinel.agents.reporting.templates import render_html, render_markdown
from sentinel.core.finding import Finding, Severity, TriageState

logger = logging.getLogger(__name__)


class ReportGeneratorAgent(BaseAgent):
    """Generate the VAPT report artifacts at the end of a scan."""

    AGENT_ID = "R_001"
    VULN_CLASS = "VAPT Report Generation"
    PHASE = "Phase 8"

    async def is_applicable(self) -> bool:
        """Always run after scan completes."""
        return True

    async def analyze(self) -> list[Finding]:
        all_findings = await self.memory.get_findings(
            session_id=self.context.session_id,
        )
        if not all_findings:
            return []

        # Stamp every finding with a CVSS 3.1 vector + base score before
        # the report builder gets them. CVSS is deterministic — no LLM
        # involved — so this is safe to do unconditionally.
        try:
            from sentinel.reports.cvss import stamp_all
            stamp_all(all_findings)
        except Exception:  # noqa: BLE001
            logger.exception("R_001: CVSS stamping failed; reports will omit scores")

        report_findings = self._select_report_findings(all_findings)
        data = build_report_data(
            findings=report_findings,
            package=self.context.manifest.get("package") or "(unknown)",
            version=self.context.manifest.get("version_name") or "(unknown)",
            session_id=self.context.session_id,
            apk_sha256=self.context.apk_sha256 or "",
            apk_size_bytes=self.context.apk_size_bytes or 0,
            generated_at=datetime.now(timezone.utc),
            coverage=build_coverage(
                all_findings,
                app_profile=self.context.app_profile,
            ),
        )

        # Narrative enrichment via the free LLM router (Groq → Cerebras
        # → Ollama). Falls back to deterministic boilerplate when every
        # provider is unavailable — the report still renders cleanly.
        router = await self._get_router()
        try:
            await enrich_sections(data.sections, router)
        except Exception as exc:  # noqa: BLE001
            logger.warning("R_001: narrative enrichment failed: %s", exc)
            await enrich_sections(data.sections, None)
        finally:
            if router is not None:
                try:
                    await router.close()
                except Exception:  # noqa: BLE001
                    pass

        artifacts = self._write_artifacts(data)
        return [self._meta_finding(data, artifacts)]

    async def _get_router(self):
        """Build a FreeProviderRouter, or return None if unavailable."""
        try:
            from sentinel.llm.router import FreeProviderRouter
            return FreeProviderRouter(force_local=self.context.is_private)
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "R_001: free LLM router unavailable, using boilerplate (%s)",
                exc,
            )
            return None

    # ---------- selection ----------

    @staticmethod
    def _select_report_findings(findings: list[Finding]) -> list[Finding]:
        """Pick the findings that belong in the client-deliverable report.

        We include everything the triager either verified or left
        uncertain — false positives stay out so the client doesn't
        see noise. When triage was skipped (``--no-triage``) we
        include everything except INFO-only meta findings.
        """
        keep: list[Finding] = []
        for f in findings:
            if f.severity == Severity.INFO:
                continue
            if f.triage == TriageState.FALSE_POSITIVE:
                continue
            keep.append(f)
        return keep

    # ---------- IO ----------

    def _write_artifacts(self, data: ReportData) -> dict[str, Path]:
        report_dir = self.context.workspace / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        stem = f"VAPT_Report_{self.context.session_id}"

        md_path = report_dir / f"{stem}.md"
        html_path = report_dir / f"{stem}.html"
        json_path = report_dir / f"{stem}.json"

        try:
            md_path.write_text(render_markdown(data), encoding="utf-8")
        except OSError as exc:
            logger.warning("R_001: failed to write markdown report: %s", exc)
            md_path = report_dir / "(markdown unavailable)"
        try:
            html_path.write_text(render_html(data), encoding="utf-8")
        except OSError as exc:
            logger.warning("R_001: failed to write HTML report: %s", exc)
            html_path = report_dir / "(html unavailable)"
        try:
            json_path.write_text(
                json.dumps(self._json_payload(data), indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("R_001: failed to write JSON report: %s", exc)
            json_path = report_dir / "(json unavailable)"

        # SARIF v2.1.0 — for GitHub Code Scanning / Azure DevOps ingest.
        sarif_path = report_dir / f"{stem}.sarif"
        try:
            from sentinel.reports.sarif import render_sarif_json
            findings_for_sarif = [s.finding for s in data.sections]
            sarif_path.write_text(
                render_sarif_json(findings_for_sarif, data.session_id),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("R_001: failed to write SARIF report: %s", exc)
            sarif_path = report_dir / "(sarif unavailable)"

        return {
            "markdown": md_path, "html": html_path,
            "json": json_path, "sarif": sarif_path,
        }

    # Bucket classification lives in sentinel.agents.reporting.models so
    # the renderers, this agent, and the frontend predicate all agree.
    # Re-exposed as a static method for back-compat with existing callers.
    _classify_section = staticmethod(bucket_for_section)

    @classmethod
    def _json_payload(cls, data: ReportData) -> dict:
        sections_serialised: list[dict] = []
        ai_powered: list[dict] = []
        static_tool: list[dict] = []
        for s in data.sections:
            bucket = cls._classify_section(s)
            entry = {
                **s.finding.model_dump(mode="json"),
                "finding_id": s.finding.finding_id,
                "rag_mapping": s.rag_mapping,
                "rag_passage_ids": s.rag_passage_ids,
                "triage_explanation": s.triage_explanation,
                "report_bucket": bucket,
            }
            sections_serialised.append(entry)
            (ai_powered if bucket == BUCKET_AI_POWERED else static_tool).append(entry)

        return {
            "package": data.package,
            "version": data.version,
            "session_id": data.session_id,
            "apk_sha256": data.apk_sha256,
            "apk_size_bytes": data.apk_size_bytes,
            "generated_at": data.generated_at.isoformat(timespec="seconds"),
            "severity_counts": data.severity_counts,
            "risk": {
                "score": data.risk.score,
                "band": data.risk.band,
                "summary": data.risk.summary,
            },
            "references": [
                {"source": r.source, "control_id": r.control_id, "title": r.title}
                for r in data.references
            ],
            "findings": sections_serialised,
            "findings_by_bucket": {
                "ai_powered": ai_powered,
                "static_tool": static_tool,
            },
            "bucket_counts": {
                "ai_powered": len(ai_powered),
                "static_tool": len(static_tool),
            },
        }

    def _meta_finding(
        self,
        data: ReportData,
        artifacts: dict[str, Path],
    ) -> Finding:
        return self._make_finding(
            vuln_class="VAPT Report Generated",
            severity=Severity.INFO,
            confidence=1.0,
            evidence={
                "report_markdown": str(artifacts["markdown"]),
                "report_html": str(artifacts["html"]),
                "report_json": str(artifacts["json"]),
                "total_findings": data.total_findings,
                "risk_score": data.risk.score,
                "risk_band": data.risk.band,
                "severity_counts": data.severity_counts,
                "references_count": len(data.references),
            },
            recommendation=(
                "Open the generated HTML report for the client-facing "
                "deliverable, or the markdown for GitHub / HackerOne "
                "submission. The JSON file is the machine-readable "
                "export."
            ),
        )
