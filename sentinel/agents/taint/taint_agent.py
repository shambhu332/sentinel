"""TAINT_001 — Data-Flow Taint Analysis Agent.

Wraps the tree-sitter tracer in the BaseAgent contract. The tracer
does the analysis; this agent renders each :class:`TaintFlow` into a
:class:`Finding` whose ``evidence`` carries the full source → … → sink
trace with file:line + code excerpt for every hop. Bumping the user
from a single line of code to a complete trail is the difference
between a triage-worthy finding and noise.

Failure modes are all soft: missing decompiled directory, missing
tree-sitter dependency, parse errors, per-file timeouts — each is
logged and downgraded to "no findings from this file" so the agent
never tanks the scan pipeline.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.agents.taint.taint_config import SinkSpec
from sentinel.agents.taint.tracer import (
    DEFAULT_PER_FILE_TIMEOUT_S,
    MAX_IPA_DEPTH,
    TaintFlow,
    TraceHop,
    analyse_tree,
)
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Hard cap on how many flows we emit per scan. Some pathological apps
# (especially React-Native bridges) generate hundreds of low-confidence
# log flows that swamp the report. Keep the high-confidence ones and
# drop the rest — the cap is comfortably above what a manual triager
# could review.
_MAX_FINDINGS_PER_SCAN = 200


class TaintAgent(BaseAgent):
    """TAINT_001: inter-procedural data-flow tracer for Android Java."""

    AGENT_ID = "TAINT_001"
    VULN_CLASS = "TAINT_FLOW"
    PHASE = "Phase 2"
    CATEGORY = "DATA_FLOW"

    async def is_applicable(self) -> bool:
        ctx = self._context
        try:
            import tree_sitter  # noqa: F401
            import tree_sitter_java  # noqa: F401
        except ImportError:
            self._log.warning(
                "[TAINT_001] tree-sitter / tree-sitter-java not installed "
                "— skipping. Install via `poetry add tree-sitter "
                "tree-sitter-java`.",
            )
            return False
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            self._log.info(
                "[TAINT_001] no decompiled directory — skipping",
            )
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = self._effective_root(ctx.decompiled_dir)
        if root is None:
            return []

        cfg = self._config if isinstance(self._config, dict) else {}
        per_file_timeout_s = float(
            cfg.get("per_file_timeout_s", DEFAULT_PER_FILE_TIMEOUT_S),
        )
        max_ipa_depth = int(cfg.get("max_ipa_depth", MAX_IPA_DEPTH))

        self._log.info(
            "[TAINT_001] analysing %s (per_file_timeout=%.1fs, max_ipa_depth=%d)",
            root, per_file_timeout_s, max_ipa_depth,
        )
        flows = analyse_tree(
            root_dir=root,
            per_file_timeout_s=per_file_timeout_s,
            max_ipa_depth=max_ipa_depth,
        )
        if not flows:
            self._log.info("[TAINT_001] no taint flows detected")
            return []

        # Sort: highest depth-0 confidence first, then by sink line so
        # the cap (when reached) keeps the most signal.
        flows.sort(key=lambda f: (-f.confidence, f.sink.line))
        flows = flows[:_MAX_FINDINGS_PER_SCAN]

        findings: list[Finding] = []
        for flow in flows:
            try:
                findings.append(self._flow_to_finding(flow))
            except Exception as e:  # noqa: BLE001
                self._log.debug(
                    "[TAINT_001] dropping malformed flow %s: %s",
                    flow.vuln_class, e,
                )
        self._log.info(
            "[TAINT_001] emitted %d taint findings", len(findings),
        )
        return findings

    # ---------- Helpers ----------

    @staticmethod
    def _effective_root(decompiled_dir: Path | None) -> Path | None:
        """JADX writes its Java tree under either ``<dir>`` or
        ``<dir>/sources``. Pick whichever exists so we don't burn time
        recursing past the resource tree.
        """
        if decompiled_dir is None:
            return None
        sources = decompiled_dir / "sources"
        if sources.exists() and sources.is_dir():
            return sources
        return decompiled_dir

    def _flow_to_finding(self, flow: TaintFlow) -> Finding:
        sink_spec = flow.sink_spec
        if sink_spec is None:  # pragma: no cover — tracer always sets it
            raise ValueError("flow missing sink_spec")
        evidence = self._render_evidence(flow)

        severity = self._adjust_severity(sink_spec.severity, flow.confidence)
        recommendation = self._recommendation_for(flow, sink_spec)
        code_snippet = {
            "file": flow.sink.file,
            "line": flow.sink.line,
            "start_col": flow.sink.start_col,
            "end_col": flow.sink.end_col,
            "content": flow.sink.code,
        }
        return self._make_finding(
            vuln_class=sink_spec.vuln_class,
            severity=severity,
            confidence=flow.confidence,
            evidence=evidence,
            code_snippet=code_snippet,
            owasp=sink_spec.owasp,
            masvs=sink_spec.masvs,
            recommendation=recommendation,
        )

    @staticmethod
    def _adjust_severity(base: Severity, confidence: float) -> Severity:
        """Downgrade severity by one notch for low-confidence flows
        so a depth-3 hint doesn't show up as Critical and outrank a
        verified depth-0 finding.
        """
        if confidence >= 0.85:
            return base
        ladder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO]
        try:
            idx = ladder.index(base)
        except ValueError:
            return base
        return ladder[min(idx + 1, len(ladder) - 1)]

    @staticmethod
    def _classify_flow(flow: TaintFlow) -> tuple[str, str]:
        """Apply the 8 DragonJAR decision rules and return (status, note).

        Rules applied in priority order:
          R6 (reflection/native boundary) → needs_dynamic_confirmation
          R7 (confidence < 0.7)           → unverified
          R1 (depth 0, high confidence)   → confirmed
          R2/R3 (multi-hop, >=0.85)       → likely_confirmed
          default                         → likely
        """
        # Collect all code snippets in the flow for reflection marker scan.
        all_code: list[str] = []
        if flow.source is not None:
            all_code.append(flow.source.code or "")
        for hop in flow.hops:
            all_code.append(hop.code or "")
        all_code.append(flow.sink.code or "")
        combined = " ".join(all_code)

        # R6: Reflection or native boundary anywhere in the flow path.
        _REFLECTION_MARKERS = (
            "Class.forName", "getDeclaredMethod", "getMethod",
            "invoke(", "loadLibrary", "dlopen", "System.load",
        )
        if any(m in combined for m in _REFLECTION_MARKERS):
            return (
                "needs_dynamic_confirmation",
                "Flow crosses a reflection or native boundary — static "
                "analysis cannot fully resolve the target; confirm with "
                "runtime instrumentation (jni-tracer.js or method-tracer.js).",
            )

        # R7: Confidence below 0.7 (depth ≥ 3) — inter-procedural speculation.
        if flow.confidence < 0.7:
            return (
                "unverified",
                f"IPA depth {flow.depth} yields confidence {flow.confidence:.1f} "
                "— flow is speculative; prioritise manually after depth-0 findings.",
            )

        # R1: Direct in-method flow at high confidence.
        if flow.depth == 0 and flow.confidence >= 0.85:
            return (
                "confirmed",
                "Source and sink are in the same method with no intermediate "
                "hops — highest-confidence finding; no runtime confirmation needed.",
            )

        # R2/R3: Multi-hop but confidence still ≥ 0.85.
        if flow.confidence >= 0.85:
            return (
                "likely_confirmed",
                f"Inter-procedural flow ({flow.depth} hop(s)) with confidence "
                f"{flow.confidence:.1f} — strong static signal; spot-check at "
                "runtime to rule out unreachable code paths.",
            )

        return (
            "likely",
            f"Confidence {flow.confidence:.1f} at IPA depth {flow.depth} — "
            "plausible flow; triage after confirmed/likely_confirmed findings.",
        )

    @staticmethod
    def _render_evidence(flow: TaintFlow) -> dict:
        """Pack the trace into a Finding.evidence dict.

        Two flat lists (``trace`` of dicts; ``trace_summary`` of
        readable strings) so consumers can choose: the UI renders the
        readable summary, downstream tooling reads the structured list.
        """
        trace_entries: list[dict] = []
        readable: list[str] = []

        # Source hop first.
        if flow.source is not None:
            trace_entries.append(_hop_dict(flow.source))
            readable.append(_hop_str(flow.source))

        for hop in flow.hops:
            trace_entries.append(_hop_dict(hop))
            readable.append(_hop_str(hop))

        trace_entries.append(_hop_dict(flow.sink))
        readable.append(_hop_str(flow.sink))

        status, triage_note = TaintAgent._classify_flow(flow)

        ev: dict = {
            "vuln_class": flow.vuln_class,
            "source_label": (
                flow.source_spec.label if flow.source_spec else "unknown"
            ),
            "sink_method": (
                flow.sink_spec.method_name if flow.sink_spec else "unknown"
            ),
            "ipa_depth": flow.depth,
            "trace": trace_entries,
            "trace_summary": " → ".join(readable),
            "source_file": flow.source.file if flow.source else "",
            "source_line": flow.source.line if flow.source else 0,
            "sink_file": flow.sink.file,
            "sink_line": flow.sink.line,
            "verification_status": status,
            "triage_note": triage_note,
        }
        return ev

    @staticmethod
    def _recommendation_for(flow: TaintFlow, sink_spec: SinkSpec) -> str:
        """Combine the sink-level guidance with a one-line summary of
        where to break the flow. The user opens the file at the source
        and traces forward; the recommendation should make that path
        obvious in plain English.
        """
        break_hint = (
            f"Break the flow between {flow.source.file}:{flow.source.line} "
            f"(source: {flow.source.label or 'untrusted input'}) and "
            f"{flow.sink.file}:{flow.sink.line} (sink: "
            f"{sink_spec.method_name}). "
        )
        return break_hint + sink_spec.recommendation


# ---------- Trace-rendering helpers (module level for testing) ----------

def _hop_dict(hop: TraceHop) -> dict:
    return {
        "file": hop.file,
        "line": hop.line,
        "start_col": hop.start_col,
        "end_col": hop.end_col,
        "code": hop.code,
        "kind": hop.kind,
        "label": hop.label,
    }


def _hop_str(hop: TraceHop) -> str:
    label = f" [{hop.label}]" if hop.label else ""
    code = f"  // {hop.code}" if hop.code else ""
    return f"{hop.kind}@{hop.file}:{hop.line}{label}{code}"


__all__ = ["TaintAgent"]
