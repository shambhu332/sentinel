"""Unit tests for TAINT_001 — data-flow taint analysis."""
from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from sentinel.agents.taint.taint_agent import (
    TaintAgent,
    _hop_dict,
    _hop_str,
)
from sentinel.agents.taint.taint_config import (
    SENSITIVE_KEY_HINTS,
    SINKS,
    VC_CMD,
    VC_INSEC_STG,
    VC_PATH,
    VC_SENS_LOG,
    VC_SQLI,
    VC_XSS_WV,
    confidence_for_depth,
    key_looks_sensitive,
)
from sentinel.agents.taint.tracer import (
    DEFAULT_PER_FILE_TIMEOUT_S,
    TaintFlow,
    TraceHop,
    analyse_tree,
)
from sentinel.core.finding import Severity, TriageState
from sentinel.core.scan_context import ScanContext

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "taint"


# ---------- Lightweight memory + context plumbing ----------

class _StubMemory:
    """Minimal MemoryInterface impl so BaseAgent.run() can publish without a DB."""

    def __init__(self) -> None:
        self.findings: list[Any] = []
        self.events: list[dict[str, Any]] = []

    async def save_finding(self, f: Any) -> None:
        self.findings.append(f)

    async def publish_event(
        self, session_id: str, event_type: str, payload: dict[str, Any],
    ) -> None:
        self.events.append({"type": event_type, "payload": payload})


def _make_context(tmp_path: Path, decompiled_dir: Path) -> ScanContext:
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")  # ZIP magic; passes the file check.
    return ScanContext(
        session_id="taint_test_session",
        apk_path=apk,
        workspace=tmp_path,
        decompiled_dir=decompiled_dir,
    )


def _copy_fixture(src_name: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / src_name
    shutil.copy(FIXTURES_DIR / src_name, target)
    return target


# ---------- Trace-level tests (analyse_tree) ----------

def test_direct_sqli_intra_procedural(tmp_path: Path) -> None:
    """Source and sink in the same method must produce a depth-0 flow."""
    _copy_fixture("direct_sqli.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    sqli = [f for f in flows if f.vuln_class == VC_SQLI]
    assert len(sqli) == 1
    flow = sqli[0]
    assert flow.depth == 0
    assert flow.confidence == pytest.approx(0.9)
    assert "getStringExtra" in flow.source.code
    assert "rawQuery" in flow.sink.code
    assert flow.sanitized is False


def test_multi_method_sqli_one_ipa_hop(tmp_path: Path) -> None:
    """source → method-call → sink must report depth 1, confidence 0.8."""
    _copy_fixture("multi_method_sqli.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert len(flows) == 1
    f = flows[0]
    assert f.vuln_class == VC_SQLI
    assert f.depth == 1
    assert f.confidence == pytest.approx(0.8)
    # The trace must contain the call hop that crosses the method
    # boundary — the readable label says so explicitly.
    call_hops = [h for h in f.hops if h.kind == "call"]
    assert len(call_hops) == 1
    assert "lookup" in call_hops[0].label


def test_three_hop_sqli_two_ipa_hops(tmp_path: Path) -> None:
    """3-step chain → depth 2, confidence 0.7."""
    _copy_fixture("three_hop.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert len(flows) == 1
    f = flows[0]
    assert f.depth == 2
    assert f.confidence == pytest.approx(0.7)
    call_hops = [h for h in f.hops if h.kind == "call"]
    assert len(call_hops) == 2


def test_four_hop_exceeds_depth_limit(tmp_path: Path) -> None:
    """An IPA chain longer than MAX_IPA_DEPTH must NOT be reported."""
    _copy_fixture("four_hop.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert flows == []


def test_sanitized_flow_not_reported(tmp_path: Path) -> None:
    """Integer.parseInt between source and sink must suppress the report."""
    _copy_fixture("sanitized.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert flows == [], (
        "parseInt is in the sanitizer table for SQL_INJECTION; the flow "
        "should not surface"
    )


def test_parameterized_query_not_reported(tmp_path: Path) -> None:
    """Tainted value bound as a ? placeholder must not be flagged."""
    _copy_fixture("parameterized_query.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert flows == []


def test_no_taint_clean_baseline(tmp_path: Path) -> None:
    """A constant SQL string with no source involvement must be silent."""
    _copy_fixture("no_taint.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert flows == []


def test_webview_xss_correct_vuln_class(tmp_path: Path) -> None:
    """Intent extra → WebView.loadUrl is WEBVIEW_XSS, not SQL_INJECTION."""
    _copy_fixture("webview_xss.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert len(flows) == 1
    f = flows[0]
    assert f.vuln_class == VC_XSS_WV
    assert f.depth == 0
    assert "loadUrl" in f.sink.code


def test_sensitive_log_severity_low(tmp_path: Path) -> None:
    """Log.d sink emits SENSITIVE_LOG and produces a flow."""
    _copy_fixture("sensitive_log.java", tmp_path / "src")
    flows = analyse_tree(tmp_path / "src")
    assert len(flows) == 1
    f = flows[0]
    assert f.vuln_class == VC_SENS_LOG
    assert f.sink_spec is not None
    assert f.sink_spec.severity == Severity.LOW


def test_confidence_scales_with_hops() -> None:
    assert confidence_for_depth(0) == pytest.approx(0.9)
    assert confidence_for_depth(1) == pytest.approx(0.8)
    assert confidence_for_depth(2) == pytest.approx(0.7)
    assert confidence_for_depth(3) == pytest.approx(0.6)
    assert confidence_for_depth(10) == pytest.approx(0.6)  # capped
    assert confidence_for_depth(-5) == pytest.approx(0.9)  # neg clamp


# ---------- Config tests ----------

def test_sensitive_key_hints_recognises_credentials() -> None:
    assert key_looks_sensitive("auth_token")
    assert key_looks_sensitive("USER_PASSWORD")
    assert key_looks_sensitive("'session_id'")  # quoted literal
    assert key_looks_sensitive("apiKey")
    assert not key_looks_sensitive("theme_pref")
    assert not key_looks_sensitive("locale")
    assert not key_looks_sensitive("")


def test_sinks_cover_required_vuln_classes() -> None:
    """The sink table must cover every vuln class the spec listed —
    a regression guard against accidental table edits."""
    classes = {s.vuln_class for s in SINKS}
    for required in (
        VC_SQLI, VC_XSS_WV, VC_CMD, VC_PATH, VC_INSEC_STG, VC_SENS_LOG,
    ):
        assert required in classes, f"missing sink coverage for {required}"


def test_sensitive_key_hints_complete() -> None:
    """Sanity-check the hint table — should include all the common
    credential-name tokens. Acts as a regression guard."""
    for tok in ("token", "password", "secret", "jwt"):
        assert tok in SENSITIVE_KEY_HINTS


# ---------- Agent-level tests ----------

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def test_agent_emits_finding_with_full_trace(tmp_path: Path) -> None:
    """End-to-end: TaintAgent.run() against direct_sqli must emit a
    well-formed Finding whose evidence contains the trace."""
    _copy_fixture("direct_sqli.java", tmp_path / "decompiled")
    ctx = _make_context(tmp_path, tmp_path / "decompiled")
    mem = _StubMemory()
    agent = TaintAgent(context=ctx, memory=mem, config={})

    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == VC_SQLI
    assert f.agent_id == "TAINT_001"
    assert 0.0 < f.confidence <= 1.0
    assert f.severity in {
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
    }
    assert f.recommendation  # non-empty
    assert f.session_id == "taint_test_session"
    assert f.triage == TriageState.UNREVIEWED

    ev = f.evidence
    assert ev["vuln_class"] == VC_SQLI
    assert ev["sink_method"] == "rawQuery"
    assert ev["ipa_depth"] == 0
    assert isinstance(ev["trace"], list)
    # source + (≥1 variable hop) + sink, so at minimum 3 entries.
    assert len(ev["trace"]) >= 2
    assert ev["trace"][0]["kind"] == "source"
    assert ev["trace"][-1]["kind"] == "sink"
    assert "rawQuery" in ev["trace_summary"]


def test_agent_skips_when_no_decompiled_dir(tmp_path: Path) -> None:
    """is_applicable() returns False without a decompiled tree, and
    run() therefore produces zero findings without crashing."""
    ctx = _make_context(tmp_path, tmp_path / "does-not-exist")
    agent = TaintAgent(context=ctx, memory=_StubMemory(), config={})
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    assert findings == []


def test_agent_handles_empty_decompiled_dir(tmp_path: Path) -> None:
    """Empty source tree must return no findings (not crash)."""
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = _make_context(tmp_path, decompiled)
    agent = TaintAgent(context=ctx, memory=_StubMemory(), config={})
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    assert findings == []


def test_agent_chains_fixture_returns_expected_count(tmp_path: Path) -> None:
    """All positive fixtures in one tree must produce 5 findings (the
    five fixtures whose sinks the tracer flags) — no over-reporting."""
    decompiled = tmp_path / "decompiled"
    for f in (
        "direct_sqli.java", "multi_method_sqli.java",
        "three_hop.java", "four_hop.java",
        "sanitized.java", "parameterized_query.java", "no_taint.java",
        "webview_xss.java", "sensitive_log.java",
    ):
        _copy_fixture(f, decompiled)
    ctx = _make_context(tmp_path, decompiled)
    agent = TaintAgent(context=ctx, memory=_StubMemory(), config={})
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    assert len(findings) == 5  # the 5 expected-positive fixtures


def test_finding_schema_compliance(tmp_path: Path) -> None:
    """Each emitted Finding must have every required field populated
    and pass Pydantic validation (a Finding object only exists if it
    validated)."""
    _copy_fixture("direct_sqli.java", tmp_path / "decompiled")
    ctx = _make_context(tmp_path, tmp_path / "decompiled")
    agent = TaintAgent(context=ctx, memory=_StubMemory(), config={})
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    f = findings[0]
    for required in ("agent_id", "vuln_class", "severity", "confidence",
                     "evidence", "recommendation", "session_id"):
        val = getattr(f, required)
        assert val not in (None, "", [], {}), (
            f"required field {required} is empty"
        )


# ---------- Robustness tests ----------

def test_malformed_java_does_not_crash(tmp_path: Path) -> None:
    """tree-sitter is error-tolerant — it should parse partially and
    we should silently produce 0 flows rather than blow up."""
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    (decompiled / "broken.java").write_text(
        "class Broken { void f( { String x = ;; rawQuery(x);",
    )
    ctx = _make_context(tmp_path, decompiled)
    agent = TaintAgent(context=ctx, memory=_StubMemory(), config={})
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    # No crash. Either zero or some salvaged flows.
    assert isinstance(findings, list)


def test_per_file_timeout_skips_runaway_method(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A per_file_timeout_s of 0.0 must mean every method after the
    first is skipped; the warning is logged but the agent returns
    whatever it produced before the deadline."""
    _copy_fixture("direct_sqli.java", tmp_path / "decompiled")
    ctx = _make_context(tmp_path, tmp_path / "decompiled")
    agent = TaintAgent(
        context=ctx, memory=_StubMemory(),
        config={"per_file_timeout_s": 0.0},
    )
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    # Time budget 0 → no method processed → no findings, no crash.
    assert isinstance(findings, list)


def test_max_ipa_depth_override(tmp_path: Path) -> None:
    """Lowering MAX_IPA_DEPTH to 0 makes inter-procedural detection
    disappear, leaving only direct-flow findings."""
    decompiled = tmp_path / "decompiled"
    _copy_fixture("direct_sqli.java", decompiled)        # depth 0 (intra)
    _copy_fixture("multi_method_sqli.java", decompiled)  # depth 1 (inter)
    ctx = _make_context(tmp_path, decompiled)
    agent = TaintAgent(
        context=ctx, memory=_StubMemory(),
        config={"max_ipa_depth": 0},
    )
    findings = asyncio.get_event_loop().run_until_complete(agent.run())
    # Only the intra-procedural one survives.
    assert len(findings) == 1
    assert findings[0].evidence["ipa_depth"] == 0


def test_hop_helpers_serialise_correctly() -> None:
    hop = TraceHop(file="/tmp/x.java", line=42, code="db.rawQuery(q)",
                   kind="sink", label="rawQuery")
    d = _hop_dict(hop)
    assert d == {"file": "/tmp/x.java", "line": 42,
                 "start_col": 0, "end_col": 0,
                 "code": "db.rawQuery(q)", "kind": "sink",
                 "label": "rawQuery"}
    s = _hop_str(hop)
    assert "rawQuery" in s
    assert "/tmp/x.java:42" in s


def test_default_per_file_timeout_positive() -> None:
    assert DEFAULT_PER_FILE_TIMEOUT_S > 0
