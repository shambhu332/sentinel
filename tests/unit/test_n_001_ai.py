"""Unit tests for N_001 AI-Autonomous Cleartext HTTP Detection Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.network.n_001_cleartext_http import N001CleartextHTTPAgent
from sentinel.agents.base.ai_autonomous_agent import Candidate
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.llm.vulnerability_analyzer import (
    ExploitStep,
    LLMVerdict,
    LLMVulnerabilityAnalyzer,
    VulnerabilityVerdict,
)
from sentinel.memory import LightweightMemory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
    ws.mkdir()
    decompiled = ws / "jadx" / "sources"
    decompiled.mkdir(parents=True)
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    c.decompiled_dir = decompiled
    return c


def _make_verdict(
    verdict: VulnerabilityVerdict = VulnerabilityVerdict.TRUE_POSITIVE,
    severity: str = "High",
    confidence: float = 0.90,
) -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="Cleartext HTTP detected — data transmitted without encryption.",
        vulnerability_type="CWE-319: Cleartext Transmission of Sensitive Information",
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Intercept HTTP traffic", "Network position", "Credentials exposed"),
        ],
        business_impact="Credentials and session tokens exposed over cleartext HTTP.",
        remediation_steps=["Use HTTPS for all network connections"],
        owasp_masvs_mapping=["M3", "MASVS-NETWORK-1"],
    )


def _mock_analyzer(verdict: LLMVerdict) -> LLMVulnerabilityAnalyzer:
    mock = MagicMock(spec=LLMVulnerabilityAnalyzer)
    mock.analyze_candidate = AsyncMock(return_value=verdict)
    return mock


def _java_file(decompiled_dir: Path, name: str, content: str) -> Path:
    p = decompiled_dir / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# TestFastPreFilter
# ---------------------------------------------------------------------------

class TestFastPreFilter:
    @pytest.mark.asyncio
    async def test_detects_http_url(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_retrofit_base_url(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "ApiClient.java",
                   'Retrofit retrofit = new Retrofit.Builder().baseUrl("http://api.example.com/").build();')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_cleartext_spec(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "OkHttp.java",
                   'ConnectionSpec spec = ConnectionSpec.CLEARTEXT;')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_localhost(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Dev.java",
                   'URL url = new URL("http://localhost:8080/api");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "NetworkTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "N_001"
        assert 0.0 < c.rule_confidence <= 1.0
        assert c.context_window


# ---------------------------------------------------------------------------
# TestAnalyzePipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'URL url = new URL("http://api.example.com/login");')
        verdict = _make_verdict(VulnerabilityVerdict.TRUE_POSITIVE, "High")
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'URL url = new URL("http://api.example.com/login");')
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.1)
        verdict.false_positive_reason = "Only used in dev builds"
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'URL url = new URL("http://api.example.com/login");')
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "High", 0.5)
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# TestFindingFields
# ---------------------------------------------------------------------------

class TestFindingFields:
    @pytest.mark.asyncio
    async def test_agent_id(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "N_001"

    @pytest.mark.asyncio
    async def test_cwe_in_compliance_tags(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-319" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'URL url = new URL("http://api.example.com/login");')
        agent = N001CleartextHTTPAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"
