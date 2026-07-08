"""Unit tests for C_002 AI-Autonomous Static IV Detection Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.crypto.c_002_static_iv import C002StaticIVAgent
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
        reasoning="Static IV detected — same IV reused across encryptions.",
        vulnerability_type="CWE-329: Not Using a Random IV with CBC Mode",
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Capture ciphertext", "Network access", "Two ciphertexts with same IV"),
        ],
        business_impact="IV reuse breaks semantic security of CBC mode.",
        remediation_steps=["Generate random IV with SecureRandom for each encryption"],
        owasp_masvs_mapping=["M5", "MASVS-CRYPTO-1"],
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
    async def test_detects_zero_iv(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Crypto.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_static_iv_field(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'private static final byte[] mIV = {0x00, 0x01, 0x02, 0x03};')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_hex_literal_iv(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'IvParameterSpec iv = new IvParameterSpec("0102030405060708090a0b0c0d0e0f10");')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "CryptoTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "C_002"
        assert 0.0 < c.rule_confidence <= 1.0
        assert c.context_window


# ---------------------------------------------------------------------------
# TestAnalyzePipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        verdict = _make_verdict(VulnerabilityVerdict.TRUE_POSITIVE, "High")
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.1)
        verdict.false_positive_reason = "IV is regenerated at runtime"
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Enc.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "High", 0.5)
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
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
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "C_002"

    @pytest.mark.asyncio
    async def test_cwe_in_compliance_tags(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-329" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'IvParameterSpec iv = new IvParameterSpec(new byte[16]);')
        agent = C002StaticIVAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"
