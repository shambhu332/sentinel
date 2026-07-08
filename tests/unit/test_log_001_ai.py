"""Unit tests for LOG_001 AI-Autonomous PII in Logcat Detection Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.logging.log_001_pii_logs import LOG001PIILogsAgent
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
    severity: str = "Medium",
    confidence: float = 0.88,
) -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="PII logged to Logcat — sensitive data written to system log.",
        vulnerability_type="CWE-532: Information Exposure Through Log Files",
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Read Logcat output", "ADB access or rooted device", "Sensitive data extracted"),
        ],
        business_impact="Passwords and tokens exposed in device logs readable by other apps.",
        remediation_steps=["Remove sensitive data from log statements", "Use ProGuard to strip logs in release"],
        owasp_masvs_mapping=["M2", "MASVS-STORAGE-2"],
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
    async def test_detects_password_in_log(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_token_in_log(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.i("Net", "Auth token: " + token);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_response_dump(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'Log.v("HTTP", "Response: " + response.body());')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "AuthTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "LOG_001"
        assert 0.0 < c.rule_confidence <= 1.0
        assert c.context_window


# ---------------------------------------------------------------------------
# TestAnalyzePipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.d("Auth", "User password: " + password);')
        verdict = _make_verdict(VulnerabilityVerdict.TRUE_POSITIVE, "Medium")
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.d("Auth", "User password: " + password);')
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.1)
        verdict.false_positive_reason = "Debug-only build flag guards this log"
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   'Log.d("Auth", "User password: " + password);')
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "Medium", 0.5)
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
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
                   'Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "LOG_001"

    @pytest.mark.asyncio
    async def test_cwe_in_compliance_tags(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-532" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'Log.d("Auth", "User password: " + password);')
        agent = LOG001PIILogsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"
