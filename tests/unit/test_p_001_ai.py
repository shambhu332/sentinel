"""Unit tests for P_001 AI-Autonomous Deep Link Hijack Detection Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.platform.p_001_deep_link_hijack import P001DeepLinkHijackAgent
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
    confidence: float = 0.87,
) -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="Exported deep link handler detected — activity handles external URLs without validation.",
        vulnerability_type="CWE-940: Improper Verification of Source of a Communication Channel",
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Craft malicious deep link", "Deep link registered", "Activity launched with attacker data"),
        ],
        business_impact="Attacker can open the app with arbitrary deep link data.",
        remediation_steps=["Validate deep link origin and parameters before processing"],
        owasp_masvs_mapping=["M1", "MASVS-PLATFORM-1"],
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
    async def test_detects_get_intent_get_data(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "MainActivity.java",
                   'Uri data = getIntent().getData(); String path = data.getPath();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_manifest_exported(self, ctx, memory):
        manifest = ctx.workspace / "AndroidManifest.xml"
        manifest.write_text(
            '<activity android:exported="true">'
            '<intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>'
            '</activity>'
        )
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_browsable_category(self, ctx, memory):
        manifest = ctx.workspace / "AndroidManifest.xml"
        manifest.write_text(
            '<category android:name="android.intent.category.BROWSABLE"/>'
        )
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "MainActivityTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('Uri data = getIntent().getData();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "MainActivity.java",
                   'Uri data = getIntent().getData();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "P_001"
        assert 0.0 < c.rule_confidence <= 1.0
        assert c.context_window


# ---------------------------------------------------------------------------
# TestAnalyzePipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "MainActivity.java",
                   'Uri data = getIntent().getData();')
        verdict = _make_verdict(VulnerabilityVerdict.TRUE_POSITIVE, "High")
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "MainActivity.java",
                   'Uri data = getIntent().getData();')
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.1)
        verdict.false_positive_reason = "Deep link data is validated before use"
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "MainActivity.java",
                   'Uri data = getIntent().getData();')
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "High", 0.5)
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
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
                   'Uri data = getIntent().getData();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "P_001"

    @pytest.mark.asyncio
    async def test_cwe_in_compliance_tags(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'Uri data = getIntent().getData();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-940" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'Uri data = getIntent().getData();')
        agent = P001DeepLinkHijackAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"
