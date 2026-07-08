"""Unit tests for A_001 AI-Autonomous Hardcoded Credentials Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent
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
    confidence: float = 0.92,
    vuln_type: str = "CWE-798: Use of Hard-coded Credentials",
) -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="The snippet contains a live Stripe secret key embedded in source.",
        vulnerability_type=vuln_type,
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Decompile APK", "APK accessible", "Java source extracted"),
            ExploitStep(2, "Grep for key pattern", "sk_live_ present", "Key retrieved"),
        ],
        business_impact="Attacker can charge customers or access financial data.",
        remediation_code="// Fetch key from secure backend; never embed in APK",
        remediation_steps=["Remove from source", "Rotate key immediately"],
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
# fast_pre_filter — pattern detection
# ---------------------------------------------------------------------------

class TestFastPreFilter:
    @pytest.mark.asyncio
    async def test_detects_stripe_key(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Pay.java",
                   'private static final String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("sk_live_" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_aws_key(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Aws.java",
                   'static final String KEY = "AKIAIOSFODNN7EXAMPLE";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("AKIA" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_google_api_key(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Maps.java",
                   'String gKey = "AIzaSyDdI0hiBtDFcKQ6lzH8d7g7YnMkHj1234XY";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("AIza" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_pem_private_key(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Certs.java",
                   'String k = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("PRIVATE KEY" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_bearer_token(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Api.java",
                   'String h = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "ApiClientTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_no_source_returns_empty(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nonexistent"
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Stripe.java",
                   'static final String S = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "A_001"
        assert 0.0 < c.rule_confidence <= 1.0
        assert c.context_window


# ---------------------------------------------------------------------------
# analyze() — LLM pipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Pay.java",
                   'static final String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict(VulnerabilityVerdict.TRUE_POSITIVE, "High")
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Config.java",
                   'static final String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.1)
        verdict.false_positive_reason = "Key is a test fixture placeholder"
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Maybe.java",
                   'static final String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "High", 0.5)
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1
        assert findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_needs_dast_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Net.java",
                   'static final String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict(VulnerabilityVerdict.NEEDS_DAST_VALIDATION, "Medium", 0.7)
        verdict.dast_validation_needed = "Verify key is active by calling Stripe API"
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_llm_called_once_per_candidate(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "A.java",
                   'String k1 = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict()
        mock = _mock_analyzer(verdict)
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=mock)
        await agent.analyze()
        assert mock.analyze_candidate.call_count >= 1

    @pytest.mark.asyncio
    async def test_no_source_returns_empty(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nonexistent"
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_test_file_not_analyzed(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "PaymentTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        mock = _mock_analyzer(_make_verdict())
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=mock)
        findings = await agent.analyze()
        assert findings == []
        mock.analyze_candidate.assert_not_called()


# ---------------------------------------------------------------------------
# Finding field validation
# ---------------------------------------------------------------------------

class TestFindingFields:
    @pytest.mark.asyncio
    async def test_agent_id(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "A_001"

    @pytest.mark.asyncio
    async def test_severity_maps_correctly(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        verdict = _make_verdict(severity="Critical", confidence=0.98)
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"

    @pytest.mark.asyncio
    async def test_severity_rationale_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].severity_rationale

    @pytest.mark.asyncio
    async def test_evidence_contains_llm_fields(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        ev = findings[0].evidence
        assert "llm_confidence" in ev
        assert "rule_triggered" in ev
        assert "exploit_path" in ev

    @pytest.mark.asyncio
    async def test_compliance_tags_extracted_from_cwe(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-798" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_recommendation_not_empty(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].recommendation

    @pytest.mark.asyncio
    async def test_session_id_matches_context(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "X.java",
                   'String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].session_id == ctx.session_id


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

class TestIsApplicable:
    @pytest.mark.asyncio
    async def test_true_when_decompiled_exists(self, ctx, memory):
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        assert await agent.is_applicable() is True

    @pytest.mark.asyncio
    async def test_false_when_no_source(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nope"
        ctx.resources_dir = None
        agent = A001AIHardcodedCredsAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        assert await agent.is_applicable() is False
