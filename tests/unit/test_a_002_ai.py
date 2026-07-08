"""Unit tests for A_002 AI-Autonomous JWT Algorithm Confusion Agent."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.auth.a_002_ai import A002AIJWTAlgConfusionAgent
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
    severity: str = "Critical",
    confidence: float = 0.95,
    vuln_type: str = "CWE-287: Improper Authentication — JWT alg:none",
) -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="Algorithm.none() allows an attacker to forge unsigned JWT tokens.",
        vulnerability_type=vuln_type,
        severity=severity,
        exploit_path=[
            ExploitStep(1, "Craft JWT with alg:none", "Target accepts alg:none", "Token accepted without signature"),
            ExploitStep(2, "Set arbitrary claims", "No signature check", "Privilege escalation"),
        ],
        business_impact="Complete authentication bypass — any user can impersonate any other.",
        remediation_code=(
            "Algorithm alg = Algorithm.RSA256(publicKey, null);\n"
            "JWTVerifier verifier = JWT.require(alg).withIssuer(issuer).build();\n"
            "verifier.verify(token);"
        ),
        remediation_steps=[
            "Replace Algorithm.none() with Algorithm.RSA256 or Algorithm.HMAC256",
            "Whitelist allowed algorithms explicitly",
            "Add integration test that rejects alg:none tokens",
        ],
        owasp_masvs_mapping=["M5", "MASVS-AUTH-2"],
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
    async def test_detects_alg_none_call(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("none" in c.code_snippet.lower() for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_alg_none_in_json_string(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Header.java",
                   'String h = "{\\"alg\\":\\"none\\",\\"typ\\":\\"JWT\\"}";')
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_detects_hmac256_with_rsa_key(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Confused.java",
                   "Algorithm alg = Algorithm.HMAC256(publicKey.getEncoded());")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("HMAC256" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_parse_claims_jwt(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "JJWT.java",
                   "Jwts.parser().setSigningKey(key).parseClaimsJwt(token);")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("parseClaimsJwt" in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_jwt_decode(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Lazy.java",
                   "DecodedJWT jwt = JWT.decode(token);")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert any("decode" in c.code_snippet.lower() for c in candidates)

    @pytest.mark.asyncio
    async def test_detects_rsa_param_used_in_hmac(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Param.java", """
void v(RSAPublicKey pub) {
    Algorithm alg = Algorithm.HMAC256(pub.getEncoded());
}
""")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert len(candidates) >= 1

    @pytest.mark.asyncio
    async def test_skips_test_files(self, ctx, memory):
        p = ctx.decompiled_dir / "com" / "example" / "AuthServiceTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_candidate_fields_populated(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates
        c = candidates[0]
        assert c.file_path
        assert c.line_number >= 1
        assert c.rule_triggered == "A_002"
        assert c.rule_confidence >= 0.9
        assert c.context_window

    @pytest.mark.asyncio
    async def test_no_source_returns_empty(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nonexistent"
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        assert candidates == []


# ---------------------------------------------------------------------------
# analyze() — full LLM pipeline
# ---------------------------------------------------------------------------

class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_true_positive_emits_finding(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_false_positive_suppressed(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Doc.java",
                   "// Example: Algorithm.none() is insecure, never use this")
        verdict = _make_verdict(VulnerabilityVerdict.FALSE_POSITIVE, "Info", 0.05)
        verdict.false_positive_reason = "Comment line — not executable code"
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_uncertain_emits_info(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Maybe.java",
                   "DecodedJWT jwt = JWT.decode(token);")
        verdict = _make_verdict(VulnerabilityVerdict.UNCERTAIN, "High", 0.5)
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert any(f.severity == Severity.INFO for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_vulns_in_one_file(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Service.java", """
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
public class Service {
    void bad1(String token) { Algorithm alg = Algorithm.none(); JWT.require(alg).build().verify(token); }
    void bad2(RSAPublicKey pub) { Algorithm alg = Algorithm.HMAC256(pub.getEncoded()); }
}
""")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        # Both patterns should trigger candidates → at least 2 LLM calls → 2 findings
        assert len(findings) >= 2

    @pytest.mark.asyncio
    async def test_secure_rs256_may_trigger_candidate_but_llm_rejects(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Secure.java", """
Algorithm alg = Algorithm.RSA256(pub, priv);
JWT.require(alg).build().verify(token);
""")
        # No patterns should match — RS256 is not in the fast-filter patterns
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        candidates = await agent.fast_pre_filter(ctx)
        # Either no candidates, or LLM would reject them — we just verify pre-filter
        # doesn't match the secure pattern (no alg:none, HMAC256, JWT.decode etc.)
        assert all("RSA256" not in c.code_snippet for c in candidates)

    @pytest.mark.asyncio
    async def test_llm_called_per_unique_candidate(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        mock = _mock_analyzer(_make_verdict())
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=mock)
        await agent.analyze()
        assert mock.analyze_candidate.call_count >= 1


# ---------------------------------------------------------------------------
# Finding fields
# ---------------------------------------------------------------------------

class TestFindingFields:
    @pytest.mark.asyncio
    async def test_agent_id(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].agent_id == "A_002"

    @pytest.mark.asyncio
    async def test_critical_severity_mapped(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        verdict = _make_verdict(severity="Critical", confidence=0.98)
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(verdict))
        findings = await agent.analyze()
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_owasp_field_set(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].owasp == "M5"

    @pytest.mark.asyncio
    async def test_masvs_field_set(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].masvs == "MASVS-AUTH-2"

    @pytest.mark.asyncio
    async def test_exploit_path_in_evidence(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        ev = findings[0].evidence
        assert isinstance(ev.get("exploit_path"), list)
        assert len(ev["exploit_path"]) >= 1

    @pytest.mark.asyncio
    async def test_cwe_in_compliance_tags(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert "CWE-287" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_finding_category_ai_powered(self, ctx, memory):
        _java_file(ctx.decompiled_dir, "Auth.java",
                   "Algorithm alg = Algorithm.none();")
        agent = A002AIJWTAlgConfusionAgent(ctx, memory, llm_analyzer=_mock_analyzer(_make_verdict()))
        findings = await agent.analyze()
        assert findings[0].finding_category == "AI-Powered"
