"""Unit tests for the LLM triage layer.

Uses a mock FreeProviderRouter to avoid real API calls during tests.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.triage import (
    LLMTriager,
    TriageOutcome,
    TriageResult,
    TriageVerdict,
)

# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def context(tmp_path):
    """ScanContext with a small synthetic decompiled dir."""
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)

    # Create a synthetic source file the triager can load
    src = decompiled / "Foo.java"
    src.write_text(
        "public class Foo {\n"
        "    void doStuff() {\n"
        "        Random r = new Random();\n"
        "        String token = String.valueOf(r.nextLong());\n"
        "    }\n"
        "}\n"
    )

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.manifest = {"package": "com.x.test"}
    return ctx


def _make_finding(
    agent_id: str = "B_002",
    vuln_class: str = "Insecure Random",
    severity: Severity = Severity.HIGH,
    session_id: str = "test_session_abc123",
) -> Finding:
    return Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.80,
        evidence={
            "title": "Test finding",
            "hits": [{"file": "Foo.java", "context": "Random r = new Random();"}],
        },
        recommendation="Use SecureRandom instead.",
        session_id=session_id,
    )


def _mock_router_response(verdict_dict: dict, provider: str = "cerebras"):
    """Create a mock router that returns the given verdict dict from query_json."""
    router = AsyncMock()
    router.query_json = AsyncMock(return_value={
        "content": verdict_dict,
        "model": "test-model",
        "provider": provider,
    })
    return router


# ---------- TriageVerdict / TriageResult model tests ----------

def test_triage_verdict_valid():
    v = TriageVerdict(
        is_real_bug=True,
        confidence=0.85,
        explanation="The Random() is used to generate a session token, which is a real bug.",
    )
    assert v.is_real_bug is True
    assert v.adjusted_severity is None


def test_triage_verdict_rejects_bad_confidence():
    """Confidence must be in [0.0, 1.0]; pydantic raises ValidationError."""
    with pytest.raises(ValidationError):
        TriageVerdict(
            is_real_bug=True,
            confidence=2.0,  # out of [0, 1]
            explanation="x" * 20,
        )


def test_triage_verdict_ignores_extra_fields():
    """TriageVerdict uses extra='ignore' to tolerate small-model JSON quirks.

    Small LLMs (llama3.1-8b etc.) often add helpful-looking unrequested
    fields like 'reasoning' or 'evidence'. We accept them silently rather
    than failing the whole verdict.
    """
    v = TriageVerdict.model_validate({
        "is_real_bug": True,
        "confidence": 0.5,
        "explanation": "x" * 20,
        "extra_field": "should be silently ignored",
        "reasoning": "another extra field",
    })
    assert v.is_real_bug is True
    assert v.confidence == 0.5
    # Extra fields are dropped, not stored
    assert not hasattr(v, "extra_field")
    assert not hasattr(v, "reasoning")


def test_triage_result_displayable():
    """FILTERED is hidden by default, others visible."""
    assert TriageResult(outcome=TriageOutcome.VERIFIED).is_displayable() is True
    assert TriageResult(outcome=TriageOutcome.UNCERTAIN).is_displayable() is True
    assert TriageResult(outcome=TriageOutcome.SKIPPED).is_displayable() is True
    assert TriageResult(outcome=TriageOutcome.FILTERED).is_displayable() is False


# ---------- LLMTriager tests ----------

@pytest.mark.asyncio
async def test_triager_skips_test_001(context):
    """TEST_001 findings should be marked SKIPPED."""
    finding = _make_finding(agent_id="TEST_001", vuln_class="Pipeline Smoke Test",
                             severity=Severity.INFO)
    router = _mock_router_response({})  # never called

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    triage_data = findings[0].evidence["_triage"]
    assert triage_data["outcome"] == "skipped"
    router.query_json.assert_not_called()


@pytest.mark.asyncio
async def test_triager_skips_meta_001(context):
    """META_001 findings should be marked SKIPPED."""
    finding = _make_finding(agent_id="META_001", vuln_class="Obfuscation Analysis",
                             severity=Severity.INFO)
    router = _mock_router_response({})

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    assert findings[0].evidence["_triage"]["outcome"] == "skipped"
    router.query_json.assert_not_called()


@pytest.mark.asyncio
async def test_triager_skips_info_severity(context):
    """INFO severity findings should be marked SKIPPED regardless of agent."""
    finding = _make_finding(severity=Severity.INFO)
    router = _mock_router_response({})

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    assert findings[0].evidence["_triage"]["outcome"] == "skipped"


@pytest.mark.asyncio
async def test_triager_marks_verified(context):
    """LLM says is_real_bug=True → VERIFIED."""
    finding = _make_finding()
    router = _mock_router_response({
        "is_real_bug": True,
        "confidence": 0.92,
        "explanation": "The Random call generates a session token in security context.",
        "adjusted_severity": None,
        "false_positive_reason": None,
    })

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    triage = findings[0].evidence["_triage"]
    assert triage["outcome"] == "verified"
    assert triage["verdict"]["is_real_bug"] is True
    assert triage["llm_provider"] == "cerebras"


@pytest.mark.asyncio
async def test_triager_marks_filtered(context):
    """LLM says is_real_bug=False → FILTERED."""
    finding = _make_finding()
    router = _mock_router_response({
        "is_real_bug": False,
        "confidence": 0.75,
        "explanation": "This Random is used for game animation timing, not security.",
        "adjusted_severity": None,
        "false_positive_reason": "non-security use (animation)",
    })

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    triage = findings[0].evidence["_triage"]
    assert triage["outcome"] == "filtered"
    assert triage["verdict"]["is_real_bug"] is False


@pytest.mark.asyncio
async def test_triager_uncertain_on_router_error(context):
    """When the router raises, the result should be UNCERTAIN."""
    from sentinel.llm.router import RouterError

    finding = _make_finding()
    router = AsyncMock()
    router.query_json = AsyncMock(side_effect=RouterError("all providers failed"))

    triager = LLMTriager(router=router, max_retries=0)
    findings = await triager.triage([finding], context)

    triage = findings[0].evidence["_triage"]
    assert triage["outcome"] == "uncertain"
    assert "router_error" in triage["error"]


@pytest.mark.asyncio
async def test_triager_uncertain_on_invalid_schema(context):
    """LLM returns valid JSON but wrong shape → UNCERTAIN."""
    finding = _make_finding()
    router = _mock_router_response({
        "wrong_field": "this is not a TriageVerdict",
    })

    triager = LLMTriager(router=router, max_retries=0)
    findings = await triager.triage([finding], context)

    triage = findings[0].evidence["_triage"]
    assert triage["outcome"] == "uncertain"
    assert "schema_validation_failed" in triage["error"]


@pytest.mark.asyncio
async def test_triager_applies_severity_adjustment(context):
    """LLM-suggested severity adjustment gets applied to verified findings."""
    finding = _make_finding(severity=Severity.HIGH)
    router = _mock_router_response({
        "is_real_bug": True,
        "confidence": 0.80,
        "explanation": "Real bug but actually Medium given context.",
        "adjusted_severity": "Medium",
        "false_positive_reason": None,
    })

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["_severity_original"] == "High"
    assert findings[0].evidence["_severity_adjusted_by_llm"] is True


@pytest.mark.asyncio
async def test_triager_ignores_invalid_severity_adjustment(context):
    """LLM suggests garbage severity → original kept, no error."""
    finding = _make_finding(severity=Severity.HIGH)
    router = _mock_router_response({
        "is_real_bug": True,
        "confidence": 0.80,
        "explanation": "Real bug.",
        "adjusted_severity": "BANANA",
        "false_positive_reason": None,
    })

    triager = LLMTriager(router=router)
    findings = await triager.triage([finding], context)

    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_triager_handles_empty_finding_list(context):
    """Empty input returns empty output."""
    router = _mock_router_response({})
    triager = LLMTriager(router=router)
    result = await triager.triage([], context)
    assert result == []
    router.query_json.assert_not_called()


@pytest.mark.asyncio
async def test_triager_processes_multiple_findings(context):
    """Multiple findings are triaged sequentially."""
    f1 = _make_finding(agent_id="B_002")
    f2 = _make_finding(agent_id="C_007", vuln_class="Weak Cryptography")

    router = AsyncMock()
    # Different verdicts for the two calls
    router.query_json = AsyncMock(side_effect=[
        {"content": {"is_real_bug": True, "confidence": 0.9,
                     "explanation": "Real bug in B_002", "adjusted_severity": None,
                     "false_positive_reason": None},
         "model": "x", "provider": "cerebras"},
        {"content": {"is_real_bug": False, "confidence": 0.7,
                     "explanation": "False positive in C_007", "adjusted_severity": None,
                     "false_positive_reason": "test code"},
         "model": "x", "provider": "cerebras"},
    ])

    triager = LLMTriager(router=router)
    findings = await triager.triage([f1, f2], context)

    assert findings[0].evidence["_triage"]["outcome"] == "verified"
    assert findings[1].evidence["_triage"]["outcome"] == "filtered"
    assert router.query_json.call_count == 2
