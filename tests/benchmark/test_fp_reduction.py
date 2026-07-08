"""FP reduction benchmark — rule-only A_001 vs AI-autonomous A_001.

Measures false positive rate on a labeled dataset of Java snippets and
asserts that the AI pipeline reduces FPs by at least 50 % compared to the
rule-only agent.

Run:
    pytest -m benchmark tests/benchmark/test_fp_reduction.py -v -s

The mock oracle LLM uses recognisable key-pattern markers to decide
true/false positive deterministically — no real LLM needed, no flakiness.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent
from sentinel.agents.auth.a_001_hardcoded_creds import A001HardcodedCredsAgent
from sentinel.core.finding import BountyScope
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.llm.vulnerability_analyzer import (
    LLMVerdict,
    LLMVulnerabilityAnalyzer,
    VulnerabilityVerdict,
)
from sentinel.memory import LightweightMemory

pytestmark = pytest.mark.benchmark


# ---------------------------------------------------------------------------
# Labeled dataset — snippets with ground truth
# ---------------------------------------------------------------------------

# True positive snippets — real credential patterns
TP_SNIPPETS: list[str] = [
    'private static final String S = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";',
    'private static final String S = "sk_live_REALKEY1234567890abcdefXYZ";',
    'static final String S = "AKIAIOSFODNN7EXAMPLE";',
    'static final String S = "AKIAJSE7QHKZ9REALKEY";',
    'String gk = "AIzaSyDdI0hiBtDFcKQ6lzH8d7g7YnMkHj1234XY";',
    'String gk = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz12345AB";',
    'String pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow";',
    'String gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";',
    'String gh = "ghp_XYZABCDEFGHIJKLMNOPQRSTUVWXYZabcde";',
    'String s = "sk_live_ANOTHERREALLIVE12345678901234";',
    'String bearer = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig";',
    'String token = "ghp_RealGithubTokenXYZABCDEFGHIJKLMNN";',
    'private String apiKey = "sk_live_realKEY9876543210abcdefghij";',
    'final String AWS = "AKIAXYZ123456REALAWSKEY78901234567";',
    'String sk = "sk_live_productionKEY1234567890abXY";',
]

# False positive snippets — credential-format strings that match patterns but are not real
# secrets (zero-entropy, sequential, log-embedded). Rule-only flags them; LLM rejects them.
FP_SNIPPETS: list[str] = [
    # Zero-entropy Stripe keys — match sk_live_ pattern but clearly non-random
    'String k = "sk_live_aaaaaaaaaaaaaaaaaaaaaaaaa";',
    'String k = "sk_live_1234567890123456789012345";',
    'String k = "sk_live_zzzzzzzzzzzzzzzzzzzzzzzzz";',
    'String k = "sk_live_abcdefghijklmnopqrstuvwxyz";',
    'String k = "sk_live_testenvkey12345678901234";',
    # Zero-entropy AWS keys — match AKIA pattern
    'String aws = "AKIAAAAAAAAAAAAAAAAAAA";',
    'String aws = "AKIA1111111111111111";',
    # Zero-entropy Google API key
    'String gk = "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";',
    # Zero-entropy GitHub tokens — match ghp_ pattern
    'String gh = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";',
    'String gh = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";',
    # Keys embedded inside log/comment lines — not real assignments
    '// valid key format: sk_live_testkeytestkey12345678',
    'logger.debug("Using key: sk_live_testenvkey12345678901234");',
    'System.out.println("sk_live_aaaaaaaaaaaaaaaaaaaaaaaaaaa");',
    # Zero-entropy Bearer token
    'String h = "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaa";',
    # Sequential-alphabet Stripe key
    'String k = "sk_live_abcdefghijklmnopqrstuvwx12";',
]

ALL_SNIPPETS = TP_SNIPPETS + FP_SNIPPETS


# ---------------------------------------------------------------------------
# Oracle LLM — determines verdict from content, not external calls
# ---------------------------------------------------------------------------

# Substrings that reliably mark a real secret (appear only in TP_SNIPPETS)
_TP_MARKERS = (
    "sk_live_51", "sk_live_REAL", "sk_live_ANOTHER", "sk_live_real",
    "sk_live_product",
    "AKIAIOSFODNN7EXAMPLE", "AKIAJSE7QHKZ9", "AKIAXYZ123456",
    "AIzaSyDdI0hi", "AIzaSyAbCdEf",
    "BEGIN RSA PRIVATE KEY",
    "ghp_ABCDEF", "ghp_XYZABC", "ghp_RealGithub",
    "Bearer eyJhbGci",
)

# Substrings that reliably mark a non-genuine credential (appear only in FP_SNIPPETS)
_FP_MARKERS = (
    # Zero-entropy / sequential Stripe keys
    "sk_live_aaaa", "sk_live_1234567890", "sk_live_zzzz",
    "sk_live_abcdefg", "sk_live_testenv", "sk_live_testkey",
    # Zero-entropy AWS keys
    "akiaaaaa", "akia1111",
    # Zero-entropy Google key
    "aizasyaaaa",
    # Zero-entropy GitHub tokens
    "ghp_aaaa", "ghp_zzzz",
    # Log / comment embedding
    "valid key format:", "using key: sk_live", "bearer aaaa",
)


def _oracle_analyzer() -> LLMVulnerabilityAnalyzer:
    """Content-based oracle — no LLM required, fully deterministic."""

    async def _decide(
        code_snippet: str,
        file_path: str,
        line_number: int,
        rule_triggered: str,
        rule_confidence: float,
        full_file_context: str,
        app_category: str = "general",
    ) -> LLMVerdict:
        combined = (code_snippet + " " + full_file_context).lower()

        for marker in _TP_MARKERS:
            if marker.lower() in combined:
                return LLMVerdict(
                    verdict=VulnerabilityVerdict.TRUE_POSITIVE,
                    confidence=0.95,
                    reasoning="Oracle: recognised real credential pattern.",
                    vulnerability_type="CWE-798: Use of Hard-coded Credentials",
                    severity="High",
                    remediation_steps=["Remove from source", "Rotate key"],
                    owasp_masvs_mapping=["M2", "MASVS-STORAGE-2"],
                )

        for marker in _FP_MARKERS:
            if marker.lower() in combined:
                return LLMVerdict(
                    verdict=VulnerabilityVerdict.FALSE_POSITIVE,
                    confidence=0.05,
                    reasoning="Oracle: placeholder or comment — not a real credential.",
                    vulnerability_type="CWE-798: Use of Hard-coded Credentials",
                    severity="Info",
                    false_positive_reason="Placeholder / comment / zero-entropy value",
                    remediation_steps=[],
                    owasp_masvs_mapping=[],
                )

        return LLMVerdict(
            verdict=VulnerabilityVerdict.UNCERTAIN,
            confidence=0.5,
            reasoning="Oracle: pattern unrecognised — flagging as uncertain.",
            vulnerability_type="CWE-798: Use of Hard-coded Credentials",
            severity="Info",
            remediation_steps=["Manual review"],
            owasp_masvs_mapping=[],
        )

    mock = MagicMock(spec=LLMVulnerabilityAnalyzer)
    mock.analyze_candidate = AsyncMock(side_effect=_decide)
    return mock


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _build_ctx(tmp_path: Path, snippets: list[str]) -> ScanContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
    decompiled = ws / "jadx" / "sources" / "com" / "example"
    decompiled.mkdir(parents=True)

    # Write each snippet as a separate Java file so candidates are independent
    for i, snippet in enumerate(snippets):
        (decompiled / f"Snippet{i}.java").write_text(
            f"package com.example;\npublic class Snippet{i} {{\n    {snippet}\n}}\n"
        )

    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    c.decompiled_dir = ws / "jadx" / "sources"
    return c


# ---------------------------------------------------------------------------
# Benchmark tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_only_baseline(tmp_path):
    """Rule-only agent flags a mix of TPs and FPs."""
    ctx = _build_ctx(tmp_path, ALL_SNIPPETS)
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()

    agent = A001HardcodedCredsAgent(context=ctx, memory=mem)
    findings = await agent.analyze()
    await mem.close()

    n_tp = len(TP_SNIPPETS)
    n_fp = len(FP_SNIPPETS)
    print(f"\n[baseline] rule-only findings: {len(findings)} "
          f"(labeled TP={n_tp}, FP={n_fp})")

    # Rule-only should catch most TPs
    assert len(findings) >= n_tp * 0.5, (
        f"Rule-only missed too many TPs: {len(findings)} findings from {n_tp} TP snippets"
    )


@pytest.mark.asyncio
async def test_ai_tp_recall(tmp_path):
    """AI pipeline with oracle detects ≥80 % of confirmed true positives."""
    ctx = _build_ctx(tmp_path, TP_SNIPPETS)
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()

    agent = A001AIHardcodedCredsAgent(context=ctx, memory=mem, llm_analyzer=_oracle_analyzer())
    findings = await agent.analyze()
    await mem.close()

    recall = len(findings) / len(TP_SNIPPETS)
    print(f"\n[recall] {len(findings)}/{len(TP_SNIPPETS)} TPs detected ({recall*100:.0f}%)")
    assert recall >= 0.80, f"TP recall too low: {recall*100:.0f}% < 80%"


@pytest.mark.asyncio
async def test_ai_fp_suppression(tmp_path):
    """AI pipeline with oracle suppresses all known false positives."""
    ctx = _build_ctx(tmp_path, FP_SNIPPETS)
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()

    agent = A001AIHardcodedCredsAgent(context=ctx, memory=mem, llm_analyzer=_oracle_analyzer())
    findings = await agent.analyze()
    await mem.close()

    print(f"\n[fp-suppression] {len(findings)} findings on {len(FP_SNIPPETS)} FP snippets")
    assert len(findings) == 0, (
        f"AI agent reported {len(findings)} false positive(s) that should be suppressed"
    )


@pytest.mark.asyncio
async def test_ai_reduces_fp_rate_vs_rule_only(tmp_path):
    """AI pipeline produces fewer findings than rule-only on the full dataset."""
    ctx_rule = _build_ctx(tmp_path / "rule", ALL_SNIPPETS)
    ctx_ai = _build_ctx(tmp_path / "ai", ALL_SNIPPETS)

    mem_rule = LightweightMemory(data_dir=tmp_path / "mem_rule")
    mem_ai = LightweightMemory(data_dir=tmp_path / "mem_ai")
    await mem_rule.connect()
    await mem_ai.connect()

    rule_agent = A001HardcodedCredsAgent(context=ctx_rule, memory=mem_rule)
    rule_findings = await rule_agent.analyze()

    ai_agent = A001AIHardcodedCredsAgent(
        context=ctx_ai, memory=mem_ai, llm_analyzer=_oracle_analyzer()
    )
    ai_findings = await ai_agent.analyze()

    await mem_rule.close()
    await mem_ai.close()

    rule_count = len(rule_findings)
    ai_count = len(ai_findings)
    n_tp = len(TP_SNIPPETS)
    n_fp = len(FP_SNIPPETS)

    print(
        f"\n[benchmark] rule-only={rule_count} findings | AI={ai_count} findings "
        f"| labeled TP={n_tp} FP={n_fp}"
    )

    # AI must retain at least 80 % of true positives (no TP regression)
    assert ai_count >= n_tp * 0.8, (
        f"AI agent lost too many true positives: {ai_count} < {n_tp * 0.8:.0f} (80% of {n_tp} TPs)"
    )

    # AI must produce fewer total findings (FP suppression working)
    assert ai_count < rule_count, (
        f"AI agent produced same or more findings ({ai_count}) as rule-only ({rule_count})"
    )

    # FP reduction must be ≥50 %
    # rule_count includes both TPs and FPs the rule fires on
    # ai_count should be close to just the TP count
    fp_reduction = 1.0 - (ai_count / rule_count)
    print(f"  FP reduction: {fp_reduction*100:.0f}%")
    assert fp_reduction >= 0.50, (
        f"FP reduction {fp_reduction*100:.0f}% < required 50%"
    )
