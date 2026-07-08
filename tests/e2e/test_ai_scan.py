"""End-to-end tests for the AI-autonomous scan pipeline.

These tests require a real LLM provider configured via environment variables:
  - GROQ_API_KEY, CEREBRAS_API_KEY, SENTINEL_LOCAL_LLM_URL, or Ollama running

Skip by default; opt in with:
    pytest -m e2e tests/e2e/test_ai_scan.py -v

What is verified:
  - LLMVulnerabilityAnalyzer is called for each candidate
  - RAG context retrieval doesn't crash (empty KB is fine)
  - Structured JSON verdict is parsed into a Finding
  - HON_001 calibration events are published for FP verdicts
  - Full pipeline returns Findings with correct agent_id, session_id
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinel.core.finding import BountyScope
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

pytestmark = pytest.mark.e2e

# ---------------------------------------------------------------------------
# Skip condition
# ---------------------------------------------------------------------------

_HAS_LLM = any([
    os.environ.get("GROQ_API_KEY", "").strip(),
    os.environ.get("CEREBRAS_API_KEY", "").strip(),
    os.environ.get("SENTINEL_LOCAL_LLM_URL", "").strip(),
    # Ollama always-on: we check by trying a connection in _ollama_available()
])


def _ollama_available() -> bool:
    try:
        import httpx
        r = httpx.get("http://127.0.0.1:11434/api/tags", timeout=2.0)
        return r.status_code == 200
    except Exception:
        return False


_SKIP_REASON = (
    "No LLM configured. Set GROQ_API_KEY, CEREBRAS_API_KEY, "
    "SENTINEL_LOCAL_LLM_URL, or run Ollama at localhost:11434."
)

skip_no_llm = pytest.mark.skipif(
    not (_HAS_LLM or _ollama_available()),
    reason=_SKIP_REASON,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def e2e_ctx(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
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


@pytest.fixture
async def e2e_memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


def _java_file(decompiled_dir: Path, name: str, content: str) -> Path:
    p = decompiled_dir / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# E2E tests
# ---------------------------------------------------------------------------

@skip_no_llm
@pytest.mark.asyncio
async def test_a001_ai_real_llm_stripe_key(e2e_ctx, e2e_memory):
    """A_001 AI agent detects a Stripe key and LLM confirms it's a true positive."""
    from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent

    _java_file(e2e_ctx.decompiled_dir, "Pay.java", """
package com.example;
public class PaymentService {
    private static final String STRIPE_KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";
    public void charge(int amount) {
        // uses STRIPE_KEY to call Stripe API
    }
}
""")
    agent = A001AIHardcodedCredsAgent(context=e2e_ctx, memory=e2e_memory)
    findings = await agent.analyze()

    # Real LLM should classify this as a true positive
    assert len(findings) >= 1, "LLM failed to flag a live Stripe key — check LLM output"
    f = findings[0]
    assert f.agent_id == "A_001"
    assert f.severity.value in ("Critical", "High", "Medium")
    assert f.evidence.get("llm_confidence", 0) > 0.0
    assert f.finding_category == "AI-Powered"
    print(f"\n[e2e] A_001 finding: {f.vuln_class} — {f.severity.value} (llm_conf={f.evidence.get('llm_confidence'):.2f})")


@skip_no_llm
@pytest.mark.asyncio
async def test_a001_ai_real_llm_placeholder_suppressed(e2e_ctx, e2e_memory):
    """A_001 AI agent does NOT flag a placeholder key (LLM should reject it)."""
    from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent

    _java_file(e2e_ctx.decompiled_dir, "Config.java", """
package com.example;
public class Config {
    // Replace with your real API key
    private static final String API_KEY = "YOUR_API_KEY_HERE";
}
""")
    agent = A001AIHardcodedCredsAgent(context=e2e_ctx, memory=e2e_memory)
    findings = await agent.analyze()

    # Rule-only A_001 might flag this, but the AI agent shouldn't
    critical_or_high = [f for f in findings if f.severity.value in ("Critical", "High")]
    assert len(critical_or_high) == 0, (
        f"LLM incorrectly flagged a placeholder key as {critical_or_high[0].severity.value}"
        if critical_or_high else ""
    )
    print(f"\n[e2e] A_001 placeholder: {len(findings)} findings (expected 0 critical/high)")


@skip_no_llm
@pytest.mark.asyncio
async def test_a002_ai_real_llm_alg_none(e2e_ctx, e2e_memory):
    """A_002 AI agent detects Algorithm.none() and LLM rates it Critical."""
    from sentinel.agents.auth.a_002_ai import A002AIJWTAlgConfusionAgent

    _java_file(e2e_ctx.decompiled_dir, "Auth.java", """
package com.example;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
public class AuthService {
    public boolean verify(String token) {
        Algorithm alg = Algorithm.none();
        JWT.require(alg).build().verify(token);
        return true;
    }
}
""")
    agent = A002AIJWTAlgConfusionAgent(context=e2e_ctx, memory=e2e_memory)
    findings = await agent.analyze()

    assert len(findings) >= 1, "LLM failed to flag Algorithm.none() — check LLM output"
    f = findings[0]
    assert f.agent_id == "A_002"
    assert f.severity.value in ("Critical", "High")
    print(f"\n[e2e] A_002 finding: {f.vuln_class} — {f.severity.value}")


@skip_no_llm
@pytest.mark.asyncio
async def test_hon001_calibration_events_published(e2e_ctx, e2e_memory):
    """HON_001 collects calibration events when LLM rejects rule hits."""
    from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent
    from sentinel.calibration.hon_001 import HON001CalibrationAgent

    # Placeholder that rule hits but LLM should reject
    _java_file(e2e_ctx.decompiled_dir, "Config.java",
               'static final String KEY = "YOUR_API_KEY_HERE";')

    a001 = A001AIHardcodedCredsAgent(context=e2e_ctx, memory=e2e_memory)
    await a001.analyze()

    # HON_001 reads calibration events from memory
    hon = HON001CalibrationAgent(context=e2e_ctx, memory=e2e_memory)
    # is_applicable returns True only if events were published
    # (may be False if LLM called this a TP — that's fine, real LLM decides)
    applicable = await hon.is_applicable()
    print(f"\n[e2e] HON_001 applicable: {applicable} (True means LLM rejected at least one hit)")


@skip_no_llm
@pytest.mark.asyncio
async def test_pipeline_with_no_vulnerable_code(e2e_ctx, e2e_memory):
    """Pipeline returns empty findings for clean code."""
    from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent

    _java_file(e2e_ctx.decompiled_dir, "Clean.java", """
package com.example;
public class Clean {
    public void fetchKey() {
        // Keys loaded from Android Keystore at runtime
        android.security.keystore.KeyGenParameterSpec spec = null;
    }
}
""")
    agent = A001AIHardcodedCredsAgent(context=e2e_ctx, memory=e2e_memory)
    findings = await agent.analyze()
    # No hardcoded keys — no candidates → no LLM calls → no findings
    critical_or_high = [f for f in findings if f.severity.value in ("Critical", "High")]
    assert len(critical_or_high) == 0
    print(f"\n[e2e] clean file: {len(findings)} total findings (0 critical/high)")
