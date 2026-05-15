"""Unit tests for Sprint 8.2 Frida agent (A_003 Runtime Crypto).

These tests use synthetic FridaCapture fixtures — no real device or
Frida required. Tests run in CI without hardware.
"""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import RuntimeCryptoAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent

# ---------- Helpers ----------


def _make_crypto_event(algorithm: str, kind: str = "crypto.cipher") -> FridaHookEvent:
    return FridaHookEvent(
        kind=kind,
        payload={"algorithm": algorithm, "kind": kind},
        timestamp=0.0,
    )


def _make_capture(events: list[FridaHookEvent]) -> FridaCapture:
    return FridaCapture(
        events=events,
        duration_seconds=10.0,
        target_package="com.example.app",
        target_pid=12345,
    )


@pytest.fixture
def ctx(tmp_path):
    apk_path = tmp_path / "dummy.apk"
    apk_path.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk_path,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


# ---------- A_003: Runtime Crypto ----------


@pytest.mark.asyncio
async def test_a003_no_capture_returns_no_findings(ctx, memory):
    """No Frida capture → no findings."""
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_a003_empty_capture_returns_no_findings(ctx, memory):
    """Frida capture with zero events → no findings."""
    ctx.sources["frida"] = _make_capture([])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_a003_strong_aes_only_no_finding(ctx, memory):
    """Strong algorithms only → no findings."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("AES/GCM/NoPadding"),
        _make_crypto_event("AES/CBC/PKCS5Padding"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_a003_des_produces_critical_finding(ctx, memory):
    """DES in runtime use → CRITICAL severity."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("DES/ECB/PKCS5Padding"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) >= 1
    des_findings = [
        f for f in findings
        if "DES" in f.evidence.get("weak_algorithm_description", "")
    ]
    assert len(des_findings) >= 1
    assert des_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_a003_rc4_produces_critical_finding(ctx, memory):
    """RC4 in runtime → CRITICAL."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("RC4"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    rc4 = [f for f in findings
           if "RC4" in f.evidence.get("weak_algorithm_description", "")]
    assert len(rc4) == 1
    assert rc4[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_a003_md5_produces_high_finding(ctx, memory):
    """MD5 hash in runtime → HIGH."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("MD5", kind="crypto.digest"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    md5 = [f for f in findings
           if "MD5" in f.evidence.get("weak_algorithm_description", "")]
    assert len(md5) == 1
    assert md5[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_a003_sha1_produces_medium_finding(ctx, memory):
    """SHA-1 in runtime → MEDIUM (downgraded from HIGH because still some use)."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("SHA-1", kind="crypto.digest"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    sha1 = [f for f in findings
            if "SHA-1" in f.evidence.get("weak_algorithm_description", "")]
    assert len(sha1) == 1
    assert sha1[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_a003_ecb_mode_detected(ctx, memory):
    """AES in ECB mode → HIGH severity (mode leak, not the cipher itself)."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("AES/ECB/PKCS5Padding"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    ecb = [f for f in findings
           if "ECB" in f.evidence.get("weak_algorithm_description", "")]
    assert len(ecb) == 1
    assert ecb[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_a003_aggregates_multiple_calls_into_one_finding(ctx, memory):
    """Same algorithm called many times → one aggregated finding."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("DES") for _ in range(5)
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    des = [f for f in findings
           if "DES" in f.evidence.get("weak_algorithm_description", "")]
    assert len(des) == 1
    assert des[0].evidence["occurrence_count"] == 5


@pytest.mark.asyncio
async def test_a003_multiple_weak_algos_separate_findings(ctx, memory):
    """Different weak algorithms → separate findings."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("DES"),
        _make_crypto_event("MD5", kind="crypto.digest"),
        _make_crypto_event("RC4"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    # We expect 3 distinct findings (DES, MD5, RC4)
    descriptions = [
        f.evidence.get("weak_algorithm_description", "") for f in findings
    ]
    assert any("DES" in d for d in descriptions)
    assert any("MD5" in d for d in descriptions)
    assert any("RC4" in d for d in descriptions)


@pytest.mark.asyncio
async def test_a003_evidence_includes_all_observed_algorithms(ctx, memory):
    """Evidence must include the full list of algos observed for context."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("DES"),
        _make_crypto_event("AES/GCM/NoPadding"),
        _make_crypto_event("AES/CBC/PKCS5Padding"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1  # Only DES is weak
    observed = findings[0].evidence["all_algorithms_observed"]
    assert "DES" in observed
    assert "AES/GCM/NoPadding" in observed
    assert "AES/CBC/PKCS5Padding" in observed


@pytest.mark.asyncio
async def test_a003_high_confidence_for_runtime_observation(ctx, memory):
    """Runtime observation → confidence 0.95 (much higher than SAST regex)."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("DES"),
    ])
    agent = RuntimeCryptoAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings[0].confidence >= 0.9
