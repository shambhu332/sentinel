"""Unit tests for D_006 StaticIvReuseAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import StaticIvReuseAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events), duration_seconds=10.0,
        target_package="com.example.app", target_pid=12345,
    )


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path, scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = StaticIvReuseAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_iv_reuse_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.iv_constructed",
            algorithm="GCMParameterSpec",
            iv_hex="aabbccddeeff0011", iv_len=12),
        _ev("crypto.iv_constructed",
            algorithm="GCMParameterSpec",
            iv_hex="aabbccddeeff0011", iv_len=12),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "D_006"
    assert f.severity == Severity.HIGH
    assert f.evidence["occurrence_count"] == 2


@pytest.mark.asyncio
async def test_constant_zero_iv_single_use_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.iv_constructed",
            algorithm="IvParameterSpec",
            iv_hex="00000000",
            iv_len=16,
            constant_pattern="zero"),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_single_random_iv_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.iv_constructed",
            algorithm="GCMParameterSpec",
            iv_hex="deadbeef12345678",
            iv_len=12),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_iv_reuse_grouped_per_algorithm_and_iv(ctx, memory):
    # Same iv_hex under two algorithms = two distinct groups, no reuse
    # inside either; no finding.
    ctx.sources["frida"] = _capture(
        _ev("crypto.iv_constructed",
            algorithm="IvParameterSpec",
            iv_hex="abcd", iv_len=16),
        _ev("crypto.iv_constructed",
            algorithm="GCMParameterSpec",
            iv_hex="abcd", iv_len=12),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_key_reuse_across_algorithms_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.secret_key_created",
            algorithm="AES", key_hex="aabbcc", key_len=32),
        _ev("crypto.secret_key_created",
            algorithm="HmacSHA256", key_hex="aabbcc", key_len=32),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "Hardcoded Key" in f.vuln_class
    assert "AES" in f.evidence["algorithms"]
    assert "HmacSHA256" in f.evidence["algorithms"]


@pytest.mark.asyncio
async def test_key_same_algorithm_no_finding(ctx, memory):
    # Reuse under a single algorithm is not yet a finding — many keys
    # are re-instantiated from KeyStore reads.
    ctx.sources["frida"] = _capture(
        _ev("crypto.secret_key_created",
            algorithm="AES", key_hex="aabbcc", key_len=32),
        _ev("crypto.secret_key_created",
            algorithm="AES", key_hex="aabbcc", key_len=32),
    )
    findings = await StaticIvReuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
