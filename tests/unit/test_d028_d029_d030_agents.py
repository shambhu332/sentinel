"""Unit tests for D_028 / D_029 / D_030."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    InAppUpdateInsecureAgent,
    InsecureHostnameVerifierAgent,
    InsecureRandomRuntimeAgent,
)
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


# ---------- D_028 ----------


@pytest.mark.asyncio
async def test_d028_no_capture_skips(ctx, memory):
    assert (await InsecureRandomRuntimeAgent(
        context=ctx, memory=memory,
    ).is_applicable()) is False


@pytest.mark.asyncio
async def test_d028_token_hint_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("random.observation",
            api="Random.nextBytes",
            byte_count=16,
            caller_class="com.example.app.auth.SessionTokenFactory",
            security_context_hint="token"),
    )
    findings = await InsecureRandomRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d028_large_read_without_hint_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("random.observation",
            api="Random.nextBytes",
            byte_count=12,
            caller_class="com.example.app.ui.ConfettiAnimator",
            security_context_hint=""),
    )
    findings = await InsecureRandomRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d028_small_read_without_hint_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("random.observation",
            api="Random.nextInt",
            byte_count=4,
            caller_class="com.example.app.ui.ColorPicker",
            security_context_hint=""),
    )
    findings = await InsecureRandomRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_029 ----------


@pytest.mark.asyncio
async def test_d029_no_capture_skips(ctx, memory):
    assert (await InsecureHostnameVerifierAgent(
        context=ctx, memory=memory,
    ).is_applicable()) is False


@pytest.mark.asyncio
async def test_d029_global_bypass_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.hostname_verifier_invoked",
            verifier_class="com.example.app.net.PermissiveVerifier",
            hostname="api.example.com",
            accepted=True,
            default_would_accept=False),
        _ev("tls.hostname_verifier_invoked",
            verifier_class="com.example.app.net.PermissiveVerifier",
            hostname="evil.attacker.com",
            accepted=True,
            default_would_accept=False),
    )
    findings = await InsecureHostnameVerifierAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d029_deliberate_allow_list_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.hostname_verifier_invoked",
            verifier_class="com.example.app.net.AllowInternalHosts",
            hostname="internal.lan",
            accepted=True,
            default_would_accept=False),
    )
    findings = await InsecureHostnameVerifierAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d029_default_accepting_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.hostname_verifier_invoked",
            verifier_class="com.example.app.net.SomeVerifier",
            hostname="api.example.com",
            accepted=True,
            default_would_accept=True),
    )
    findings = await InsecureHostnameVerifierAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_030 ----------


@pytest.mark.asyncio
async def test_d030_no_capture_skips(ctx, memory):
    assert (await InAppUpdateInsecureAgent(
        context=ctx, memory=memory,
    ).is_applicable()) is False


@pytest.mark.asyncio
async def test_d030_http_source_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("apk_install.committed",
            session_id=42,
            source_scheme="http",
            source_url="http://updates.example.com/v2.apk",
            signature_verified=False),
    )
    findings = await InAppUpdateInsecureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d030_https_without_signature_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("apk_install.committed",
            session_id=42,
            source_scheme="https",
            source_url="https://updates.example.com/v2.apk",
            signature_verified=False),
    )
    findings = await InAppUpdateInsecureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d030_https_with_signature_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("apk_install.committed",
            session_id=42,
            source_scheme="https",
            source_url="https://updates.example.com/v2.apk",
            signature_verified=True,
            signature_class_seen="PackageManager.getPackageArchiveInfo"),
    )
    findings = await InAppUpdateInsecureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d030_unknown_source_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("apk_install.committed",
            session_id=42,
            source_scheme="",
            source_url="",
            signature_verified=False),
    )
    findings = await InAppUpdateInsecureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
