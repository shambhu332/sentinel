"""Unit tests for D_038 / D_039 / D_040 / D_041."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    BiometricDeviceCredentialFallbackAgent,
    InsecureTrustManagerRuntimeAgent,
    NotificationFloodAgent,
    OkHttpLoggingRuntimeAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent

BIOMETRIC_STRONG = 0x0F
BIOMETRIC_WEAK = 0xFF
DEVICE_CREDENTIAL = 0x8000


def _ev(kind: str, timestamp: float = 0.0, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=timestamp)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events), duration_seconds=30.0,
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


# ---------- D_038 ----------


@pytest.mark.asyncio
async def test_d038_global_bypass_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.trust_manager_invoked",
            tm_class="com.example.app.net.PermissiveTM",
            chain_subject="CN=api.example.com",
            auth_type="RSA",
            accepted=True, default_would_accept=False),
        _ev("tls.trust_manager_invoked",
            tm_class="com.example.app.net.PermissiveTM",
            chain_subject="CN=evil.attacker.com",
            auth_type="RSA",
            accepted=True, default_would_accept=False),
    )
    findings = await InsecureTrustManagerRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d038_deliberate_single_host_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.trust_manager_invoked",
            tm_class="com.example.app.net.AllowInternalTM",
            chain_subject="CN=internal.lan",
            auth_type="RSA",
            accepted=True, default_would_accept=False),
    )
    findings = await InsecureTrustManagerRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d038_default_accepting_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tls.trust_manager_invoked",
            tm_class="com.example.app.net.SomeTM",
            chain_subject="CN=api.example.com",
            auth_type="RSA",
            accepted=True, default_would_accept=True),
    )
    findings = await InsecureTrustManagerRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_039 ----------


@pytest.mark.asyncio
async def test_d039_body_level_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("okhttp.logging_level_observed",
            level="BODY",
            interceptor_class="com.example.app.net.LoggingInterceptor",
            caller_class="com.example.app.net.ApiClient"),
    )
    findings = await OkHttpLoggingRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d039_headers_level_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("okhttp.logging_level_observed",
            level="HEADERS",
            interceptor_class="com.example.app.net.LoggingInterceptor"),
    )
    findings = await OkHttpLoggingRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d039_body_dedupes_per_interceptor(ctx, memory):
    """One interceptor running 1000 requests must fire one finding."""
    ctx.sources["frida"] = _capture(
        *[_ev("okhttp.logging_level_observed",
              level="BODY",
              interceptor_class="com.example.app.net.LoggingInterceptor")
          for _ in range(5)],
    )
    findings = await OkHttpLoggingRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].evidence["occurrence_count"] == 1


# ---------- D_040 ----------


@pytest.mark.asyncio
async def test_d040_crypto_with_credential_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.authenticate_called",
            allowed_authenticators=BIOMETRIC_STRONG | DEVICE_CREDENTIAL,
            has_crypto=True,
            caller_class="com.example.app.auth.LoginViewModel"),
    )
    findings = await BiometricDeviceCredentialFallbackAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Bypassable via PIN" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d040_weak_only_no_crypto_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.authenticate_called",
            allowed_authenticators=BIOMETRIC_WEAK,
            has_crypto=False,
            caller_class="com.example.app.auth.ApprovalViewModel"),
    )
    findings = await BiometricDeviceCredentialFallbackAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Class-2" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d040_credential_no_crypto_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.authenticate_called",
            allowed_authenticators=BIOMETRIC_STRONG | DEVICE_CREDENTIAL,
            has_crypto=False,
            caller_class="com.example.app.auth.PinViewModel"),
    )
    findings = await BiometricDeviceCredentialFallbackAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d040_strong_only_with_crypto_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.authenticate_called",
            allowed_authenticators=BIOMETRIC_STRONG,
            has_crypto=True,
            caller_class="com.example.app.auth.LoginViewModel"),
    )
    findings = await BiometricDeviceCredentialFallbackAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_041 ----------


@pytest.mark.asyncio
async def test_d041_burst_of_ten_is_high(ctx, memory):
    # 10 notifications in 2 seconds = HIGH (>= 10 within 5s window).
    events = [
        _ev("notification.posted", timestamp=float(i) * 0.2)
        for i in range(10)
    ]
    ctx.sources["frida"] = _capture(*events)
    findings = await NotificationFloodAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d041_burst_of_six_is_medium(ctx, memory):
    events = [
        _ev("notification.posted", timestamp=float(i) * 0.5)
        for i in range(6)
    ]
    ctx.sources["frida"] = _capture(*events)
    findings = await NotificationFloodAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d041_spread_out_is_clean(ctx, memory):
    # 20 notifications, one every 10 seconds — never more than one in
    # any 5-second window.
    events = [
        _ev("notification.posted", timestamp=float(i) * 10.0)
        for i in range(20)
    ]
    ctx.sources["frida"] = _capture(*events)
    findings = await NotificationFloodAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d041_no_notifications_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture()
    findings = await NotificationFloodAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
