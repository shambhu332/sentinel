"""Unit tests for the Sprint 8.3 dynamic agents.

Covers:
* D_001 ClipboardLeakAgent
* D_002 FlagSecureMissingAgent
* D_003 BiometricWeakAgent

All tests use synthetic ``FridaCapture`` payloads — no device or real
Frida required.
"""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    BiometricWeakAgent,
    ClipboardLeakAgent,
    FlagSecureMissingAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


# ---------- shared helpers ----------


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events),
        duration_seconds=10.0,
        target_package="com.example.app",
        target_pid=12345,
    )


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
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


# ---------- D_001 ClipboardLeakAgent ----------


@pytest.mark.asyncio
async def test_d001_no_capture_skips(ctx, memory):
    agent = ClipboardLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d001_empty_capture_no_findings(ctx, memory):
    ctx.sources["frida"] = _capture()
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d001_flags_label_with_credential_keyword(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.write",
            label="auth_token", text="opaque",
            mime_types=["text/plain"]),
    )
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "D_001"
    assert f.severity == Severity.HIGH
    assert f.evidence["occurrence_count"] == 1


@pytest.mark.asyncio
async def test_d001_flags_token_shaped_text_without_label(ctx, memory):
    # Token-shaped (≥1 letter, ≥1 digit, 8-64 chars, no whitespace)
    ctx.sources["frida"] = _capture(
        _ev("clipboard.write",
            label="copy", text="aZ19xQ7c8Tg2HhPp",
            mime_types=["text/plain"]),
    )
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    # Redacted preview, not the full value
    sample = findings[0].evidence["samples"][0]["text_preview"]
    assert "aZ19xQ7c8Tg2HhPp" not in sample
    assert "…" in sample


@pytest.mark.asyncio
async def test_d001_ignores_benign_text(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.write",
            label="copy", text="Hello world",
            mime_types=["text/plain"]),
    )
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d001_flags_in_app_read_with_caller_stack(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read",
            stack="com.example.app.PasteSniffer.onResume",
            mime_types=["text/plain"]),
    )
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "Clipboard Read" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d001_ignores_system_paste_ui_read(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read",
            stack="android.widget.Editor$1.onLongClick",
            mime_types=["text/plain"]),
    )
    findings = await ClipboardLeakAgent(context=ctx, memory=memory).analyze()
    assert findings == []


# ---------- D_002 FlagSecureMissingAgent ----------


@pytest.mark.asyncio
async def test_d002_no_capture_skips(ctx, memory):
    agent = FlagSecureMissingAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d002_sensitive_input_without_flag_secure_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("ui.sensitive_input_seen",
            activity="com.example.app.LoginActivity",
            field="password_field"),
    )
    findings = await FlagSecureMissingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "D_002"
    assert f.severity == Severity.HIGH
    assert f.evidence["activity"] == "com.example.app.LoginActivity"
    assert "password_field" in f.evidence["sensitive_fields"]


@pytest.mark.asyncio
async def test_d002_flag_secure_present_suppresses_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("ui.sensitive_input_seen",
            activity="com.example.app.LoginActivity",
            field="password_field"),
        _ev("ui.window_flags",
            activity="com.example.app.LoginActivity",
            flags=8192, secure=True),
    )
    findings = await FlagSecureMissingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d002_window_flags_without_secure_still_flags(ctx, memory):
    # setFlags() called but without FLAG_SECURE — should still flag.
    ctx.sources["frida"] = _capture(
        _ev("ui.sensitive_input_seen",
            activity="com.example.app.PinActivity",
            field="pin_input"),
        _ev("ui.window_flags",
            activity="com.example.app.PinActivity",
            flags=1024, secure=False),
    )
    findings = await FlagSecureMissingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d002_per_activity_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("ui.sensitive_input_seen",
            activity="com.example.app.LoginActivity", field="pw"),
        _ev("ui.sensitive_input_seen",
            activity="com.example.app.OtpActivity", field="otp"),
        # Only OtpActivity sets FLAG_SECURE
        _ev("ui.window_flags",
            activity="com.example.app.OtpActivity",
            flags=8192, secure=True),
    )
    findings = await FlagSecureMissingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].evidence["activity"] == "com.example.app.LoginActivity"


# ---------- D_003 BiometricWeakAgent ----------


@pytest.mark.asyncio
async def test_d003_no_capture_skips(ctx, memory):
    agent = BiometricWeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d003_strong_only_with_crypto_object_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.prompt",
            activity="com.example.app.UnlockActivity",
            authenticators=0x0F,
            device_credential_allowed=False,
            crypto_object=True),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d003_device_credential_bit_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.prompt",
            activity="com.example.app.UnlockActivity",
            authenticators=0x0F | 0x8000,
            crypto_object=True),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "DEVICE_CREDENTIAL" in findings[0].evidence["issue"]


@pytest.mark.asyncio
async def test_d003_legacy_device_credential_allowed_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.prompt",
            activity="com.example.app.UnlockActivity",
            authenticators=0x0F,
            device_credential_allowed=True,
            crypto_object=True),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "setDeviceCredentialAllowed" in findings[0].evidence["issue"]


@pytest.mark.asyncio
async def test_d003_weak_without_strong_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.prompt",
            activity="com.example.app.UnlockActivity",
            authenticators=0xFF,
            crypto_object=True),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "BIOMETRIC_WEAK" in findings[0].evidence["issue"]


@pytest.mark.asyncio
async def test_d003_strong_without_crypto_object_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("biometric.prompt",
            activity="com.example.app.UnlockActivity",
            authenticators=0x0F,
            crypto_object=False),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "CryptoObject" in findings[0].evidence["issue"]


@pytest.mark.asyncio
async def test_d003_ignores_non_biometric_events(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.cipher", algorithm="AES"),
    )
    findings = await BiometricWeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
