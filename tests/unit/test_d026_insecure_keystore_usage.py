"""Unit tests for D_026 InsecureKeystoreUsageAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import InsecureKeystoreUsageAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


PURPOSE_ENCRYPT = 0x1
PURPOSE_DECRYPT = 0x2
PURPOSE_SIGN = 0x4
PURPOSE_VERIFY = 0x8


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
    agent = InsecureKeystoreUsageAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_sign_key_without_user_auth_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="auth_signing_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=False,
            strong_box_backed=True),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Insecure Android-Keystore" in findings[0].vuln_class
    # Purposes are decoded for the reader.
    assert "SIGN" in findings[0].evidence["samples"][0]["purposes_decoded"]


@pytest.mark.asyncio
async def test_decrypt_key_without_user_auth_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="token_decrypt_key",
            purposes=PURPOSE_ENCRYPT | PURPOSE_DECRYPT,
            user_auth_required=False,
            strong_box_backed=True),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_user_auth_without_invalidation_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="biometric_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=True,
            invalidated_by_biometric_enrollment=False,
            strong_box_backed=True,
            validity_duration_seconds=-1),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Re-Enrollment" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_long_validity_window_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="auth_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=True,
            invalidated_by_biometric_enrollment=True,
            strong_box_backed=True,
            validity_duration_seconds=300),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Validity Window Too Wide" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_no_strongbox_for_sensitive_purpose_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="auth_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=True,
            invalidated_by_biometric_enrollment=True,
            strong_box_backed=False,
            validity_duration_seconds=-1),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "StrongBox" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_well_configured_key_produces_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="well_configured_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=True,
            invalidated_by_biometric_enrollment=True,
            strong_box_backed=True,
            validity_duration_seconds=-1),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_encrypt_only_key_without_auth_is_ignored(ctx, memory):
    """ENCRYPT-only keys do not gate the user — no finding."""
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="data_encrypt_key",
            purposes=PURPOSE_ENCRYPT,
            user_auth_required=False,
            strong_box_backed=True),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_multiple_findings_from_one_spec(ctx, memory):
    """A spec can trip several rules simultaneously."""
    ctx.sources["frida"] = _capture(
        _ev("keystore.key_spec_built",
            alias="auth_key",
            purposes=PURPOSE_SIGN | PURPOSE_VERIFY,
            user_auth_required=True,
            invalidated_by_biometric_enrollment=False,
            strong_box_backed=False,
            validity_duration_seconds=600),
    )
    findings = await InsecureKeystoreUsageAgent(
        context=ctx, memory=memory,
    ).analyze()
    classes = {f.vuln_class for f in findings}
    assert any("Re-Enrollment" in c for c in classes)
    assert any("Validity Window Too Wide" in c for c in classes)
    assert any("StrongBox" in c for c in classes)
