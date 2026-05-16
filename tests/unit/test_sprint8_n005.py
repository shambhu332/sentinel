"""Unit tests for Sprint 8.2 Part B Frida agent (N_005 Cert Pinning Bypass).

Uses synthetic FridaCapture fixtures — no real device or Frida required.
Tests run in CI without hardware.
"""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import CertPinningBypassAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent

# ---------- Helpers ----------


def _make_tls_event(
    kind: str,
    library: str = "okhttp.CertificatePinner",
    **payload_extras: object,
) -> FridaHookEvent:
    payload = {"kind": kind, "library": library, **payload_extras}
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _make_crypto_event(algorithm: str = "AES") -> FridaHookEvent:
    return FridaHookEvent(
        kind="crypto.cipher",
        payload={"algorithm": algorithm, "kind": "crypto.cipher"},
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


# ---------- N_005 ----------


@pytest.mark.asyncio
async def test_n005_no_capture_returns_no_findings(ctx, memory):
    """No Frida capture -> no findings, agent skipped."""
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n005_empty_capture_returns_no_findings(ctx, memory):
    """Frida capture with zero events -> no findings."""
    ctx.sources["frida"] = _make_capture([])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n005_only_crypto_events_no_tls_findings(ctx, memory):
    """Capture containing only crypto events (A_003 territory) -> no N_005 findings."""
    ctx.sources["frida"] = _make_capture([
        _make_crypto_event("AES"),
        _make_crypto_event("DES"),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n005_okhttp_bypass_produces_high_finding(ctx, memory):
    """OkHttp CertificatePinner bypass -> HIGH severity bug finding."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event(
            "tls.bypass",
            library="okhttp.CertificatePinner",
            method="check(String, List)",
            host="api.example.com",
        ),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.85
    assert finding.vuln_class == "Certificate Pinning Bypass"
    assert "okhttp.CertificatePinner" in finding.evidence["bypassed_libraries"]
    assert "api.example.com" in finding.evidence["hosts_observed"]


@pytest.mark.asyncio
async def test_n005_conscrypt_only_produces_medium_finding(ctx, memory):
    """Only a medium-tier library bypassed -> MEDIUM severity, not HIGH."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event(
            "tls.bypass",
            library="Conscrypt.Platform",
            method="checkServerTrusted",
        ),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_n005_mixed_libraries_severity_takes_highest(ctx, memory):
    """Bypass on HIGH + MEDIUM libraries -> finding severity is HIGH."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event("tls.bypass", library="Conscrypt.Platform"),
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner",
                        host="auth.example.com"),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    libs = findings[0].evidence["bypassed_libraries"]
    assert "okhttp.CertificatePinner" in libs
    assert "Conscrypt.Platform" in libs


@pytest.mark.asyncio
async def test_n005_multiple_bypasses_same_library_aggregated(ctx, memory):
    """Many bypass calls on the same library -> one finding, counts preserved."""
    events = [
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner",
                        host=f"host{i}.example.com")
        for i in range(5)
    ]
    ctx.sources["frida"] = _make_capture(events)
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["per_library_counts"]["okhttp.CertificatePinner"] == 5
    # Hosts captured up to cap
    assert len(finding.evidence["hosts_observed"]) == 5


@pytest.mark.asyncio
async def test_n005_bypass_failed_produces_info_survived_finding(ctx, memory):
    """tls.bypass_failed only -> INFO 'survived' finding, no bug finding."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event(
            "tls.bypass_failed",
            library="okhttp.CertificatePinner",
            error="overload mismatch on check()",
        ),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.INFO
    assert finding.vuln_class == "Certificate Pinning Resistance"
    assert "okhttp.CertificatePinner" in finding.evidence["resistant_libraries"]


@pytest.mark.asyncio
async def test_n005_both_bypass_and_failed_produces_two_findings(ctx, memory):
    """Mixed bypass + bypass_failed events -> two findings (HIGH bug + INFO survived)."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner"),
        _make_tls_event(
            "tls.bypass_failed",
            library="TrustKit",
            error="anti-Frida check fired",
        ),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    assert Severity.INFO in severities
    vuln_classes = {f.vuln_class for f in findings}
    assert "Certificate Pinning Bypass" in vuln_classes
    assert "Certificate Pinning Resistance" in vuln_classes


@pytest.mark.asyncio
async def test_n005_hooks_installed_summary_included_in_evidence(ctx, memory):
    """tls.hooks_installed event -> hooks_installed list propagates to evidence."""
    ctx.sources["frida"] = _make_capture([
        FridaHookEvent(
            kind="tls.hooks_installed",
            payload={
                "kind": "tls.hooks_installed",
                "libraries": ["okhttp.CertificatePinner", "Conscrypt.Platform"],
                "count": 2,
            },
            timestamp=0.0,
        ),
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner"),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].evidence["hooks_installed"] == [
        "okhttp.CertificatePinner", "Conscrypt.Platform",
    ]


@pytest.mark.asyncio
async def test_n005_high_confidence_for_runtime_observation(ctx, memory):
    """Runtime bypass -> confidence >= 0.85 (much higher than SAST)."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner"),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings[0].confidence >= 0.85


@pytest.mark.asyncio
async def test_n005_unknown_library_treated_as_medium(ctx, memory):
    """A bypass event on an unfamiliar library -> defaults to MEDIUM weight."""
    ctx.sources["frida"] = _make_capture([
        _make_tls_event("tls.bypass", library="some.custom.NoOneEverHeardOf"),
    ])
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_n005_evidence_caps_samples_at_15(ctx, memory):
    """Large bypass event count -> samples capped at 15 to avoid blowing evidence size."""
    events = [
        _make_tls_event("tls.bypass", library="okhttp.CertificatePinner",
                        host=f"host{i}.example.com")
        for i in range(50)
    ]
    ctx.sources["frida"] = _make_capture(events)
    agent = CertPinningBypassAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert len(findings[0].evidence["sample_bypasses"]) <= 15
