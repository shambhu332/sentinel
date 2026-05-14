"""Unit tests for Sprint 8.1 dynamic agents (N_003, N_004).

These tests use synthetic CapturedFlow fixtures — no real network capture
required. Tests run in CI without a device.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic import DataInTransitAgent, ImproperTLSAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture

# ---------- Helpers ----------


def _make_flow(
    host: str,
    scheme: str = "https",
    method: str = "GET",
    url: str | None = None,
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    response_status: int = 200,
    response_headers: dict[str, str] | None = None,
    response_body: str = "",
    tls_failed: bool = False,
    path: str = "/",
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        url=url or f"{scheme}://{host}{path}",
        scheme=scheme,
        host=host,
        path=path,
        request_headers=request_headers or {},
        request_body=request_body,
        response_status=response_status,
        response_headers=response_headers or {},
        response_body=response_body,
        tls_failed=tls_failed,
        timestamp=0.0,
    )


def _make_capture(flows: list[CapturedFlow]) -> MitmproxyCapture:
    return MitmproxyCapture(
        flows=flows,
        capture_file=Path("/tmp/test.jsonl"),
        duration_seconds=10.0,
        flow_count=len(flows),
    )


@pytest.fixture
def ctx(tmp_path):
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=tmp_path / "dummy.apk",
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


# ---------- N_003: Improper TLS ----------


@pytest.mark.asyncio
async def test_n003_no_capture_returns_no_findings(ctx, memory):
    """If Phase 4 didn't run, N_003 must produce zero findings."""
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n003_empty_capture_returns_no_findings(ctx, memory):
    """Empty capture is a no-op, not an error."""
    ctx.sources["mitmproxy"] = _make_capture([])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n003_all_pinned_no_finding(ctx, memory):
    """When every host fails TLS handshake (pinning works), no finding."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com", tls_failed=True),
        _make_flow("auth.example.com", tls_failed=True),
    ])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n003_unpinned_host_produces_finding(ctx, memory):
    """A host that successfully completed HTTPS through proxy → finding."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com", scheme="https", response_status=200),
        _make_flow("api.example.com", scheme="https", response_status=200),
    ])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_003"
    hosts = f.evidence["hosts_without_pinning"]
    assert any(h["host"] == "api.example.com" for h in hosts)


@pytest.mark.asyncio
async def test_n003_high_severity_for_auth_host(ctx, memory):
    """Auth/banking hosts produce HIGH severity even with one match."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("auth.bank.example.com", scheme="https",
                   response_status=200),
    ])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_n003_low_severity_for_only_analytics(ctx, memory):
    """When only low-sensitivity (analytics) hosts are unpinned → LOW."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("analytics.example.com", scheme="https",
                   response_status=200),
        _make_flow("static.example.com", scheme="https", response_status=200),
    ])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_n003_mixed_returns_pinned_hosts_in_evidence(ctx, memory):
    """Pinned hosts should be listed as context in the evidence."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com", scheme="https", response_status=200),
        _make_flow("pinned.example.com", tls_failed=True),
    ])
    agent = ImproperTLSAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    f = findings[0]
    assert "pinned.example.com" in f.evidence["hosts_with_pinning"]


# ---------- N_004: Data In Transit ----------


@pytest.mark.asyncio
async def test_n004_no_capture_returns_no_findings(ctx, memory):
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n004_clean_traffic_returns_no_findings(ctx, memory):
    """HTTPS traffic with no sensitive data → no findings."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com", response_body='{"status":"ok"}'),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_n004_jwt_in_response_body(ctx, memory):
    """JWT in response body produces an auth_token finding."""
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTczMDAwMDAwMH0."
        "abc123signature_xyz789def456"
    )
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com",
                   response_body=f'{{"token":"{jwt}"}}',
                   scheme="https"),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    auth_findings = [f for f in findings
                     if f.evidence.get("category") == "auth_token"]
    assert len(auth_findings) == 1


@pytest.mark.asyncio
async def test_n004_jwt_over_cleartext_is_critical(ctx, memory):
    """Same JWT over HTTP → CRITICAL severity."""
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTczMDAwMDAwMH0."
        "signature_in_cleartext_traffic"
    )
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow("api.example.com", scheme="http",
                   response_body=f'{{"token":"{jwt}"}}'),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    auth_findings = [f for f in findings
                     if f.evidence.get("category") == "auth_token"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_n004_bearer_in_authorization_header_not_flagged(ctx, memory):
    """Bearer in Authorization header over HTTPS = normal, no finding."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com",
            scheme="https",
            request_headers={"Authorization": "Bearer abc123def456ghi789jkl"},
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    auth_findings = [f for f in findings
                     if f.evidence.get("category") == "auth_token"]
    assert auth_findings == []


@pytest.mark.asyncio
async def test_n004_bearer_in_url_flagged_as_high(ctx, memory):
    """Auth token in URL (logged everywhere) → HIGH severity."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com",
            scheme="https",
            url="https://api.example.com/me?access_token=eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiJ1c2VyMSJ9.signature_data_here_long_enough",
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    auth_findings = [f for f in findings
                     if f.evidence.get("category") == "auth_token"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_n004_password_in_post_body_cleartext(ctx, memory):
    """Plain password in form body over HTTP → credential CRITICAL."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com", scheme="http", method="POST",
            request_body="username=alice&password=hunter2",
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    cred_findings = [f for f in findings
                     if f.evidence.get("category") == "credential"]
    assert len(cred_findings) == 1
    assert cred_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_n004_password_https_is_high_not_critical(ctx, memory):
    """Password over HTTPS → HIGH (still concerning, less than cleartext)."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com", scheme="https", method="POST",
            request_body='{"username":"alice","password":"hunter2"}',
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    cred_findings = [f for f in findings
                     if f.evidence.get("category") == "credential"]
    assert len(cred_findings) == 1
    assert cred_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_n004_google_api_key_in_url(ctx, memory):
    """A real-looking Google API key (AIza prefix + 35 chars) → finding."""
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com", scheme="https",
            url="https://api.example.com/?key=AIzaSyA1234567890ABCDEFGHIJKLMNOPQR3st",
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    api_findings = [f for f in findings
                    if f.evidence.get("category") == "api_key"]
    assert len(api_findings) == 1


@pytest.mark.asyncio
async def test_n004_aggregates_multiple_leaks_into_one_finding_per_category(ctx, memory):
    """Many same-category leaks → one aggregated finding, not many."""
    flows = []
    for i in range(5):
        flows.append(_make_flow(
            "api.example.com", scheme="http", method="POST",
            request_body=f"username=user{i}&password=secret{i}",
        ))
    ctx.sources["mitmproxy"] = _make_capture(flows)
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    cred_findings = [f for f in findings
                     if f.evidence.get("category") == "credential"]
    assert len(cred_findings) == 1
    assert cred_findings[0].evidence["leak_count"] == 5


@pytest.mark.asyncio
async def test_n004_redaction_obscures_full_value(ctx, memory):
    """Redacted values must not expose the full secret."""
    secret = "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRdgw"
    ctx.sources["mitmproxy"] = _make_capture([
        _make_flow(
            "api.example.com", scheme="https",
            url=f"https://api.example.com/?key={secret}",
        ),
    ])
    agent = DataInTransitAgent(context=ctx, memory=memory)
    findings = await agent.run()
    api_findings = [f for f in findings
                    if f.evidence.get("category") == "api_key"]
    assert len(api_findings) == 1
    samples = api_findings[0].evidence["samples"]
    assert len(samples) >= 1
    redacted = samples[0]["redacted_value"]
    assert secret not in redacted
    assert "..." in redacted
