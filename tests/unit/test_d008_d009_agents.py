"""Unit tests for the Sprint 8.5 business-logic dynamic agents.

* D_008 IapBypassAgent
* D_009 IdorCandidateAgent
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic import IapBypassAgent, IdorCandidateAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _fcapture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events), duration_seconds=10.0,
        target_package="com.example.app", target_pid=12345,
    )


def _flow(
    method: str, path: str,
    *, host: str = "api.example.com",
    status: int = 200,
    body: str = "",
    req_body: str = "",
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        url=f"https://{host}{path}",
        scheme="https", host=host, path=path,
        request_body=req_body,
        response_status=status,
        response_body=body,
    )


def _mcapture(*flows: CapturedFlow) -> MitmproxyCapture:
    return MitmproxyCapture(
        flows=list(flows), capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=10.0, flow_count=len(flows),
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


# ---------- D_008 ----------


@pytest.mark.asyncio
async def test_d008_no_capture_skips(ctx, memory):
    agent = IapBypassAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d008_unlock_without_verification_is_high(ctx, memory):
    ctx.sources["frida"] = _fcapture(
        _ev("billing.purchase_observed",
            sku="pro_unlock", purchase_state=1,
            order_id="GPA.1", token_prefix="abcd1234efgh5678",
            acknowledged=True),
        _ev("billing.feature_unlock",
            entitlement="pro", source="MainActivity"),
    )
    # No mitmproxy flow contains the token prefix.
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("GET", "/api/v1/profile", body='{"id":1}'),
    )
    findings = await IapBypassAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d008_verification_present_no_finding(ctx, memory):
    ctx.sources["frida"] = _fcapture(
        _ev("billing.purchase_observed",
            sku="pro_unlock", purchase_state=1,
            order_id="GPA.1", token_prefix="abcd1234efgh5678",
            acknowledged=True),
        _ev("billing.feature_unlock",
            entitlement="pro", source="MainActivity"),
    )
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("POST", "/api/v1/iap/verify",
              req_body='{"token":"abcd1234efgh5678..."}',
              body='{"verified":true}'),
    )
    findings = await IapBypassAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d008_unacknowledged_after_unlock_is_medium(ctx, memory):
    ctx.sources["frida"] = _fcapture(
        _ev("billing.purchase_observed",
            sku="pro_unlock", purchase_state=1,
            order_id="GPA.1", token_prefix="zzzz0000aaaa1111",
            acknowledged=False),
        _ev("billing.feature_unlock",
            entitlement="pro", source="MainActivity"),
    )
    # Verification flow IS present, so HIGH path doesn't trigger; only
    # the MEDIUM unacked path remains.
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("POST", "/api/v1/iap/verify",
              req_body='{"token":"zzzz0000aaaa1111..."}',
              body='{"verified":true}'),
    )
    findings = await IapBypassAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


# ---------- D_009 ----------


@pytest.mark.asyncio
async def test_d009_no_capture_skips(ctx, memory):
    agent = IdorCandidateAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d009_user_id_endpoint_with_pii_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("GET", "/api/v1/users/12345",
              body='{"id":12345,"email":"a@b.com","balance":1000}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "IDOR" in f.vuln_class
    assert f.evidence["id_segment_observed"] == "12345"


@pytest.mark.asyncio
async def test_d009_uuid_path_segment_also_caught(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("GET", "/api/v2/accounts/550e8400-e29b-41d4-a716-446655440000",
              body='{"email":"x@y.com"}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_d009_no_pii_in_response_not_flagged(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("GET", "/api/v1/users/12345",
              body='{"id":12345,"name":"X","status":"ok"}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d009_mass_assignment_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("PATCH", "/api/v1/profile",
              req_body='{"name":"x","is_admin":false}',
              body='{"ok":true}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "Mass-Assignment" in f.vuln_class
    assert "is_admin" in f.evidence["privilege_keys_observed"]


@pytest.mark.asyncio
async def test_d009_nested_priv_keys_caught(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("PUT", "/api/v1/account",
              req_body='{"user":{"role":"viewer","perm":1}}',
              body='{"ok":true}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert any("Mass-Assignment" in f.vuln_class for f in findings)


@pytest.mark.asyncio
async def test_d009_template_collapses_ids(ctx, memory):
    ctx.sources["mitmproxy"] = _mcapture(
        _flow("GET", "/api/v1/users/1",
              body='{"email":"a@b.com"}'),
        _flow("GET", "/api/v1/users/2",
              body='{"email":"c@d.com"}'),
    )
    findings = await IdorCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    idor = [f for f in findings if "IDOR" in f.vuln_class]
    assert len(idor) == 1
    assert idor[0].evidence["occurrence_count"] == 2
