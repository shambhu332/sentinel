"""Unit tests for D_007 RaceConditionCandidateAgent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic import RaceConditionCandidateAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _flow(
    method: str,
    path: str,
    *,
    host: str = "api.example.com",
    status: int = 200,
    body: str = '{"status":"success"}',
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        url=f"https://{host}{path}",
        scheme="https",
        host=host,
        path=path,
        response_status=status,
        response_body=body,
    )


def _capture(*flows: CapturedFlow) -> MitmproxyCapture:
    return MitmproxyCapture(
        flows=list(flows),
        capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=10.0,
        flow_count=len(flows),
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
    agent = RaceConditionCandidateAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_redeem_post_with_success_is_medium(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v1/coupon/redeem", status=200,
              body='{"status":"success","new_balance":500}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "coupon" in findings[0].evidence["verbs"] \
        or "redeem" in findings[0].evidence["verbs"]


@pytest.mark.asyncio
async def test_withdraw_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v2/wallet/withdraw",
              body='{"ok":true,"txn":"abc"}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_get_request_not_flagged(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow("GET", "/api/v1/coupon/redeem",
              body='{"status":"success"}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_non_value_path_not_flagged(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v1/users/profile",
              body='{"status":"success"}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_failed_response_not_flagged(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v1/coupon/redeem", status=400,
              body='{"error":"invalid"}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_same_endpoint_grouped(ctx, memory):
    # Two flows to the same endpoint with different IDs collapse to
    # one finding.
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v1/coupon/redeem/123",
              body='{"status":"success"}'),
        _flow("POST", "/api/v1/coupon/redeem/456",
              body='{"status":"success"}'),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].evidence["occurrence_count"] == 2


@pytest.mark.asyncio
async def test_201_status_alone_qualifies(ctx, memory):
    # 201 Created without a success word in body should still flag.
    ctx.sources["mitmproxy"] = _capture(
        _flow("POST", "/api/v1/reservation/book",
              status=201, body=""),
    )
    findings = await RaceConditionCandidateAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
