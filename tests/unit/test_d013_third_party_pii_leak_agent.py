"""Unit tests for D_013 ThirdPartyPiiLeakAgent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic import ThirdPartyPiiLeakAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _flow(
    method: str = "POST",
    path: str = "/track",
    *, host: str,
    body: str = "",
    status: int = 200,
) -> CapturedFlow:
    return CapturedFlow(
        method=method, url=f"https://{host}{path}",
        scheme="https", host=host, path=path,
        request_body=body,
        response_status=status, response_body="{}",
    )


def _capture(*flows: CapturedFlow) -> MitmproxyCapture:
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
    # package -> example.com is first-party root
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
    agent = ThirdPartyPiiLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_first_party_calls_ignored(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.example.com", body='{"password":"hunter2"}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_credential_in_segment_body_is_critical(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.segment.io",
              body='{"event":"login","properties":{"password":"hunter2"}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if "Credential" in f.vuln_class]
    assert len(crit) == 1
    assert crit[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_jwt_in_amplitude_payload_is_high(ctx, memory):
    jwt = "eyAAAAAA.eyBBBBBB.cCCCCCCCC"
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.amplitude.com",
              body=f'{{"event_props":{{"token":"{jwt}"}}}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    tok = [f for f in findings if "Bearer Token" in f.vuln_class]
    assert len(tok) == 1
    assert tok[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_bearer_header_in_sentry_event_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="o123.ingest.sentry.io",
              path="/api/1/store/",
              body='{"breadcrumbs":[{"data":{"Authorization":'
                   '"Bearer abcDEF1234567890abcd"}}]}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert any("Bearer Token" in f.vuln_class for f in findings)


@pytest.mark.asyncio
async def test_email_in_mixpanel_event_is_medium(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.mixpanel.com",
              body='{"event":"signup","properties":'
                   '{"distinct_id":"alice@example.org"}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    pii = [f for f in findings if "PII" in f.vuln_class]
    assert len(pii) == 1
    assert pii[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_card_shape_passing_luhn_caught(ctx, memory):
    # 4111-1111-1111-1111 is a known Luhn-valid test card.
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.amplitude.com",
              body='{"props":{"card":"4111-1111-1111-1111"}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    pii = [f for f in findings if "PII" in f.vuln_class]
    assert len(pii) == 1


@pytest.mark.asyncio
async def test_benign_third_party_event_no_finding(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.mixpanel.com",
              body='{"event":"tap","properties":{"button":"ok"}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_per_category_findings_dedupe_across_flows(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="api.mixpanel.com",
              body='{"props":{"email":"a@b.com"}}'),
        _flow(host="api.amplitude.com",
              body='{"props":{"email":"c@d.com"}}'),
    )
    findings = await ThirdPartyPiiLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    pii = [f for f in findings if "PII" in f.vuln_class]
    assert len(pii) == 1
    assert pii[0].evidence["occurrence_count"] == 2
