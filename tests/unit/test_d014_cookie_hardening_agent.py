"""Unit tests for D_014 CookieHardeningAgent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic import CookieHardeningAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _flow(
    *, host: str = "api.example.com",
    set_cookie: str = "",
) -> CapturedFlow:
    headers = {"Set-Cookie": set_cookie} if set_cookie else {}
    return CapturedFlow(
        method="GET", url=f"https://{host}/login",
        scheme="https", host=host, path="/login",
        response_status=200,
        response_headers=headers,
        response_body="",
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
    agent = CookieHardeningAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_fully_hardened_cookie_no_finding(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        set_cookie="sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_missing_secure_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        set_cookie="sessionid=abc; Path=/; HttpOnly; SameSite=Lax",
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = [x for x in findings if "Secure" in x.vuln_class]
    assert len(f) == 1
    assert f[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_missing_httponly_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        set_cookie="token=t; Path=/; Secure; SameSite=Lax",
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = [x for x in findings if "HttpOnly" in x.vuln_class]
    assert len(f) == 1
    assert f[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_missing_samesite_is_medium(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        set_cookie="auth=v; Path=/; Secure; HttpOnly",
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = [x for x in findings if "SameSite" in x.vuln_class]
    assert len(f) == 1
    assert f[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_parent_domain_is_medium(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        host="api.example.com",
        set_cookie=(
            "sessionid=abc; Domain=.example.com; "
            "Path=/; Secure; HttpOnly; SameSite=Lax"
        ),
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = [x for x in findings if "Parent Domain" in x.vuln_class]
    assert len(f) == 1
    assert f[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_non_session_cookie_ignored(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow(
        set_cookie="theme=dark; Path=/",
    ))
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_per_host_dedupe(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(host="a.example.com",
              set_cookie="sessionid=x; Path=/; HttpOnly; SameSite=Lax"),
        _flow(host="b.example.com",
              set_cookie="sessionid=y; Path=/; HttpOnly; SameSite=Lax"),
    )
    findings = await CookieHardeningAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = [x for x in findings if "Secure" in x.vuln_class]
    assert len(f) == 1
    assert f[0].evidence["occurrence_count"] == 2
