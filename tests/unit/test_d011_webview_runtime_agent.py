"""Unit tests for D_011 WebViewRuntimeAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import WebViewRuntimeAgent
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


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = WebViewRuntimeAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_bridge_with_http_load_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.js_interface_added",
            name="AndroidBridge",
            object_class="com.example.app.JsBridge",
            exposed_methods=["openUrl", "getToken"]),
        _ev("webview.load",
            url="http://attacker.example.org/index.html",
            scheme="http"),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1


@pytest.mark.asyncio
async def test_bridge_with_first_party_https_no_finding(ctx, memory):
    # package=com.example.app -> example.com is first-party root.
    ctx.sources["frida"] = _capture(
        _ev("webview.js_interface_added",
            name="AndroidBridge",
            object_class="com.example.app.JsBridge",
            exposed_methods=["openUrl"]),
        _ev("webview.load",
            url="https://www.example.com/page",
            scheme="https"),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit == []


@pytest.mark.asyncio
async def test_bridge_with_third_party_https_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.js_interface_added",
            name="AndroidBridge",
            object_class="com.example.app.JsBridge",
            exposed_methods=["openUrl"]),
        _ev("webview.load",
            url="https://ads.partner.com/index.html",
            scheme="https"),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1


@pytest.mark.asyncio
async def test_allow_file_access_from_file_urls_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.settings",
            setting="setAllowFileAccessFromFileURLs", value=True),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_universal_file_access_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.settings",
            setting="setAllowUniversalAccessFromFileURLs", value=True),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_debugging_enabled_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.debugging", enabled=True),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Debugging" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_mixed_content_always_allow_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.settings", setting="setMixedContentMode", value=0),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_javascript_url_load_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("webview.load",
            url="javascript:window.bridge.openUrl('x')",
            scheme="javascript"),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "javascript:" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_safe_setting_no_finding(ctx, memory):
    # setMixedContentMode(1) = NEVER_ALLOW (safe) → no finding.
    ctx.sources["frida"] = _capture(
        _ev("webview.settings", setting="setMixedContentMode", value=1),
        _ev("webview.settings",
            setting="setAllowFileAccessFromFileURLs", value=False),
    )
    findings = await WebViewRuntimeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
