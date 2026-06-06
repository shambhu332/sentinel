"""Unit tests for N_009 WebViewDebugFlagAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import WebViewDebugFlagAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, decompiled: bool = True):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if decompiled:
        d = ws / "decompiled"
        d.mkdir(exist_ok=True)
        ctx.decompiled_dir = d
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(tmp_path, decompiled=False)
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_ungated_debug_call_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bad", """
class Bad {
  void wire(android.webkit.WebView w) {
    android.webkit.WebView.setWebContentsDebuggingEnabled(true);
  }
}
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_009"
    assert f.severity == Severity.HIGH
    assert f.evidence["guard_detected"] is False


@pytest.mark.asyncio
async def test_buildconfig_debug_guard_demotes_to_info(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Guarded", """
class Guarded {
  void wire(android.webkit.WebView w) {
    if (com.x.BuildConfig.DEBUG) {
      android.webkit.WebView.setWebContentsDebuggingEnabled(true);
    }
  }
}
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].evidence["guard_detected"] is True


@pytest.mark.asyncio
async def test_flag_debuggable_guard_demotes_to_info(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.RuntimeGuard", """
class RuntimeGuard {
  void wire(android.content.Context ctx, android.webkit.WebView w) {
    if ((ctx.getApplicationInfo().flags
         & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      android.webkit.WebView.setWebContentsDebuggingEnabled(true);
    }
  }
}
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_setdebug_false_is_safe(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Safe", """
class Safe {
  void wire(android.webkit.WebView w) {
    android.webkit.WebView.setWebContentsDebuggingEnabled(false);
  }
}
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_webview_calls_no_findings(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.NoWeb", """
class NoWeb { void f() { System.out.println("hi"); } }
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bad", """
class Bad { void w() {
  android.webkit.WebView.setWebContentsDebuggingEnabled(true);
}}
""")
    agent = WebViewDebugFlagAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Communication"
    assert f.masvs and f.masvs.startswith("MSTG-RESILIENCE")
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
