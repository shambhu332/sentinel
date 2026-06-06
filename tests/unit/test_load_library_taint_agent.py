"""Unit tests for NL_002 LoadLibraryTaintAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.native import LoadLibraryTaintAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, decompiled=True):
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


def _plant(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False)
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_static_string_literal_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Hello", """
class Hello {
  static { System.loadLibrary("hello-jni"); }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_intent_extra_load_library_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plug", """
import android.content.Intent;
class Plug {
  void run(Intent intent) {
    String libName = intent.getStringExtra("lib");
    System.loadLibrary(libName);
  }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["taint_source"] == "intent_extra"


@pytest.mark.asyncio
async def test_deep_link_query_load_library_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Deep", """
import android.content.Intent;
class Deep {
  void run(Intent intent) {
    String libName = intent.getData().getQueryParameter("lib");
    System.loadLibrary(libName);
  }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["taint_source"] == "deep_link"


@pytest.mark.asyncio
async def test_system_load_absolute_path_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Abs", """
import android.content.SharedPreferences;
class Abs {
  void run(SharedPreferences prefs) {
    String path = prefs.getString("plugin_path", "");
    System.load(path);
  }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["method"] == "load"
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_network_taint_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Dl", """
import java.net.URL;
class Dl {
  void run() throws Exception {
    URL url = new URL("https://example.com/lib");
    String libName = url.openStream().toString();
    System.loadLibrary(libName);
  }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["taint_source"] == "network_download"


@pytest.mark.asyncio
async def test_no_taint_source_in_scope_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Loc", """
class Loc {
  void run() {
    String libName = computeName();
    System.loadLibrary(libName);
  }
  String computeName() { return "hello"; }
}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.content.Intent;
class S { void run(Intent intent) {
  String n = intent.getStringExtra("lib");
  System.loadLibrary(n);
}}
""")
    agent = LoadLibraryTaintAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.agent_id == "NL_002"
    assert f.owasp == "M7: Client Code Quality"
    assert f.masvs == "MSTG-CODE-8"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
