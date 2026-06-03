"""Unit tests for C_008 — JavaScript Interface Bridge Method Auditor."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.webview import JavaScriptInterfaceBridgeAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

# ---------- Fixtures ----------


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def ctx(tmp_path):
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    c.decompiled_dir = decompiled
    c.manifest = {"package": "com.x", "exported_components": []}
    return c


def _plant(decompiled_dir: Path, fqcn: str, body: str) -> Path:
    parts = fqcn.split(".")
    java_file = decompiled_dir.joinpath(*parts).with_suffix(".java")
    java_file.parent.mkdir(parents=True, exist_ok=True)
    java_file.write_text(body)
    return java_file


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled_dir(memory, tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    agent = JavaScriptInterfaceBridgeAgent(context=c, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_decompiled_dir(memory, ctx):
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- CRITICAL tier ----------


@pytest.mark.asyncio
async def test_runtime_exec_is_critical(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.Bridge", """
package com.x;
import android.webkit.JavascriptInterface;
public class Bridge {
    @JavascriptInterface
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.agent_id == "C_008"
    assert f.confidence == pytest.approx(0.92)
    assert f.evidence["method"] == "run"
    assert f.evidence["class"] == "Bridge"
    assert "Runtime.getRuntime().exec" in f.evidence["trigger"]
    assert f.evidence["category"] == "command-execution / class-loading"


@pytest.mark.asyncio
async def test_processbuilder_is_critical(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.Bridge", """
package com.x;
import android.webkit.JavascriptInterface;
public class Bridge {
    @JavascriptInterface
    public void spawn(String prog) throws Exception {
        new ProcessBuilder(prog).start();
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


# ---------- HIGH tier ----------


@pytest.mark.asyncio
@pytest.mark.parametrize("body_line,expected_category", [
    ("Class.forName(name).newInstance();", "reflection"),
    ("this.getClass().getMethod(name).invoke(this);", "reflection"),
    ("new FileOutputStream(path).write(data);", "filesystem-write"),
    ('openFileOutput(name, MODE_PRIVATE).write(data);', "filesystem-write"),
    ('new java.io.File(path).delete();', "filesystem-write"),
    ('startActivity(new android.content.Intent(action));', "intent-dispatch"),
    ('sendBroadcast(new android.content.Intent(action));', "intent-dispatch"),
])
async def test_high_tier_patterns(memory, ctx, body_line, expected_category):
    _plant(ctx.decompiled_dir, "com.x.HighBridge", f"""
package com.x;
import android.webkit.JavascriptInterface;
public class HighBridge {{
    @JavascriptInterface
    public void op(String name, String path, String action, byte[] data) throws Exception {{
        {body_line}
    }}
}}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1, f"Expected 1 finding for {body_line!r}"
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == pytest.approx(0.85)
    assert f.evidence["category"] == expected_category


# ---------- MEDIUM tier ----------


@pytest.mark.asyncio
@pytest.mark.parametrize("body_line,expected_category", [
    ('return tm.getDeviceId();', "device-identifier"),
    ('return tm.getImei();', "device-identifier"),
    ('return android.provider.Settings.Secure.ANDROID_ID;', "device-identifier"),
    ('return new java.io.FileInputStream(path).read();', "filesystem-read"),
    ('return openFileInput(name).read();', "filesystem-read"),
])
async def test_medium_tier_patterns(memory, ctx, body_line, expected_category):
    _plant(ctx.decompiled_dir, "com.x.MedBridge", f"""
package com.x;
import android.webkit.JavascriptInterface;
public class MedBridge {{
    private android.telephony.TelephonyManager tm;
    @JavascriptInterface
    public int op(String name, String path) throws Exception {{
        {body_line}
    }}
}}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == pytest.approx(0.75)
    assert f.evidence["category"] == expected_category


@pytest.mark.asyncio
async def test_sensitive_prefs_key_is_medium(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.Prefs", """
package com.x;
import android.webkit.JavascriptInterface;
public class Prefs {
    @JavascriptInterface
    public String fetch(android.content.SharedPreferences sp) {
        return sp.getString("auth_token", "");
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.evidence["category"] == "sensitive-preferences-read"


# ---------- LOW tier (bridge present, no escalation) ----------


@pytest.mark.asyncio
async def test_innocuous_bridge_is_low(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.Echo", """
package com.x;
import android.webkit.JavascriptInterface;
public class Echo {
    @JavascriptInterface
    public String echo(String s) {
        return "ECHO: " + s;
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert f.confidence == pytest.approx(0.50)
    assert f.evidence["category"] == "bridge-exposure"


# ---------- Negative cases ----------


@pytest.mark.asyncio
async def test_no_finding_when_no_annotation(memory, ctx):
    """A method that calls Runtime.exec but is NOT @JavascriptInterface is out of scope."""
    _plant(ctx.decompiled_dir, "com.x.Plain", """
package com.x;
public class Plain {
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_for_unrelated_annotation(memory, ctx):
    """``@Override`` etc. must not be mistaken for ``@JavascriptInterface``."""
    _plant(ctx.decompiled_dir, "com.x.Plain", """
package com.x;
public class Plain {
    @Override
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- Multi-method / multi-file ----------


@pytest.mark.asyncio
async def test_multiple_bridge_methods_each_classified(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.Multi", """
package com.x;
import android.webkit.JavascriptInterface;
public class Multi {
    @JavascriptInterface
    public void exec(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
    @JavascriptInterface
    public String echo(String s) { return s; }
    @JavascriptInterface
    public String id(android.telephony.TelephonyManager tm) {
        return tm.getDeviceId();
    }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 3
    by_method = {f.evidence["method"]: f.severity for f in findings}
    assert by_method["exec"] == Severity.CRITICAL
    assert by_method["id"] == Severity.MEDIUM
    assert by_method["echo"] == Severity.LOW


@pytest.mark.asyncio
async def test_findings_across_files(memory, ctx):
    _plant(ctx.decompiled_dir, "com.x.A", """
package com.x;
import android.webkit.JavascriptInterface;
public class A {
    @JavascriptInterface
    public void run(String c) throws Exception { Runtime.getRuntime().exec(c); }
}
""")
    _plant(ctx.decompiled_dir, "com.x.B", """
package com.x;
import android.webkit.JavascriptInterface;
public class B {
    @JavascriptInterface
    public String echo(String s) { return s; }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    classes = sorted(f.evidence["class"] for f in findings)
    assert classes == ["A", "B"]


# ---------- Fully qualified annotation ----------


@pytest.mark.asyncio
async def test_fully_qualified_annotation_recognised(memory, ctx):
    """``@android.webkit.JavascriptInterface`` (no import) is also recognised."""
    _plant(ctx.decompiled_dir, "com.x.Qual", """
package com.x;
public class Qual {
    @android.webkit.JavascriptInterface
    public void run(String c) throws Exception { Runtime.getRuntime().exec(c); }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


# ---------- sources/ subdir ----------


@pytest.mark.asyncio
async def test_walks_sources_subdir(memory, ctx):
    sources = ctx.decompiled_dir / "sources"
    sources.mkdir()
    _plant(sources, "com.x.Inside", """
package com.x;
import android.webkit.JavascriptInterface;
public class Inside {
    @JavascriptInterface
    public void run(String c) throws Exception { Runtime.getRuntime().exec(c); }
}
""")
    agent = JavaScriptInterfaceBridgeAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["file"].startswith("com/x/")
