"""Unit tests for N_013 InsecureWebSocketAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import InsecureWebSocketAgent
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
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_okhttp_ws_url_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Ws", """
import okhttp3.*;
class Ws {
  WebSocket open(OkHttpClient c) {
    Request r = new Request.Builder().url("ws://chat.example.com/socket").build();
    return c.newWebSocket(r, new WebSocketListener() {});
  }
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_013"
    assert f.severity == Severity.HIGH
    assert f.evidence["loopback_host"] is False


@pytest.mark.asyncio
async def test_wss_url_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Wss", """
import okhttp3.*;
class Wss {
  WebSocket open(OkHttpClient c) {
    Request r = new Request.Builder().url("wss://chat.example.com/socket").build();
    return c.newWebSocket(r, new WebSocketListener() {});
  }
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_localhost_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Dev", """
import okhttp3.*;
class Dev {
  WebSocket open(OkHttpClient c) {
    Request r = new Request.Builder().url("ws://localhost:8080/dev").build();
    return c.newWebSocket(r, new WebSocketListener() {});
  }
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["loopback_host"] is True


@pytest.mark.asyncio
async def test_emulator_host_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Emu", """
import okhttp3.*;
class Emu {
  WebSocket open(OkHttpClient c) {
    Request r = new Request.Builder().url("ws://10.0.2.2:3000/api").build();
    return c.newWebSocket(r, new WebSocketListener() {});
  }
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_no_websocket_context_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Comment", """
class Comment {
  // mentions "ws://example.com" in a doc comment only
  String name = "ws://example.com";  // unrelated stray literal
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_java_websocket_library_path(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.JavaWs", """
import org.java_websocket.client.WebSocketClient;
import java.net.URI;
class JavaWs {
  WebSocketClient client() throws Exception {
    return new WebSocketClient(new URI("ws://chat.example.com")) {
      @Override public void onOpen(org.java_websocket.handshake.ServerHandshake h) {}
      @Override public void onMessage(String m) {}
      @Override public void onClose(int c, String r, boolean b) {}
      @Override public void onError(Exception e) {}
    };
  }
}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import okhttp3.*;
class S { WebSocket open(OkHttpClient c) {
  Request r = new Request.Builder().url("ws://x.example.com/").build();
  return c.newWebSocket(r, new WebSocketListener(){});
}}
""")
    agent = InsecureWebSocketAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Communication"
    assert f.masvs == "MSTG-NETWORK-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
