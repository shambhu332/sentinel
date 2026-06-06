"""Unit tests for C_013 JavaSerializationAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import JavaSerializationAgent
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
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_network_sourced_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import java.io.*;
import java.net.*;
class Net {
  Object load() throws Exception {
    URL url = new URL("https://api.example.com/blob");
    ObjectInputStream ois = new ObjectInputStream(url.openStream());
    return ois.readObject();
  }
}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "C_013"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["network_source"] is True


@pytest.mark.asyncio
async def test_intent_sourced_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Local", """
import android.content.Intent;
import java.io.*;
class Local {
  Object load(Intent intent) throws Exception {
    byte[] blob = intent.getByteArrayExtra("payload");
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(blob));
    return ois.readObject();
  }
}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_external_storage_sourced_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Ext", """
import android.os.Environment;
import java.io.*;
class Ext {
  Object load() throws Exception {
    File f = new File(Environment.getExternalStorageDirectory(), "blob.ser");
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f));
    return ois.readObject();
  }
}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_no_external_source_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Inner", """
import java.io.*;
class Inner {
  Object load(byte[] inMemory) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(inMemory));
    return ois.readObject();
  }
}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_no_object_input_stream_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
import java.io.*;
class Plain {
  Object load(InputStream in) throws Exception {
    return in.read();
  }
}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import java.io.*;
import java.net.*;
class S { Object load() throws Exception {
  ObjectInputStream o = new ObjectInputStream(new URL("https://x").openStream());
  return o.readObject();
}}
""")
    agent = JavaSerializationAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M7: Client Code Quality"
    assert f.masvs == "MSTG-CODE-8"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
