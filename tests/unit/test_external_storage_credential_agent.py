"""Unit tests for STG_008 ExternalStorageCredentialAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.shared_prefs import ExternalStorageCredentialAgent
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
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_external_api_with_token_filename_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Dump", """
import android.os.Environment;
import java.io.*;
class Dump {
  void save(String t) throws IOException {
    File dir = Environment.getExternalStoragePublicDirectory(
        Environment.DIRECTORY_DOWNLOADS);
    FileOutputStream fos = new FileOutputStream(new File(dir, "token.json"));
    fos.write(t.getBytes());
  }
}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "STG_008"
    assert f.severity == Severity.HIGH
    assert f.evidence["external_root_api"] is True
    assert "token" in f.evidence["credential_marker"]


@pytest.mark.asyncio
async def test_sdcard_literal_with_session_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Lit", """
import java.io.*;
class Lit {
  void save(String s) throws IOException {
    FileWriter w = new FileWriter("/sdcard/session.txt");
    w.write(s);
  }
}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["external_path_literal"] is True


@pytest.mark.asyncio
async def test_external_without_credential_keyword_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Photo", """
import android.os.Environment;
import java.io.*;
class Photo {
  void save() throws IOException {
    File dir = Environment.getExternalStoragePublicDirectory(
        Environment.DIRECTORY_PICTURES);
    FileOutputStream fos = new FileOutputStream(new File(dir, "photo.jpg"));
    fos.write(new byte[0]);
  }
}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_internal_storage_with_credential_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Safe", """
import android.content.Context;
import java.io.*;
class Safe {
  void save(Context ctx, String token) throws IOException {
    FileOutputStream fos = new FileOutputStream(
        new File(ctx.getFilesDir(), "token.json"));
    fos.write(token.getBytes());
  }
}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_dedup_within_same_method(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Twice", """
import android.os.Environment;
import java.io.*;
class Twice {
  void save(String t) throws IOException {
    File dir = Environment.getExternalStorageDirectory();
    FileOutputStream a = new FileOutputStream(new File(dir, "token.json"));
    FileOutputStream b = new FileOutputStream(new File(dir, "secret.bin"));
    a.write(t.getBytes());
  }
}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.os.Environment;
import java.io.*;
class S { void w() throws IOException {
  File dir = Environment.getExternalStorageDirectory();
  new FileOutputStream(new File(dir, "token.json")).write(new byte[0]);
}}
""")
    agent = ExternalStorageCredentialAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M2: Inadequate Supply Chain Security"
    assert f.masvs == "MSTG-STORAGE-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
