"""Unit tests for STG_010 PlaintextPasswordFileAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.shared_prefs import PlaintextPasswordFileAgent
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
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_plaintext_password_json_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Save", """
import java.io.*;
class Save {
  void persist(String password) throws IOException {
    FileWriter w = new FileWriter("credentials.json");
    w.write("{\\"password\\":\\"" + password + "\\"}");
    w.close();
  }
}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "STG_010"
    assert f.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_encryption_call_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import java.io.*;
import javax.crypto.Cipher;
class Good {
  void persist(String password) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    byte[] sealed = c.doFinal(password.getBytes());
    FileOutputStream out = new FileOutputStream("credentials.dat");
    out.write(sealed);
  }
}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_password_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Diary", """
import java.io.*;
class Diary {
  void persist(String entry) throws IOException {
    FileWriter w = new FileWriter("diary.txt");
    w.write(entry);
  }
}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_password_to_non_credential_filename_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Photo", """
import java.io.*;
class Photo {
  void persist(byte[] data) throws IOException {
    FileOutputStream out = new FileOutputStream("photo.jpg");
    out.write(data);
  }
}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_passphrase_to_properties_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Vault", """
import java.io.*;
class Vault {
  void persist(String passphrase) throws IOException {
    BufferedWriter w = new BufferedWriter(new FileWriter("vault.properties"));
    w.write("master_password=" + passphrase);
    w.close();
  }
}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import java.io.*;
class S { void w(String password) throws IOException {
  FileWriter fw = new FileWriter("credentials.json");
  fw.write(password);
}}
""")
    agent = PlaintextPasswordFileAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M2: Inadequate Supply Chain Security"
    assert f.masvs == "MSTG-STORAGE-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
