"""Unit tests for B_006 UnsignedUpdateAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.business import UnsignedUpdateAgent
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
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_action_install_package_without_verify_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Up", """
import android.content.Intent;
import android.net.Uri;
class Up {
  void install(Uri apkUri) {
    Intent i = new Intent("android.intent.action.INSTALL_PACKAGE");
    i.setData(apkUri);
    startActivity(i);
  }
  void startActivity(Intent i) {}
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].agent_id == "B_006"
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_signature_check_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Up", """
import android.content.Intent;
import android.content.pm.PackageManager;
class Up {
  void install() {
    PackageManager pm = getPm();
    pm.getPackageArchiveInfo("/tmp/update.apk",
        PackageManager.GET_SIGNING_CERTIFICATES);
    Intent i = new Intent("android.intent.action.INSTALL_PACKAGE");
    startActivity(i);
  }
  PackageManager getPm() { return null; }
  void startActivity(Intent i) {}
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_sha256_check_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Up", """
import android.content.Intent;
import java.security.MessageDigest;
class Up {
  void install(byte[] apkBytes) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(apkBytes);
    byte[] expected = new byte[32];
    if (!java.util.Arrays.equals(md.digest(), expected)) return;
    Intent i = new Intent("android.intent.action.INSTALL_PACKAGE");
    startActivity(i);
  }
  void startActivity(Intent i) {}
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_pm_install_runtime_exec_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Sh", """
class Sh {
  void install(String path) throws Exception {
    Runtime.getRuntime().exec("pm install -r " + path);
  }
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_package_installer_without_apk_data_suppressed(memory, tmp_path):
    ctx = _ctx(tmp_path)
    # System-level PackageInstaller use that's not an actual APK install
    # in this scope shouldn't fire.
    _plant(ctx.decompiled_dir, "com.x.Sysish", """
import android.content.pm.PackageInstaller;
class Sysish {
  void other(PackageInstaller pi) {
    pi.uninstall("com.example", null);
  }
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.content.Intent;
class S { void w() {
  Intent i = new Intent("android.intent.action.INSTALL_PACKAGE");
  startActivity(i);
}
void startActivity(Intent i) {}
}
""")
    agent = UnsignedUpdateAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M7: Client Code Quality"
    assert f.masvs == "MSTG-CODE-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
