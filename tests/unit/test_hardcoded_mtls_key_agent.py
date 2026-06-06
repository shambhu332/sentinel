"""Unit tests for N_014 HardcodedMtlsKeyAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import HardcodedMtlsKeyAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, decompiled=True, resources=True):
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
    if resources:
        res = ws / "resources"
        res.mkdir(exist_ok=True)
        ctx.resources_dir = res
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant_java(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


def _plant_resource(resources_dir, rel_path, content=b"\x00\x01\x02\x03"):
    f = resources_dir / rel_path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(content)


@pytest.mark.asyncio
async def test_not_applicable_without_any_input(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False, resources=False)
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_p12_with_loader_and_password_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_resource(ctx.resources_dir, "res/raw/client_cert.p12")
    _plant_java(ctx.decompiled_dir, "com.x.Net", """
import java.security.KeyStore;
class Net {
  KeyStore load(android.content.Context ctx) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(ctx.getResources().openRawResource(R.raw.client_cert),
            "passw0rd".toCharArray());
    return ks;
  }
}
""")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # Both critical finding (loader+asset) AND the asset is "used", so
    # no second standalone HIGH finding.
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_014"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["password_inline"] is True


@pytest.mark.asyncio
async def test_loader_without_asset_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path, resources=False)
    _plant_java(ctx.decompiled_dir, "com.x.Net", """
import java.security.KeyStore;
class Net {
  void load(java.io.InputStream stream) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(stream, "passw0rd".toCharArray());
  }
}
""")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_asset_without_loader_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False)
    _plant_resource(ctx.resources_dir, "res/raw/client_cert.p12")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].vuln_class == "Hardcoded Bundled Keystore"


@pytest.mark.asyncio
async def test_no_keystore_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_resource(ctx.resources_dir, "res/raw/some_data.bin")
    _plant_java(ctx.decompiled_dir, "com.x.Plain", """
class Plain { void run() { System.out.println("hi"); } }
""")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_bks_keystore_extension_detected(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False)
    _plant_resource(ctx.resources_dir, "assets/keystore.bks")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_resource(ctx.resources_dir, "res/raw/client_cert.p12")
    _plant_java(ctx.decompiled_dir, "com.x.S", """
import java.security.KeyStore;
class S { void l() throws Exception {
  KeyStore ks = KeyStore.getInstance("PKCS12");
  ks.load(null, "p".toCharArray());
}}
""")
    agent = HardcodedMtlsKeyAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M2: Inadequate Supply Chain Security"
    assert f.masvs == "MSTG-CRYPTO-1"
    assert "Android Keystore" in f.recommendation
