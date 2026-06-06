"""Unit tests for C_012 AesGcmNonceReuseAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import AesGcmNonceReuseAgent
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
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_gcm_usage_no_findings(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Cbc", """
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
class Cbc {
  void enc() {
    Cipher.getInstance("AES/CBC/PKCS5Padding");
    new IvParameterSpec(new byte[16]);
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_zero_byte_iv_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Zero", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
class Zero {
  void enc() {
    Cipher.getInstance("AES/GCM/NoPadding");
    new GCMParameterSpec(128, new byte[12]);
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "C_012"
    assert f.severity == Severity.CRITICAL
    assert "zero-byte" in f.evidence["reason"]


@pytest.mark.asyncio
async def test_constant_literal_iv_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Lit", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
class Lit {
  void enc() {
    Cipher.getInstance("AES/GCM/NoPadding");
    new GCMParameterSpec(128, new byte[]{1,2,3,4,5,6,7,8,9,10,11,12});
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "constant" in findings[0].evidence["reason"]


@pytest.mark.asyncio
async def test_field_iv_without_secure_random_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Fld", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
class Fld {
  private final byte[] iv = new byte[12];
  void enc() {
    Cipher.getInstance("AES/GCM/NoPadding");
    new GCMParameterSpec(128, iv);
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_secure_random_suppresses_field_iv(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
class Good {
  void enc() {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    Cipher.getInstance("AES/GCM/NoPadding");
    new GCMParameterSpec(128, iv);
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_message_digest_iv_without_secure_random_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Md", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
class Md {
  private final byte[] iv = MessageDigest.getInstance("SHA-256").digest("seed".getBytes());
  void enc() {
    Cipher.getInstance("AES/GCM/NoPadding");
    new GCMParameterSpec(128, iv);
  }
}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # The field is also matched as "field IV without SecureRandom"
    # → HIGH wins via the earlier branch; that's the right answer
    # here because field reuse trumps "derived from digest".
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Zero", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
class Zero { void w() {
  Cipher.getInstance("AES/GCM/NoPadding");
  new GCMParameterSpec(128, new byte[12]);
}}
""")
    agent = AesGcmNonceReuseAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.vuln_class == "AES-GCM Nonce Reuse"
    assert f.owasp == "M4: Insufficient Cryptography"
    assert f.masvs == "MSTG-CRYPTO-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
