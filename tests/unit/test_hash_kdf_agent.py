"""Unit tests for C_016 HashKdfAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import HashKdfAgent
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
    agent = HashKdfAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_password_digest_used_as_key_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bad", """
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
class Bad {
  void seal(String password, byte[] plaintext) throws Exception {
    byte[] key = MessageDigest.getInstance("SHA-256")
                              .digest(password.getBytes());
    SecretKeySpec spec = new SecretKeySpec(key, "AES");
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, spec);
  }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "C_016"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["key_use_in_scope"] is True


@pytest.mark.asyncio
async def test_password_digest_without_key_use_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Mid", """
import java.security.MessageDigest;
class Mid {
  String fingerprint(String password) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256")
                                 .digest(password.getBytes());
    return new String(digest);
  }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_pbkdf2_in_file_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import java.security.MessageDigest;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
class Good {
  byte[] derive(char[] password, byte[] salt) throws Exception {
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password, salt, 100000, 256);
    byte[] key = f.generateSecret(spec).getEncoded();
    new SecretKeySpec(key, "AES");
    // The digest below is a separate fingerprint, not the key.
    MessageDigest.getInstance("SHA-256").digest(password.toString().getBytes());
    return key;
  }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_non_password_digest_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.FileHash", """
import java.security.MessageDigest;
class FileHash {
  byte[] cacheKeyFor(byte[] fileBytes) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(fileBytes);
  }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_two_step_update_then_digest_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.TwoStep", """
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
class TwoStep {
  byte[] derive(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(password.getBytes());
    byte[] key = md.digest();
    new SecretKeySpec(key, "AES");
    return key;
  }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_helper_call_inside_body_suppresses(memory, tmp_path):
    """When the body uses a checksumOf / cacheKey helper alongside the
    digest call, the agent treats the digest as the auxiliary hash and
    skips. (Method names themselves aren't visible from inside the
    body; the suppression hooks on an explicit call to one of the
    documented legitimate-use helpers.)"""
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Checksum", """
import java.security.MessageDigest;
class Checksum {
  byte[] verify(String password, byte[] expected) throws Exception {
    byte[] computed = checksumOf(password);
    return MessageDigest.getInstance("SHA-256").digest(password.getBytes());
  }
  byte[] checksumOf(String s) { return null; }
}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
class S { void w(String password) throws Exception {
  byte[] k = MessageDigest.getInstance("SHA-256").digest(password.getBytes());
  new SecretKeySpec(k, "AES");
}}
""")
    agent = HashKdfAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M4: Insufficient Cryptography"
    assert f.masvs == "MSTG-CRYPTO-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
    assert "PBKDF2" in f.recommendation
