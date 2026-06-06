"""Unit tests for C_015 WeakPrngSeedAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import WeakPrngSeedAgent
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
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_clock_seed_securerandom_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Sr", """
import java.security.SecureRandom;
class Sr {
  void wire() {
    SecureRandom r = new SecureRandom();
    r.setSeed(System.currentTimeMillis());
  }
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "clock" in findings[0].evidence["reason"]


@pytest.mark.asyncio
async def test_literal_random_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Lit", """
import java.util.Random;
class Lit {
  Random r = new Random(42L);
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_random_with_explicit_clock_seed_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Rc", """
import java.util.Random;
class Rc {
  Random r = new Random(System.currentTimeMillis());
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_no_arg_securerandom_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import java.security.SecureRandom;
class Good {
  SecureRandom r = new SecureRandom();
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_string_bytes_seed_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Sb", """
import java.security.SecureRandom;
class Sb {
  void wire() {
    SecureRandom r = new SecureRandom("fixed-seed".getBytes());
  }
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "getBytes" in findings[0].evidence["reason"]


@pytest.mark.asyncio
async def test_random_with_runtime_value_still_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Rv", """
import java.util.Random;
class Rv {
  Random make(long seed) { return new Random(seed); }
}
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # java.util.Random with any explicit seed is still non-crypto;
    # surface as HIGH so reviewer decides.
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import java.util.Random;
class S { Random r = new Random(123L); }
""")
    agent = WeakPrngSeedAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M4: Insufficient Cryptography"
    assert f.masvs == "MSTG-CRYPTO-6"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
