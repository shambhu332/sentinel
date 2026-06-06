"""Unit tests for P_012 MutablePendingIntentAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import MutablePendingIntentAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, target_sdk: int = 0, decompiled: bool = True):
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
    ctx.manifest = {"package": "com.x", "target_sdk": target_sdk}
    return ctx


def _plant(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(tmp_path, decompiled=False)
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- safe paths ----------


@pytest.mark.asyncio
async def test_flag_immutable_present_is_safe(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Safe", """
class Safe {
  void wire(Context ctx) {
    Intent i = new Intent("com.x.PING");
    PendingIntent pi = PendingIntent.getBroadcast(
        ctx, 0, i, PendingIntent.FLAG_IMMUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_immutable_literal_value_is_safe(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.SafeLit", """
class SafeLit {
  void wire(Context ctx) {
    Intent i = new Intent("com.x.PING");
    PendingIntent pi = PendingIntent.getBroadcast(ctx, 0, i, 67108864);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- CRITICAL: mutable + implicit ----------


@pytest.mark.asyncio
async def test_mutable_implicit_intent_is_critical(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.BadCrit", """
class BadCrit {
  void wire(Context ctx) {
    Intent i = new Intent("com.x.IMPLICIT_ACTION");
    PendingIntent pi = PendingIntent.getBroadcast(
        ctx, 0, i, PendingIntent.FLAG_MUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == 0.90
    assert findings[0].evidence["mutable_flag_present"] is True
    assert findings[0].evidence["explicit_intent"] is False


# ---------- HIGH: mutable + explicit (pinned) ----------


@pytest.mark.asyncio
async def test_mutable_with_setpackage_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.PinnedMut", """
class PinnedMut {
  void wire(Context ctx) {
    Intent i = new Intent("com.x.ACTION");
    i.setPackage("com.x");
    PendingIntent pi = PendingIntent.getBroadcast(
        ctx, 0, i, PendingIntent.FLAG_MUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["explicit_intent"] is True


@pytest.mark.asyncio
async def test_explicit_intent_ctor_is_explicit(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.ExplicitCtor", """
class ExplicitCtor {
  void wire(Context ctx) {
    Intent i = new Intent(ctx, MainActivity.class);
    PendingIntent pi = PendingIntent.getActivity(
        ctx, 0, i, PendingIntent.FLAG_MUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


# ---------- HIGH: bare-zero + implicit ----------


@pytest.mark.asyncio
async def test_bare_zero_flags_implicit_intent_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path, target_sdk=29)
    _plant(ctx.decompiled_dir, "com.x.BareZero", """
class BareZero {
  void wire(Context ctx) {
    Intent i = new Intent("com.x.IMPLICIT");
    PendingIntent pi = PendingIntent.getBroadcast(ctx, 0, i, 0);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["bare_zero_flags"] is True


# ---------- MEDIUM: bare-zero + explicit, legacy SDK ----------


@pytest.mark.asyncio
async def test_bare_zero_explicit_low_sdk_is_medium(memory, tmp_path):
    ctx = _make_ctx(tmp_path, target_sdk=29)
    _plant(ctx.decompiled_dir, "com.x.BareExplicit", """
class BareExplicit {
  void wire(Context ctx) {
    Intent i = new Intent(ctx, MainActivity.class);
    PendingIntent pi = PendingIntent.getActivity(ctx, 0, i, 0);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


# ---------- INFO: bare-zero + explicit, modern SDK ----------


@pytest.mark.asyncio
async def test_bare_zero_explicit_modern_sdk_is_info(memory, tmp_path):
    ctx = _make_ctx(tmp_path, target_sdk=33)
    _plant(ctx.decompiled_dir, "com.x.ModernExplicit", """
class ModernExplicit {
  void wire(Context ctx) {
    Intent i = new Intent(ctx, MainActivity.class);
    PendingIntent pi = PendingIntent.getActivity(ctx, 0, i, 0);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


# ---------- Multiple call sites in one file ----------


@pytest.mark.asyncio
async def test_multiple_call_sites_each_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Multi", """
class Multi {
  void a(Context ctx) {
    Intent i = new Intent("com.x.A");
    PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_MUTABLE);
  }
  void b(Context ctx) {
    Intent j = new Intent("com.x.B");
    PendingIntent.getService(ctx, 0, j, PendingIntent.FLAG_MUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in findings)


# ---------- Finding-schema compliance ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Schema", """
class Schema {
  void w(Context ctx) {
    Intent i = new Intent("com.x.PING");
    PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_MUTABLE);
  }
}
""")
    agent = MutablePendingIntentAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.agent_id == "P_012"
    assert f.vuln_class == "Mutable PendingIntent"
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
