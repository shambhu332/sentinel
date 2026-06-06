"""Unit tests for P_006 UnprotectedBroadcastAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import UnprotectedBroadcastAgent
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
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_bare_broadcast_with_sensitive_payload_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.OtpSvc", """
import android.content.Context;
import android.content.Intent;
class OtpSvc {
  void onOtp(Context ctx, String otp) {
    Intent i = new Intent("com.x.OTP_DELIVERED");
    i.putExtra("otp", otp);
    ctx.sendBroadcast(i);
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "P_006"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["sensitive_keyword"] == "otp"


@pytest.mark.asyncio
async def test_bare_broadcast_non_sensitive_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Heartbeat", """
import android.content.Context;
import android.content.Intent;
class Heartbeat {
  void tick(Context ctx) {
    Intent i = new Intent("com.x.HEARTBEAT");
    ctx.sendBroadcast(i);
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_permission_argument_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Safe", """
import android.content.Context;
import android.content.Intent;
class Safe {
  void notify(Context ctx, String otp) {
    Intent i = new Intent("com.x.OTP");
    i.putExtra("otp", otp);
    ctx.sendBroadcast(i, "com.x.permission.RECEIVE_OTP");
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_set_package_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Pkg", """
import android.content.Context;
import android.content.Intent;
class Pkg {
  void notify(Context ctx, String otp) {
    Intent i = new Intent("com.x.OTP");
    i.putExtra("otp", otp);
    i.setPackage(ctx.getPackageName());
    ctx.sendBroadcast(i);
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_explicit_intent_ctor_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Direct", """
import android.content.Context;
import android.content.Intent;
class Direct {
  void notify(Context ctx) {
    Intent i = new Intent(ctx, Receiver.class);
    ctx.sendBroadcast(i);
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_null_permission_arg_still_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Null", """
import android.content.Context;
import android.content.Intent;
class Null {
  void notify(Context ctx, String token) {
    Intent i = new Intent("com.x.LOGIN");
    i.putExtra("token", token);
    ctx.sendBroadcast(i, null);
  }
}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.content.Context;
import android.content.Intent;
class S { void w(Context ctx, String token) {
  Intent i = new Intent("com.x.LOGIN");
  i.putExtra("token", token);
  ctx.sendBroadcast(i);
}}
""")
    agent = UnprotectedBroadcastAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
