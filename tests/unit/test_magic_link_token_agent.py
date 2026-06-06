"""Unit tests for A_013 MagicLinkTokenAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import MagicLinkTokenAgent
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
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_magic_token_putstring_without_redeem_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
import android.content.SharedPreferences;
class Auth {
  void handle(Intent intent, SharedPreferences prefs) {
    String magic = intent.getData().getQueryParameter("magic");
    prefs.edit().putString("magic_token", magic).apply();
  }
}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "A_013"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["vector"] == "putString_magic_token"


@pytest.mark.asyncio
async def test_redeem_call_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
import android.content.SharedPreferences;
class Auth {
  void handle(Intent intent, SharedPreferences prefs) {
    String magic = intent.getData().getQueryParameter("magic");
    String session = redeemMagicLink(magic);
    prefs.edit().putString("session_token", session).apply();
  }
  String redeemMagicLink(String m) { return ""; }
}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_persist_helper_only_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
class Auth {
  void handle(Intent intent) {
    String m = intent.getStringExtra("magic_token");
    saveAuthToken(m);
  }
  void saveAuthToken(String s) {}
}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["vector"] == "persist_helper"


@pytest.mark.asyncio
async def test_write_then_clear_in_same_method_is_skipped(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
import android.content.SharedPreferences;
class Auth {
  void handle(Intent intent, SharedPreferences prefs) {
    String magic = intent.getData().getQueryParameter("magic");
    prefs.edit().putString("magic_token", magic).apply();
    prefs.edit().remove("magic_token").apply();
  }
}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_magic_source_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
import android.content.SharedPreferences;
class Auth {
  void handle(Intent intent, SharedPreferences prefs) {
    String t = intent.getStringExtra("page");
    prefs.edit().putString("last_page", t).apply();
  }
}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.content.Intent;
import android.content.SharedPreferences;
class S { void h(Intent i, SharedPreferences p) {
  String m = i.getData().getQueryParameter("magic");
  p.edit().putString("magic_token", m).apply();
}}
""")
    agent = MagicLinkTokenAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Authentication / Authorization"
    assert f.masvs == "MSTG-AUTH-3"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
