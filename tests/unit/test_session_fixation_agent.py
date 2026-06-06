"""Unit tests for A_012 SessionFixationAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import SessionFixationAgent
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
    agent = SessionFixationAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_intent_extra_to_session_token_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Login", """
import android.content.Intent;
import android.content.SharedPreferences;
class Login {
  void handle(Intent intent, SharedPreferences prefs) {
    String sid = intent.getStringExtra("session_id");
    prefs.edit().putString("session_id", sid).apply();
  }
}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "A_012"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["vector"] == "putString_token"


@pytest.mark.asyncio
async def test_persist_helper_only_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Login", """
import android.content.Intent;
class Login {
  void handle(Intent intent) {
    String sid = intent.getStringExtra("session_id");
    setAuthToken(sid);
  }
  void setAuthToken(String s) {}
}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["vector"] == "persist_helper"


@pytest.mark.asyncio
async def test_rotation_call_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Login", """
import android.content.Intent;
import android.content.SharedPreferences;
class Login {
  void handle(Intent intent, SharedPreferences prefs) {
    String sid = intent.getStringExtra("session_id");
    String fresh = rotateSession(sid);
    prefs.edit().putString("session_id", fresh).apply();
  }
  String rotateSession(String s) { return ""; }
}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_non_credential_extra_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Page", """
import android.content.Intent;
import android.content.SharedPreferences;
class Page {
  void handle(Intent intent, SharedPreferences prefs) {
    String tab = intent.getStringExtra("tab");
    prefs.edit().putString("last_tab", tab).apply();
  }
}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_deep_link_query_param_path(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Deep", """
import android.content.Intent;
import android.content.SharedPreferences;
class Deep {
  void handle(Intent intent, SharedPreferences prefs) {
    String sid = intent.getData().getQueryParameter("token");
    prefs.edit().putString("token", sid).apply();
  }
}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.L", """
import android.content.Intent;
import android.content.SharedPreferences;
class L { void h(Intent i, SharedPreferences p) {
  String s = i.getStringExtra("session_id");
  p.edit().putString("session_id", s).apply();
}}
""")
    agent = SessionFixationAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M2: Inadequate Supply Chain Security"
    assert f.masvs == "MSTG-AUTH-3"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
