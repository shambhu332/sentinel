"""Unit tests for A_011 RefreshTokenReuseAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import RefreshTokenReuseAgent
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
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_logout_without_clear_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.SharedPreferences;
class Auth {
  void store(SharedPreferences prefs, String t) {
    prefs.edit().putString("refresh_token", t).apply();
  }
  public void logout() {
    user = null;
    navigateToLogin();
  }
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "A_011"
    assert f.severity == Severity.HIGH
    assert f.evidence["method"] == "logout"


@pytest.mark.asyncio
async def test_logout_with_remove_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.SharedPreferences;
class Auth {
  void store(SharedPreferences prefs, String t) {
    prefs.edit().putString("refresh_token", t).apply();
  }
  public void logout(SharedPreferences prefs) {
    user = null;
    prefs.edit().remove("refresh_token").apply();
  }
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_logout_with_clear_all_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.SharedPreferences;
class Auth {
  void store(SharedPreferences prefs, String t) {
    prefs.edit().putString("refresh_token", t).apply();
  }
  public void signOut(SharedPreferences prefs) {
    user = null;
    prefs.edit().clear().apply();
  }
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_refresh_token_storage_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
class Plain {
  public void logout() { user = null; }
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_uncertain_helper_demotes_to_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.SharedPreferences;
class Auth {
  void store(SharedPreferences prefs, String t) {
    prefs.edit().putString("refresh_token", t).apply();
  }
  public void logout() {
    user = null;
    clearCache();
  }
  void clearCache() {}
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["helper_in_scope"] == "clearCache"


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.A", """
import android.content.SharedPreferences;
class A {
  void s(SharedPreferences p, String t) { p.edit().putString("refresh_token", t).apply(); }
  public void logout() { user = null; }
}
""")
    agent = RefreshTokenReuseAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M2: Inadequate Supply Chain Security"
    assert f.masvs == "MSTG-AUTH-7"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
