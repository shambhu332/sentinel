"""Unit tests for A_009 TapJackingAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import TapJackingAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, manifest=None, with_resources=True):
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
    d = ws / "decompiled"
    d.mkdir(exist_ok=True)
    ctx.decompiled_dir = d
    if with_resources:
        res = ws / "resources"
        (res / "res" / "layout").mkdir(parents=True, exist_ok=True)
        ctx.resources_dir = res
    if manifest is not None:
        ctx.manifest = manifest
    return ctx


def _plant_java(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


def _plant_layout(ctx, name: str, body: str) -> None:
    f = ctx.resources_dir / "res" / "layout" / name
    f.write_text(body)


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    agent = TapJackingAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- sensitive name without opt-in ----------


_BARE_LOGIN = """
package com.x;
import android.app.Activity;
public class LoginActivity extends Activity {
  public void onCreate(android.os.Bundle s) {}
}
"""


@pytest.mark.asyncio
async def test_sensitive_name_without_opt_in_is_high(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.LoginActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.LoginActivity", _BARE_LOGIN)
    agent = TapJackingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "A_009"
    assert f.severity == Severity.HIGH
    assert f.evidence["matched_via"] == "name_hint"
    assert f.evidence["xml_opt_in_anywhere"] is False


# ---------- opt-in in Java suppresses ----------


_LOGIN_WITH_OPT_IN = """
package com.x;
import android.app.Activity;
public class LoginActivity extends Activity {
  public void onCreate(android.os.Bundle s) {
    findViewById(android.R.id.button1)
        .setFilterTouchesWhenObscured(true);
  }
}
"""


@pytest.mark.asyncio
async def test_java_opt_in_suppresses_finding(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.LoginActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.LoginActivity", _LOGIN_WITH_OPT_IN)
    agent = TapJackingAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- XML opt-in demotes ----------


@pytest.mark.asyncio
async def test_xml_opt_in_demotes_to_medium(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.LoginActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.LoginActivity", _BARE_LOGIN)
    _plant_layout(ctx, "secure_screen.xml", """<?xml version="1.0"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:filterTouchesWhenObscured="true">
</LinearLayout>
""")
    agent = TapJackingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["xml_opt_in_anywhere"] is True


# ---------- body signal hit ----------


_GENERIC_NAME_BIOMETRIC = """
package com.x;
import android.app.Activity;
import androidx.biometric.BiometricPrompt;
public class HomeActivity extends Activity {
  void show() { new BiometricPrompt(this, null, null); }
}
"""


@pytest.mark.asyncio
async def test_body_signal_matches_when_name_is_generic(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.HomeActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.HomeActivity", _GENERIC_NAME_BIOMETRIC)
    agent = TapJackingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["matched_via"] == "body_signal"


# ---------- non-sensitive activity ignored ----------


_BORING = """
package com.x;
import android.app.Activity;
public class HelpActivity extends Activity {
  void show() {}
}
"""


@pytest.mark.asyncio
async def test_non_sensitive_activity_not_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.HelpActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.HelpActivity", _BORING)
    agent = TapJackingAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- multiple activities, mixed ----------


@pytest.mark.asyncio
async def test_mixed_activities_one_finding(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "activities": [
                "com.x.HelpActivity",
                "com.x.PaymentConfirmActivity",
                "com.x.LoginActivity",
            ],
        },
    )
    _plant_java(ctx.decompiled_dir, "com.x.HelpActivity", _BORING)
    _plant_java(ctx.decompiled_dir, "com.x.PaymentConfirmActivity", _LOGIN_WITH_OPT_IN.replace("LoginActivity", "PaymentConfirmActivity"))
    _plant_java(ctx.decompiled_dir, "com.x.LoginActivity", _BARE_LOGIN)
    agent = TapJackingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["activity"] == "com.x.LoginActivity"


# ---------- finding schema ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={"package": "com.x", "activities": ["com.x.LoginActivity"]},
    )
    _plant_java(ctx.decompiled_dir, "com.x.LoginActivity", _BARE_LOGIN)
    agent = TapJackingAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.vuln_class == "Tap-Jacking Exposure"
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-9"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
