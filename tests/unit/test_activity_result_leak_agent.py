"""Unit tests for P_007 ActivityResultLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import ActivityResultLeakAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, manifest=None, decompiled=True):
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
    if manifest is not None:
        ctx.manifest = manifest
    return ctx


def _exported_activity(name, permission=""):
    return {
        "type": "activity",
        "name": name,
        "explicitly_exported": True,
        "has_intent_filter": False,
        "permission": permission,
    }


def _plant(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_exported_activities(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={"package": "com.x", "exported_components": []})
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_set_result_with_token_extra_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity("com.x.AuthActivity")],
    })
    _plant(ctx.decompiled_dir, "com.x.AuthActivity", """
import android.app.Activity;
import android.content.Intent;
class AuthActivity extends Activity {
  void finish(String token) {
    Intent result = new Intent();
    result.putExtra("auth_token", token);
    setResult(RESULT_OK, result);
    super.finish();
  }
}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "P_007"
    assert f.severity == Severity.CRITICAL
    assert "auth_token" in f.evidence["sensitive_extras"]


@pytest.mark.asyncio
async def test_permission_gate_demotes_to_high(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity(
            "com.x.AuthActivity", permission="com.x.SIGN",
        )],
    })
    _plant(ctx.decompiled_dir, "com.x.AuthActivity", """
import android.app.Activity;
import android.content.Intent;
class AuthActivity extends Activity {
  void finish(String token) {
    Intent result = new Intent();
    result.putExtra("session_id", token);
    setResult(RESULT_OK, result);
  }
}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_non_credential_extra_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity("com.x.PickerActivity")],
    })
    _plant(ctx.decompiled_dir, "com.x.PickerActivity", """
import android.app.Activity;
import android.content.Intent;
class PickerActivity extends Activity {
  void done(String value) {
    Intent result = new Intent();
    result.putExtra("selected_value", value);
    setResult(RESULT_OK, result);
  }
}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_set_result_without_extras_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity("com.x.SimpleActivity")],
    })
    _plant(ctx.decompiled_dir, "com.x.SimpleActivity", """
import android.app.Activity;
import android.content.Intent;
class SimpleActivity extends Activity {
  void done() {
    Intent result = new Intent();
    setResult(RESULT_OK, result);
  }
}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_multiple_credential_keys_collected(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity("com.x.AuthActivity")],
    })
    _plant(ctx.decompiled_dir, "com.x.AuthActivity", """
import android.app.Activity;
import android.content.Intent;
class AuthActivity extends Activity {
  void finish(String token, String otp) {
    Intent result = new Intent();
    result.putExtra("auth_token", token);
    result.putExtra("otp", otp);
    setResult(RESULT_OK, result);
  }
}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    keys = findings[0].evidence["sensitive_extras"]
    assert "auth_token" in keys
    assert "otp" in keys


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path, manifest={
        "package": "com.x",
        "exported_components": [_exported_activity("com.x.AuthActivity")],
    })
    _plant(ctx.decompiled_dir, "com.x.AuthActivity", """
import android.app.Activity;
import android.content.Intent;
class AuthActivity extends Activity { void f(String t) {
  Intent r = new Intent();
  r.putExtra("auth_token", t);
  setResult(RESULT_OK, r);
}}
""")
    agent = ActivityResultLeakAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert "exported" in f.recommendation
