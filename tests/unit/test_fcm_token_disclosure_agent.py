"""Unit tests for F_002 FcmTokenDisclosureAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.cloud import FcmTokenDisclosureAgent
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
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_fcm_usage_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
class Plain {
  void run() {
    String token = "x";
    android.util.Log.d("T", token);
  }
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_token_logged_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Push", """
import com.google.firebase.messaging.FirebaseMessaging;
import android.util.Log;
class Push {
  void wire() {
    FirebaseMessaging.getInstance().getToken();
    String fcmToken = "...";
    Log.d("FCM", "token=" + fcmToken);
  }
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "F_002"
    assert f.severity == Severity.HIGH
    assert f.vuln_class == "FCM Token Logged to Logcat"


@pytest.mark.asyncio
async def test_token_logged_with_buildconfig_guard_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Push", """
import com.google.firebase.messaging.FirebaseMessaging;
import android.util.Log;
import com.x.BuildConfig;
class Push {
  void wire() {
    FirebaseMessaging.getInstance().getToken();
    String fcmToken = "...";
    if (BuildConfig.DEBUG) {
      Log.d("FCM", "token=" + fcmToken);
    }
  }
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["guard_detected"] is True


@pytest.mark.asyncio
async def test_token_sent_over_http_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Push", """
import com.google.firebase.messaging.FirebaseMessaging;
class Push {
  void wire() {
    FirebaseMessaging.getInstance().getToken();
    String fcmToken = "...";
    String url = "http://collector.example.com/upload";
    sendPost(url, fcmToken);
  }
  void sendPost(String u, String b) {}
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_class == "FCM Token Sent Over HTTP"
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_token_only_used_for_topic_subscription_safe(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Topic", """
import com.google.firebase.messaging.FirebaseMessaging;
class Topic {
  void wire() {
    FirebaseMessaging.getInstance().getToken();
    String fcmToken = "...";
    FirebaseMessaging.getInstance().subscribeToTopic("news");
  }
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_combined_log_and_http_emit_two_findings(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Push", """
import com.google.firebase.messaging.FirebaseMessaging;
import android.util.Log;
class Push {
  void wire() {
    FirebaseMessaging.getInstance().getToken();
    String fcmToken = "...";
    Log.d("FCM", fcmToken);
    String url = "http://collector.example.com/upload";
    sendPost(url, fcmToken);
  }
  void sendPost(String u, String b) {}
}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    classes = sorted(f.vuln_class for f in findings)
    assert classes == ["FCM Token Logged to Logcat", "FCM Token Sent Over HTTP"]


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Push", """
import com.google.firebase.messaging.FirebaseMessaging;
import android.util.Log;
class Push { void w() {
  FirebaseMessaging.getInstance().getToken();
  String fcmToken = "...";
  Log.d("T", fcmToken);
}}
""")
    agent = FcmTokenDisclosureAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp.startswith("M")
    assert f.masvs and f.masvs.startswith("MSTG-")
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
