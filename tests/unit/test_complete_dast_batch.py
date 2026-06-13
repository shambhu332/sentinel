"""Smoke tests for the final 22 dynamic agents (D_044..D_071).
   One positive test per agent — keeps the suite fast while pinning
   the AGENT_ID, applicability gate, and finding shape.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id


def _apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx(tmp_path: Path, with_resources: bool = False) -> ScanContext:
    apk = _apk(tmp_path / "t.apk")
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    if with_resources:
        (tmp_path / "resources").mkdir()
        ctx.resources_dir = tmp_path / "resources"
    return ctx


@pytest.fixture
async def memory(tmp_path):
    from sentinel.memory import LightweightMemory
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# Each test below verifies: agent fires on a minimal positive case
# and emits a finding with the expected agent_id.
# ============================================================

@pytest.mark.asyncio
async def test_d044_biometric_replay(tmp_path, memory):
    from sentinel.agents.dynamic.d044_biometric_replay import BiometricReplayAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Auth.java").write_text(
        "class Auth { "
        "  BiometricPrompt.AuthenticationCallback cb = "
        "    new BiometricPrompt.AuthenticationCallback() {"
        "      public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {"
        "        grantAccess();"
        "      }"
        "  };"
        "}\n"
    )
    findings = await BiometricReplayAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_044"


@pytest.mark.asyncio
async def test_d045_sqlite_prober(tmp_path, memory):
    from sentinel.agents.dynamic.d045_sqlite_prober import SqliteProberAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Db.java").write_text(
        "class Db extends SQLiteOpenHelper {\n"
        "  void q(Intent i) {\n"
        "    String n = i.getStringExtra(\"name\");\n"
        "    db.rawQuery(\"SELECT * FROM u WHERE name='\" + n + \"'\", null);\n"
        "  }\n"
        "}\n"
    )
    findings = await SqliteProberAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_045"


@pytest.mark.asyncio
async def test_d047_memory_dump(tmp_path, memory):
    from sentinel.agents.dynamic.d047_memory_dump import MemoryDumpTargetAgent
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "activities": [{"name": "com.x.LoginActivity", "exported": True}],
    }
    findings = await MemoryDumpTargetAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_047"


@pytest.mark.asyncio
async def test_d048_webview_xss(tmp_path, memory):
    from sentinel.agents.dynamic.d048_webview_xss import WebViewXssAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Wv.java").write_text(
        "class Wv { void s(WebView w) {"
        "  w.getSettings().setJavaScriptEnabled(true);"
        "  w.loadUrl(externalUrl);"
        "} }\n"
    )
    findings = await WebViewXssAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_048"


@pytest.mark.asyncio
async def test_d049_notification_snoop(tmp_path, memory):
    from sentinel.agents.dynamic.d049_notification_snoop import NotificationSnoopAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "N.java").write_text(
        "class N { void post() {"
        "  new NotificationCompat.Builder(c)"
        "    .setContentText(\"Your OTP is 123456\")"
        "    .build();"
        "} }\n"
    )
    findings = await NotificationSnoopAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_049"


@pytest.mark.asyncio
async def test_d053_side_channel(tmp_path, memory):
    from sentinel.agents.dynamic.d053_side_channel import SideChannelAgent
    ctx = _ctx(tmp_path)
    ctx.app_profile = {"native_libs_info": {"count": 3, "libs": ["a.so", "b.so", "c.so"]}}
    findings = await SideChannelAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_053"


@pytest.mark.asyncio
async def test_d054_graphql_fuzzer(tmp_path, memory):
    from sentinel.agents.dynamic.d054_graphql_fuzzer import GraphqlFuzzerAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Api.java").write_text(
        'class Api { ApolloClient c = new ApolloClient(); }\n'
    )
    findings = await GraphqlFuzzerAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_054"


@pytest.mark.asyncio
async def test_d055_native_heap(tmp_path, memory):
    from sentinel.agents.dynamic.d055_native_heap import NativeHeapAgent
    ctx = _ctx(tmp_path)
    ctx.app_profile = {"native_libs_info": {"count": 2, "libs": ["x.so", "y.so"]}}
    findings = await NativeHeapAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_055"


@pytest.mark.asyncio
async def test_d056_biometric_timing(tmp_path, memory):
    from sentinel.agents.dynamic.d056_biometric_timing import BiometricTimingAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "B.java").write_text(
        "class B { "
        "  void onAuthenticationSucceeded() { "
        "    if (token.equals(stored)) grantAccess();"
        "  }"
        "}\n"
    )
    findings = await BiometricTimingAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_056"


@pytest.mark.asyncio
async def test_d057_state_poisoner(tmp_path, memory):
    from sentinel.agents.dynamic.d057_state_poisoner import StatePoisonerAgent
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "activities": [
            {"name": "com.x.Main", "exported": True,
             "intent_filters": [{"actions": ["android.intent.action.VIEW"]}]},
        ],
    }
    (ctx.decompiled_dir / "Main.java").write_text(
        'class Main { void go(Intent i) {'
        '  boolean a = i.getBooleanExtra("isPremium", false);'
        '  if (a) grant();'
        '} }\n'
    )
    findings = await StatePoisonerAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_057"


@pytest.mark.asyncio
async def test_d058_websocket_injector(tmp_path, memory):
    from sentinel.agents.dynamic.d058_websocket_injector import WebSocketInjectorAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Ws.java").write_text(
        "import okhttp3.WebSocket;\n"
        "class Ws { void open() { client.newWebSocket(req, listener); } }\n"
    )
    findings = await WebSocketInjectorAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_058"


@pytest.mark.asyncio
async def test_d059_clipboard_hijack(tmp_path, memory):
    from sentinel.agents.dynamic.d059_clipboard_hijack import ClipboardHijackAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "C.java").write_text(
        "class C { void p(ClipboardManager m) { "
        "  m.getPrimaryClip().getItemAt(0).getText(); "
        "} }\n"
    )
    findings = await ClipboardHijackAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_059"


@pytest.mark.asyncio
async def test_d060_sensor_spoofing(tmp_path, memory):
    from sentinel.agents.dynamic.d060_sensor_spoofing import SensorSpoofingAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "G.java").write_text(
        "import android.location.LocationManager;\n"
        "class G { Location get(LocationManager m) {"
        "  return m.getLastKnownLocation(\"gps\");"
        "} }\n"
    )
    findings = await SensorSpoofingAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_060"


@pytest.mark.asyncio
async def test_d061_key_extractor(tmp_path, memory):
    from sentinel.agents.dynamic.d061_key_extractor import KeyExtractorAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "K.java").write_text(
        "class K { void x() {"
        "  SecretKeySpec s = new SecretKeySpec(bytes, \"AES\");"
        "  Cipher.getInstance(\"AES\").init(Cipher.ENCRYPT_MODE, s);"
        "} }\n"
    )
    findings = await KeyExtractorAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_061"


@pytest.mark.asyncio
async def test_d062_binder_bomb(tmp_path, memory):
    from sentinel.agents.dynamic.d062_binder_bomb import BinderBombAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "B.java").write_text(
        "class B extends android.os.Binder {"
        "  protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {"
        "    return super.onTransact(code, data, reply, flags);"
        "  }"
        "}\n"
    )
    findings = await BinderBombAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_062"


@pytest.mark.asyncio
async def test_d064_job_hijacker(tmp_path, memory):
    from sentinel.agents.dynamic.d064_job_hijacker import JobHijackerAgent
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "services": [{"name": "com.x.JS", "exported": True}],
    }
    (ctx.decompiled_dir / "J.java").write_text(
        "class J extends JobService {"
        "  public boolean onStartJob(JobParameters params) {"
        "    String r = params.getExtras().getString(\"role\");"
        "    return true;"
        "  }"
        "}\n"
    )
    findings = await JobHijackerAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_064"


@pytest.mark.asyncio
async def test_d066_a11y_abuser(tmp_path, memory):
    from sentinel.agents.dynamic.d066_a11y_abuser import A11yAbuserAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Svc.java").write_text(
        "class Svc extends AccessibilityService {"
        "  void click(AccessibilityNodeInfo n) {"
        "    n.performAction(AccessibilityNodeInfo.ACTION_CLICK);"
        "  }"
        "}\n"
    )
    findings = await A11yAbuserAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_066"


@pytest.mark.asyncio
async def test_d067_split_apk(tmp_path, memory):
    from sentinel.agents.dynamic.d067_split_apk import SplitApkAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "S.java").write_text(
        "import com.google.android.play.core.splitinstall.SplitInstallManager;\n"
        "class S { void install(SplitInstallManager m, SplitInstallRequest r) {"
        "  m.startInstall(r);"
        "} }\n"
    )
    findings = await SplitApkAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_067"


@pytest.mark.asyncio
async def test_d068_wearable_bridge(tmp_path, memory):
    from sentinel.agents.dynamic.d068_wearable_bridge import WearableBridgeAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "W.java").write_text(
        "import com.google.android.gms.wearable.WearableListenerService;\n"
        "class W extends WearableListenerService {"
        "  public void onMessageReceived(MessageEvent e) {"
        "    String email = parse(e);"
        "  }"
        "}\n"
    )
    findings = await WearableBridgeAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_068"


@pytest.mark.asyncio
async def test_d069_autofill_sniffer(tmp_path, memory):
    from sentinel.agents.dynamic.d069_autofill_sniffer import AutofillSnifferAgent
    ctx = _ctx(tmp_path, with_resources=True)
    layouts = ctx.resources_dir / "res" / "layout"
    layouts.mkdir(parents=True)
    (layouts / "login.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '  <EditText android:id="@+id/pw"\n'
        '            android:inputType="textPassword" />\n'
        '</LinearLayout>\n'
    )
    findings = await AutofillSnifferAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_069"


@pytest.mark.asyncio
async def test_d070_pip_spy(tmp_path, memory):
    from sentinel.agents.dynamic.d070_pip_spy import PipSpyAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "P.java").write_text(
        "class P { void go() { activity.enterPictureInPictureMode(); } }\n"
    )
    findings = await PipSpyAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_070"


@pytest.mark.asyncio
async def test_d071_twa_breaker(tmp_path, memory):
    from sentinel.agents.dynamic.d071_twa_breaker import TwaBreakerAgent
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "T.java").write_text(
        "import androidx.browser.customtabs.CustomTabsIntent;\n"
        "class T { void open() {"
        "  CustomTabsIntent c = new CustomTabsIntent.Builder().build();"
        "  c.launchUrl(ctx, Uri.parse(\"https://example.com\"));"
        "} }\n"
    )
    findings = await TwaBreakerAgent(context=ctx, memory=memory).analyze()
    assert findings and findings[0].agent_id == "D_071"
