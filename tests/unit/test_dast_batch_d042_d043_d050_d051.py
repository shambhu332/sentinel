"""Tests for D_042 deep-link bomb, D_043 hidden-API hunter,
   D_050 pinning stress, D_051 service leaker."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d042_deep_link_bomb import DeepLinkBombAgent
from sentinel.agents.dynamic.d043_hidden_api_hunter import HiddenApiHunterAgent
from sentinel.agents.dynamic.d050_pinning_stress_test import (
    PinningStressTestAgent,
)
from sentinel.agents.dynamic.d051_service_leaker import ServiceLeakerAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id


def _apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx(tmp_path: Path) -> tuple[ScanContext, Path]:
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
    return ctx, decompiled


@pytest.fixture
async def memory(tmp_path):
    from sentinel.memory import LightweightMemory
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# D_042 DeepLinkBomb
# ============================================================

@pytest.mark.asyncio
async def test_d042_emits_payload_for_view_activity(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.x.app",
        "activities": [
            {
                "name": "com.x.MainActivity",
                "exported": True,
                "intent_filters": [{
                    "actions": ["android.intent.action.VIEW"],
                    "schemes": ["myapp"],
                    "hosts": ["target"],
                }],
            },
        ],
    }
    findings = await DeepLinkBombAgent(context=ctx, memory=memory).analyze()
    assert len(findings) == 1
    payload = findings[0].evidence.get("frida_payload") or {}
    assert payload.get("package") == "com.x.app"
    assert payload.get("activity") == "com.x.MainActivity"
    # myapp:// rewritten to the configured scheme/host
    probes = payload.get("probes") or []
    assert any("myapp://target/" in p for p in probes)
    assert payload.get("safety_budget", {}).get("max_actions_total") == 50


@pytest.mark.asyncio
async def test_d042_skips_activity_without_view_action(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.x.app",
        "activities": [
            {"name": "Plain", "exported": True,
             "intent_filters": [{"actions": ["android.intent.action.MAIN"]}]},
        ],
    }
    findings = await DeepLinkBombAgent(context=ctx, memory=memory).analyze()
    assert findings == []


# ============================================================
# D_043 HiddenApiHunter
# ============================================================

@pytest.mark.asyncio
async def test_d043_captures_internal_path(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "ApiClient.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class ApiClient {\n"
        "  void hit() {\n"
        "    OkHttpClient c = new OkHttpClient.Builder().build();\n"
        '    Request r = new Request.Builder()'
        '.url("https://api.example.com/internal/admin/users").build();\n'
        "  }\n"
        "}\n"
    )
    findings = await HiddenApiHunterAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    urls = findings[0].evidence.get("urls") or []
    assert any("internal" in u["url"] for u in urls)
    assert any(u.get("internal_reason") == "internal_path" for u in urls)


@pytest.mark.asyncio
async def test_d043_captures_staging_host(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Api.java").write_text(
        "import retrofit2.Retrofit;\n"
        "class Api { void x() {\n"
        '  Retrofit r = new Retrofit.Builder()'
        '.baseUrl("https://staging.api.acme.com/v1/").build();\n'
        "} }\n"
    )
    findings = await HiddenApiHunterAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings
    urls = findings[0].evidence.get("urls") or []
    assert any(u.get("internal_reason") == "internal_host" for u in urls)


@pytest.mark.asyncio
async def test_d043_no_finding_when_all_urls_normal(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Api.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class Api { void x() {\n"
        '  String url = "https://api.example.com/v1/products";\n'
        "  OkHttpClient c = new OkHttpClient();\n"
        "} }\n"
    )
    findings = await HiddenApiHunterAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ============================================================
# D_050 PinningStressTest
# ============================================================

@pytest.mark.asyncio
async def test_d050_maps_two_pinning_layers(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Pinned.java").write_text(
        "import okhttp3.CertificatePinner;\n"
        "import javax.net.ssl.X509TrustManager;\n"
        "class Pinned implements X509TrustManager {\n"
        "  void build() {\n"
        "    new CertificatePinner.Builder()"
        '.add("api.acme.com", "sha256/AAAAAAA=").build();\n'
        "  }\n"
        "  public void checkServerTrusted(X509Certificate[] c, String t) {}\n"
        "}\n"
    )
    findings = await PinningStressTestAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    layers = findings[0].evidence.get("layers") or {}
    assert "okhttp_certificate_pinner" in layers
    assert "x509_trust_manager" in layers
    # 2 layers -> LOW severity per the band
    assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_d050_single_layer_is_medium(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "OnlyHandler.java").write_text(
        "import android.webkit.WebViewClient;\n"
        "class V extends WebViewClient {\n"
        "  public void onReceivedSslError(WebView v, SslErrorHandler h, "
        "SslError e) {\n"
        "    h.proceed();\n"
        "  }\n"
        "}\n"
    )
    findings = await PinningStressTestAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d050_no_pinning_no_finding(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Plain.java").write_text(
        "class Plain { void x() { log(\"hi\"); } }\n"
    )
    findings = await PinningStressTestAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ============================================================
# D_051 ServiceLeaker
# ============================================================

@pytest.mark.asyncio
async def test_d051_flags_unprotected_exported_service(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Worker.java").write_text(
        "public class Worker extends IntentService {\n"
        "  public Worker() { super(\"Worker\"); }\n"
        "  protected void onHandleIntent(Intent i) {\n"
        "    doStuff(i.getExtras());\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "services": [
            {
                "name": "com.x.Worker",
                "exported": True,
                "intent_filters": [
                    {"actions": ["com.x.ACTION_RUN"]},
                ],
            },
        ],
    }
    findings = await ServiceLeakerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    payload = findings[0].evidence.get("frida_payload") or {}
    assert payload.get("service_name") == "com.x.Worker"
    assert "com.x.ACTION_RUN" in (payload.get("actions") or [])
    assert payload.get("safety_budget", {}).get("max_actions_total") == 15


@pytest.mark.asyncio
async def test_d051_skips_permission_guarded_service(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {
        "services": [
            {"name": "com.x.Guarded", "exported": True,
             "permission": "com.x.MY_PERMISSION"},
        ],
    }
    findings = await ServiceLeakerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
