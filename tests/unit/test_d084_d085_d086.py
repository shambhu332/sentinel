"""Tests for D_084 WebView Universal XSS, D_085 Provider LFI, D_086 Intent XSS.

Per the brief's safety guidance — every payload assertion confirms
the probes are non-destructive (console.log only, app-owned files
only, no forbidden system paths).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d084_webview_xss import WebViewUniversalXssAgent
from sentinel.agents.dynamic.d085_provider_lfi import ProviderLfiAgent
from sentinel.agents.dynamic.d086_intent_xss import IntentXssAgent
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
        (tmp_path / "resources" / "res" / "xml").mkdir(parents=True)
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
# D_084 WebView Universal XSS
# ============================================================

@pytest.mark.asyncio
async def test_d084_critical_when_universal_access_enabled(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Wv.java").write_text(
        "import android.webkit.WebView;\n"
        "class Wv {\n"
        "  void setup(WebView wv) {\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.getSettings().setAllowUniversalAccessFromFileURLs(true);\n"
        "  }\n"
        "}\n"
    )
    findings = await WebViewUniversalXssAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["allow_universal_access_from_file_urls"]


@pytest.mark.asyncio
async def test_d084_high_when_file_from_file_urls(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Wv.java").write_text(
        "import android.webkit.WebView;\n"
        "class Wv {\n"
        "  void setup(WebView wv) {\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.getSettings().setAllowFileAccessFromFileURLs(true);\n"
        "  }\n"
        "}\n"
    )
    findings = await WebViewUniversalXssAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d084_skips_when_no_file_origin_elevation(tmp_path, memory):
    # JS + loadUrl present but NO file-origin flags — D_048 covers this,
    # D_084 should not duplicate.
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Wv.java").write_text(
        "import android.webkit.WebView;\n"
        "class Wv {\n"
        "  void setup(WebView wv) {\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.loadUrl(\"https://example.com/\");\n"
        "  }\n"
        "}\n"
    )
    findings = await WebViewUniversalXssAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d084_payload_is_console_log_only(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "Wv.java").write_text(
        "import android.webkit.WebView;\n"
        "class Wv {\n"
        "  void setup(WebView wv) {\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.getSettings().setAllowUniversalAccessFromFileURLs(true);\n"
        "  }\n"
        "}\n"
    )
    findings = await WebViewUniversalXssAgent(
        context=ctx, memory=memory,
    ).analyze()
    payload = findings[0].evidence["frida_payload"]
    # Brief safety: probes are non-destructive. Each probe must use
    # console.log and must NOT call alert / prompt / document.write.
    forbidden = ("alert(", "prompt(", "document.write", "fetch('http")
    for probe in payload["probes"]:
        for f in forbidden:
            assert f not in probe, f"forbidden destructive primitive: {f}"
    assert payload["expect_console_token"].startswith("SENTINEL_XSS_PROBE_")


# ============================================================
# D_085 Provider LFI (paths.xml policy audit)
# ============================================================

@pytest.mark.asyncio
async def test_d085_flags_root_path_wildcard(tmp_path, memory):
    ctx = _ctx(tmp_path, with_resources=True)
    (ctx.resources_dir / "res" / "xml" / "file_paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<paths>\n'
        '  <root-path name="rootfs" path="." />\n'
        '</paths>\n'
    )
    ctx.manifest = {
        "providers": [{
            "name": "androidx.core.content.FileProvider",
            "authority": "com.x.fp",
        }],
    }
    findings = await ProviderLfiAgent(context=ctx, memory=memory).analyze()
    assert findings
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d085_high_when_external_path_broad(tmp_path, memory):
    ctx = _ctx(tmp_path, with_resources=True)
    (ctx.resources_dir / "res" / "xml" / "provider_paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<paths>\n'
        '  <external-path name="ext" path="" />\n'
        '</paths>\n'
    )
    ctx.manifest = {"providers": [{
        "name": "androidx.core.content.FileProvider",
        "authority": "com.x.fp",
    }]}
    findings = await ProviderLfiAgent(context=ctx, memory=memory).analyze()
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d085_skips_narrow_path(tmp_path, memory):
    ctx = _ctx(tmp_path, with_resources=True)
    (ctx.resources_dir / "res" / "xml" / "file_paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<paths>\n'
        '  <files-path name="images" path="shared_images/" />\n'
        '</paths>\n'
    )
    ctx.manifest = {"providers": []}
    findings = await ProviderLfiAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d085_payload_blocks_system_paths(tmp_path, memory):
    ctx = _ctx(tmp_path, with_resources=True)
    (ctx.resources_dir / "res" / "xml" / "file_paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<paths>\n'
        '  <root-path name="rootfs" path="." />\n'
        '</paths>\n'
    )
    ctx.manifest = {"providers": [{
        "name": "androidx.core.content.FileProvider",
        "authority": "com.x.fp",
    }]}
    findings = await ProviderLfiAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    # Per brief safety: never read system files.
    assert payload["block_off_app_targets"] is True
    assert "/etc/" in payload["forbidden_path_substrings"]
    assert "/system/" in payload["forbidden_path_substrings"]
    assert "shadow" in payload["forbidden_path_substrings"]
    # Probe URIs reference only files in safe_app_owned_files.
    safe_files = payload["safe_app_owned_files"]
    flat = " ".join(payload["probe_uris"]).lower()
    forbidden = ("/etc/", "/system/", "/proc/", "shadow", "passwd")
    for f in forbidden:
        assert f not in flat, f"forbidden path appeared in probe URI: {f}"
    # Each probe URI ends with an app-owned filename
    for uri in payload["probe_uris"]:
        assert any(uri.endswith(f) for f in safe_files), \
            f"URI does not target an app-owned file: {uri}"


# ============================================================
# D_086 Intent Injection XSS
# ============================================================

@pytest.mark.asyncio
async def test_d086_flags_intent_to_load_url_flow(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "WebViewActivity.java").write_text(
        "import android.webkit.WebView;\n"
        "class WebViewActivity {\n"
        "  void onCreate() {\n"
        "    String url = getIntent().getStringExtra(\"url\");\n"
        "    WebView wv = new WebView(this);\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.loadUrl(url);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "activities": [{
            "name": "com.x.WebViewActivity",
            "exported": True,
        }],
    }
    findings = await IntentXssAgent(context=ctx, memory=memory).analyze()
    assert findings
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d086_medium_when_not_exported(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "WebViewActivity.java").write_text(
        "import android.webkit.WebView;\n"
        "class WebViewActivity {\n"
        "  void onCreate() {\n"
        "    String url = getIntent().getStringExtra(\"url\");\n"
        "    WebView wv = new WebView(this);\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.loadUrl(url);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "activities": [{
            "name": "com.x.WebViewActivity",
            "exported": False,
        }],
    }
    findings = await IntentXssAgent(context=ctx, memory=memory).analyze()
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d086_skips_when_no_intent_source(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "WebViewActivity.java").write_text(
        "import android.webkit.WebView;\n"
        "class WebViewActivity {\n"
        "  void onCreate() {\n"
        "    WebView wv = new WebView(this);\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.loadUrl(\"https://example.com/\");\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {"activities": []}
    findings = await IntentXssAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d086_payload_console_log_only(tmp_path, memory):
    ctx = _ctx(tmp_path)
    (ctx.decompiled_dir / "WV.java").write_text(
        "import android.webkit.WebView;\n"
        "class WV {\n"
        "  void onCreate() {\n"
        "    String url = getIntent().getStringExtra(\"url\");\n"
        "    WebView wv = new WebView(this);\n"
        "    wv.getSettings().setJavaScriptEnabled(true);\n"
        "    wv.loadUrl(url);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {"activities": [{"name": "com.x.WV", "exported": True}]}
    findings = await IntentXssAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    forbidden = ("alert(", "prompt(", "document.write", "fetch('http")
    for probe in payload["probes"]:
        for f in forbidden:
            assert f not in probe
    assert payload["expect_console_token"].startswith(
        "SENTINEL_INTENT_XSS_PROBE_",
    )
