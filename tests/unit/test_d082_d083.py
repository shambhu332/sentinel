"""Tests for D_082 IAP Spoofing + D_083 Mobile SSRF SAST agents.

The IAP state-manipulation logic itself lives in the TS hook; here we
pin the SAST identification + safety-guarantee assertions on the
Python side (severity bands, dynamic_target flag, payload allow-list).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d082_iap_spoofing import IapSpoofingAgent
from sentinel.agents.dynamic.d083_mobile_ssrf import MobileSsrfAgent
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
# D_082 IAP Spoofing
# ============================================================

@pytest.mark.asyncio
async def test_d082_flags_listener_with_direct_entitlement(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Billing.java").write_text(
        "import com.android.billingclient.api.BillingClient;\n"
        "class Billing implements PurchasesUpdatedListener {\n"
        "  public void onPurchasesUpdated(BillingResult r, List<Purchase> p) {\n"
        "    setPremium(true);\n"
        '    prefs.edit().putBoolean("premium", true).apply();\n'
        "  }\n"
        "}\n"
    )
    findings = await IapSpoofingAgent(context=ctx, memory=memory).analyze()
    assert any(
        f.severity == Severity.HIGH
        and f.evidence.get("direct_entitlement_in_callback") is True
        and f.evidence.get("dynamic_target") is True
        for f in findings
    )


@pytest.mark.asyncio
async def test_d082_skips_when_token_flows_to_network(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "VerifiedBilling.java").write_text(
        "import com.android.billingclient.api.BillingClient;\n"
        "class VerifiedBilling implements PurchasesUpdatedListener {\n"
        "  public void onPurchasesUpdated(BillingResult r, List<Purchase> p) {\n"
        "    String tok = p.get(0).getPurchaseToken();\n"
        "    OkHttpClient c = new OkHttpClient();\n"
        '    c.newCall(new Request.Builder().url("/verify").post(tok).build())\n'
        "      .execute();\n"
        "  }\n"
        "}\n"
    )
    findings = await IapSpoofingAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d082_no_billing_no_finding(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Plain.java").write_text(
        "class Plain { void x() { log(\"hi\"); } }\n"
    )
    findings = await IapSpoofingAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d082_payload_is_local_only(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Billing.java").write_text(
        "import com.android.billingclient.api.BillingClient;\n"
        'class Billing implements PurchasesUpdatedListener {\n'
        "  void onPurchasesUpdated(BillingResult r, List<Purchase> p) {\n"
        '    setPremium(true);\n'
        "  }\n"
        "}\n"
    )
    findings = await IapSpoofingAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    # Brief's safety guidance: hook must NOT process real payments.
    assert payload["safe_mode_local_only"] is True
    assert payload["purchase_state"] == 1  # PURCHASED
    assert payload["fake_purchase_token"].startswith("fake_token_d082_")
    # No real-money URL in any payload field
    flat = str(payload).lower()
    assert "play.google.com" not in flat
    assert "googleapis.com" not in flat


# ============================================================
# D_083 Mobile SSRF
# ============================================================

@pytest.mark.asyncio
async def test_d083_flags_url_from_intent_to_okhttp(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Fetcher.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class Fetcher {\n"
        "  void go(Intent intent) {\n"
        "    String url = intent.getStringExtra(\"url\");\n"
        "    OkHttpClient c = new OkHttpClient.Builder().build();\n"
        "    c.newCall(new Request.Builder().url(url).build()).execute();\n"
        "  }\n"
        "}\n"
    )
    findings = await MobileSsrfAgent(context=ctx, memory=memory).analyze()
    assert any(
        f.severity == Severity.HIGH
        and "okhttp_newcall" in f.evidence.get("matched_sinks", [])
        and f.evidence.get("dynamic_target") is True
        for f in findings
    )


@pytest.mark.asyncio
async def test_d083_flags_webview_load_from_deeplink(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Wv.java").write_text(
        "class Wv {\n"
        "  void onCreate(WebView wv, Intent i) {\n"
        "    String u = i.getData().getQueryParameter(\"next\");\n"
        "    wv.loadUrl(u);\n"
        "  }\n"
        "}\n"
    )
    findings = await MobileSsrfAgent(context=ctx, memory=memory).analyze()
    assert any(
        f.severity == Severity.HIGH
        and "webview_load" in f.evidence.get("matched_sinks", [])
        for f in findings
    )


@pytest.mark.asyncio
async def test_d083_skips_when_no_user_input(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Hardcoded.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class Hardcoded {\n"
        "  void go() {\n"
        "    OkHttpClient c = new OkHttpClient();\n"
        "    c.newCall(new Request.Builder().url(\"https://api.example.com/v1\")\n"
        "                                   .build()).execute();\n"
        "  }\n"
        "}\n"
    )
    findings = await MobileSsrfAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d083_payload_blocks_external_destinations(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Fetcher.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class Fetcher {\n"
        "  void go(Intent i) {\n"
        "    String u = i.getStringExtra(\"url\");\n"
        "    new OkHttpClient().newCall(new Request.Builder().url(u).build())\n"
        "      .execute();\n"
        "  }\n"
        "}\n"
    )
    findings = await MobileSsrfAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    # Brief's safety guidance: probes are LOCAL/PRIVATE only.
    assert payload["block_external"] is True
    # Every configured probe must start with an allow-listed prefix.
    allowed = payload["allowed_destination_prefixes"]
    for probe in payload["probe_destinations"]:
        assert any(probe.startswith(a) for a in allowed), \
            f"Unsafe probe destination would leak externally: {probe}"
    # Cloud-metadata addresses present
    flat = " ".join(payload["probe_destinations"])
    assert "169.254.169.254" in flat
    assert "metadata.google.internal" in flat


@pytest.mark.asyncio
async def test_d083_payload_excludes_public_internet(tmp_path, memory):
    """The probe list must never contain a public IP / public domain."""
    ctx, root = _ctx(tmp_path)
    (root / "Fetcher.java").write_text(
        "import okhttp3.OkHttpClient;\n"
        "class Fetcher {\n"
        "  void go(Intent i) {\n"
        "    String u = i.getStringExtra(\"url\");\n"
        "    new OkHttpClient().newCall(new Request.Builder().url(u).build())\n"
        "      .execute();\n"
        "  }\n"
        "}\n"
    )
    findings = await MobileSsrfAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    # The brief: "Do not allow scanning of external third-party servers."
    forbidden = (
        "google.com", "facebook.com", "amazon.com", "evil.com",
        "8.8.8.8", "1.1.1.1",
    )
    flat = " ".join(payload["probe_destinations"]).lower()
    for f in forbidden:
        assert f not in flat, f"Forbidden destination present: {f}"
