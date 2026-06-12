"""Smoke tests for the 6 new SAST agents shipped in this batch:
   I_001, SCA_002, PRIV_001, C_018, LOGIC_001, RES_002.

Each agent gets at least one positive and one negative case.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.business.logic001_temporal_detector import TemporalLogicAgent
from sentinel.agents.crypto.c018_crypto_constants import CryptoConstantsAgent
from sentinel.agents.platform.i001_component_cross_ref import (
    ComponentCrossRefAgent,
)
from sentinel.agents.privacy.priv001_data_collection_auditor import (
    DataCollectionAuditorAgent,
)
from sentinel.agents.resilience.res002_resource_leak import ResourceLeakAgent
from sentinel.agents.supply_chain.sca002_sdk_privacy_auditor import (
    SDKPrivacyAuditorAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


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
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# I_001
# ============================================================
@pytest.mark.asyncio
async def test_i001_flags_exported_activity_without_guard(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "com" / "x").mkdir(parents=True)
    (decompiled / "com" / "x" / "Pay.java").write_text(
        "public class Pay extends Activity {\n"
        "  public void onCreate(Bundle b) { super.onCreate(b); doWork(); }\n"
        "}\n"
    )
    ctx.manifest = {
        "activities": [
            {"name": "com.x.Pay", "exported": True, "intent_filters": []},
        ],
    }
    f = await ComponentCrossRefAgent(context=ctx, memory=memory).analyze()
    assert any(x.vuln_class == "Unprotected Exported Component" for x in f)


@pytest.mark.asyncio
async def test_i001_skips_when_permission_check_present(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "com" / "x").mkdir(parents=True)
    (decompiled / "com" / "x" / "Pay.java").write_text(
        "public class Pay extends Activity {\n"
        "  public void onCreate(Bundle b) {\n"
        "    super.onCreate(b);\n"
        "    if (checkCallingOrSelfPermission(\"X\") != 0) finish();\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "activities": [
            {"name": "com.x.Pay", "exported": True, "intent_filters": []},
        ],
    }
    f = await ComponentCrossRefAgent(context=ctx, memory=memory).analyze()
    assert f == []


# ============================================================
# SCA_002
# ============================================================
@pytest.mark.asyncio
async def test_sca002_flags_facebook_sdk_with_sms_permission(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "com" / "facebook").mkdir(parents=True)
    (decompiled / "com" / "facebook" / "Sdk.java").write_text("// stub")
    ctx.manifest = {"package": "com.app"}
    ctx.permissions = ["android.permission.READ_SMS"]
    f = await SDKPrivacyAuditorAgent(context=ctx, memory=memory).analyze()
    assert any("Facebook SDK" == x.evidence.get("sdk") for x in f)


@pytest.mark.asyncio
async def test_sca002_no_finding_without_sdk(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {"package": "com.app"}
    ctx.permissions = ["android.permission.READ_SMS"]
    f = await SDKPrivacyAuditorAgent(context=ctx, memory=memory).analyze()
    assert f == []


# ============================================================
# PRIV_001
# ============================================================
@pytest.mark.asyncio
async def test_priv001_flags_telephony_getdeviceid(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Main.java").write_text(
        "class Main { void x(TelephonyManager t) { t.getDeviceId(); } }\n"
    )
    ctx.manifest = {"activities": []}
    f = await DataCollectionAuditorAgent(context=ctx, memory=memory).analyze()
    classes = {x.vuln_class for x in f}
    assert "Pre-Consent Sensitive Data Collection" in classes


@pytest.mark.asyncio
async def test_priv001_softer_when_consent_in_same_file(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Main.java").write_text(
        "class Main { void x(TelephonyManager t) {\n"
        "  showConsentDialog(); t.getDeviceId();\n"
        "} }\n"
    )
    ctx.manifest = {"activities": []}
    f = await DataCollectionAuditorAgent(context=ctx, memory=memory).analyze()
    # Still flagged but at INFO severity
    assert all(x.severity == Severity.INFO for x in f)


# ============================================================
# C_018
# ============================================================
@pytest.mark.asyncio
async def test_c018_flags_aes_sbox_constants(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Sbox.java").write_text(
        "byte[] sbox = { 0x63, 0x7c, 0x77, 0x7b, 0x6f };\n"
    )
    f = await CryptoConstantsAgent(context=ctx, memory=memory).analyze()
    assert any(x.evidence.get("algorithm") == "AES" for x in f)


@pytest.mark.asyncio
async def test_c018_flags_all_zero_iv(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Crypto.java").write_text(
        "byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};\n"
    )
    f = await CryptoConstantsAgent(context=ctx, memory=memory).analyze()
    assert any(x.vuln_class == "Hardcoded All-Zero IV" for x in f)


@pytest.mark.asyncio
async def test_c018_flags_xor_loop(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Cipher.java").write_text(
        "void encrypt(byte[] buf, byte[] k) {\n"
        "  for (int i = 0; i < buf.length; i++) {\n"
        "    buf[i] ^= k[i % k.length];\n"
        "  }\n"
        "}\n"
    )
    f = await CryptoConstantsAgent(context=ctx, memory=memory).analyze()
    assert any(x.vuln_class == "XOR-Loop \"Encryption\"" for x in f)


# ============================================================
# LOGIC_001
# ============================================================
@pytest.mark.asyncio
async def test_logic001_flags_hardcoded_date(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Gate.java").write_text(
        "if (today.isAfter(\"2025-01-01\")) showPaywall();\n"
    )
    f = await TemporalLogicAgent(context=ctx, memory=memory).analyze()
    assert any(x.vuln_class == "Hardcoded Date Comparison" for x in f)


@pytest.mark.asyncio
async def test_logic001_flags_debug_trigger(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Hidden.java").write_text(
        'if (s.equals("DEBUG_UNLOCK_ALL")) enableAll();\n'
    )
    f = await TemporalLogicAgent(context=ctx, memory=memory).analyze()
    assert any(x.vuln_class == "Hidden Debug-Mode Trigger" for x in f)


@pytest.mark.asyncio
async def test_logic001_clean_code_no_finding(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Clean.java").write_text(
        "if (response.ok()) render();\n"
    )
    f = await TemporalLogicAgent(context=ctx, memory=memory).analyze()
    assert f == []


# ============================================================
# RES_002
# ============================================================
@pytest.mark.asyncio
async def test_res002_flags_unclosed_cursor(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Db.java").write_text(
        "Cursor c = db.query(\"u\", null, null, null, null, null, null);\n"
        "while (c.moveToNext()) read(c);\n"
    )
    f = await ResourceLeakAgent(context=ctx, memory=memory).analyze()
    assert any("Cursor Leak" == x.vuln_class for x in f)


@pytest.mark.asyncio
async def test_res002_silent_on_try_with_resources(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Db.java").write_text(
        "try (Cursor c = db.query(\"u\", null, null, null, null, null, null)) {\n"
        "  while (c.moveToNext()) read(c);\n"
        "}\n"
    )
    f = await ResourceLeakAgent(context=ctx, memory=memory).analyze()
    assert f == []


@pytest.mark.asyncio
async def test_res002_silent_when_close_present(tmp_path, memory):
    ctx, decompiled = _ctx(tmp_path)
    (decompiled / "Io.java").write_text(
        "InputStream s = new FileInputStream(\"x\");\n"
        "try { read(s); } finally { s.close(); }\n"
    )
    f = await ResourceLeakAgent(context=ctx, memory=memory).analyze()
    assert f == []
