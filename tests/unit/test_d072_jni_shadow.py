"""Tests for D_072 JNI Shadow Executor (SAST half)."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d072_jni_shadow import (
    JniShadowAgent,
    _java_jni_mangle,
)
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
# JNI mangling
# ============================================================

def test_jni_mangle_simple():
    assert _java_jni_mangle("com.acme", "Foo", "doThing") == \
        "Java_com_acme_Foo_doThing"


def test_jni_mangle_underscore_escaped():
    # Literal `_` in any segment becomes `_1`.
    assert _java_jni_mangle("com.acme", "Foo_Bar", "do_thing") == \
        "Java_com_acme_Foo_1Bar_do_1thing"


def test_jni_mangle_empty_package():
    assert _java_jni_mangle("", "Foo", "bar") == "Java__Foo_bar"


# ============================================================
# SAST identification
# ============================================================

@pytest.mark.asyncio
async def test_d072_flags_native_string_method(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "NativeBridge.java").write_text(
        "package com.acme;\n"
        "public class NativeBridge {\n"
        "  public native String formatMessage(String fmt);\n"
        "  public native int safeAdd(int a, int b);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    methods = {f.evidence.get("method") for f in findings}
    assert "formatMessage" in methods
    assert "safeAdd" in methods


@pytest.mark.asyncio
async def test_d072_string_method_is_high_severity(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "NativeBridge.java").write_text(
        "package com.acme;\n"
        "public class NativeBridge {\n"
        "  public native String formatMessage(String fmt);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    f = next(x for x in findings if x.evidence["method"] == "formatMessage")
    assert f.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d072_int_only_method_is_medium(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "Math.java").write_text(
        "package com.acme;\n"
        "public class Math {\n"
        "  public native int safeAdd(int a, int b);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d072_emits_jni_symbol_in_evidence(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "NativeBridge.java").write_text(
        "package com.acme;\n"
        "public class NativeBridge {\n"
        "  public native String formatMessage(String fmt);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    f = findings[0]
    assert f.evidence["jni_symbol"] == \
        "Java_com_acme_NativeBridge_formatMessage"


@pytest.mark.asyncio
async def test_d072_frida_payload_carries_safety_budget(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "NativeBridge.java").write_text(
        "package com.acme;\n"
        "public class NativeBridge {\n"
        "  public native String formatMessage(String fmt);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    assert payload["jni_symbol"] == \
        "Java_com_acme_NativeBridge_formatMessage"
    assert payload["safety_budget"]["max_payload_bytes"] == 512
    assert payload["safety_budget"]["max_mem_violations_per_sec"] == 2
    # Probes must include canary + format string
    kinds = {p["kind"] for p in payload["probes"]}
    assert "canary" in kinds
    assert "format_string" in kinds


@pytest.mark.asyncio
async def test_d072_no_findings_when_no_native_methods(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "Plain.java").write_text(
        "package com.acme;\n"
        "public class Plain { String hi() { return \"hello\"; } }\n"
    )
    ctx.manifest = {"package": "com.acme"}
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d072_uses_app_profile_native_libs_hint(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    pkg_dir = root / "com" / "acme"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "NativeBridge.java").write_text(
        "package com.acme;\n"
        "public class NativeBridge {\n"
        "  public native String formatMessage(String fmt);\n"
        "}\n"
    )
    ctx.manifest = {"package": "com.acme"}
    ctx.app_profile = {
        "native_libs_info": {
            "count": 2,
            "libs": ["libnative.so", "libcrypto.so"],
        },
    }
    findings = await JniShadowAgent(context=ctx, memory=memory).analyze()
    payload = findings[0].evidence["frida_payload"]
    assert "libnative.so" in payload["native_lib_hints"]
