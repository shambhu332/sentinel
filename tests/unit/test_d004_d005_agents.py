"""Unit tests for the Sprint 8.4 dynamic agents.

* D_004 AntiTamperCoverageAgent
* D_005 DynamicCodeLoadingAgent
"""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    AntiTamperCoverageAgent,
    DynamicCodeLoadingAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events),
        duration_seconds=10.0,
        target_package="com.example.app",
        target_pid=12345,
    )


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
def banking_ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    c.manifest = {"package": "com.acme.banking"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


# ---------- D_004 ----------


@pytest.mark.asyncio
async def test_d004_no_capture_skips(ctx, memory):
    agent = AntiTamperCoverageAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d004_full_coverage_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tamper.root_check",       api="File.exists", value="/system/bin/su"),
        _ev("tamper.emulator_check",   api="Build.getRadioVersion", value=""),
        _ev("tamper.integrity_check",  api="PackageManager.getPackageInfo"),
        _ev("tamper.debugger_check",   api="Debug.isDebuggerConnected"),
    )
    findings = await AntiTamperCoverageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d004_zero_coverage_on_banking_app_is_medium(banking_ctx, memory):
    banking_ctx.sources["frida"] = _capture()
    # Need an event for is_applicable to pass; emit one unrelated event.
    banking_ctx.sources["frida"] = _capture(
        _ev("crypto.cipher", algorithm="AES"),
    )
    findings = await AntiTamperCoverageAgent(
        context=banking_ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["covered_categories"] == []


@pytest.mark.asyncio
async def test_d004_zero_coverage_on_generic_app_is_low(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.cipher", algorithm="AES"),
    )
    findings = await AntiTamperCoverageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_d004_partial_coverage_is_low(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("tamper.root_check",     api="File.exists"),
        _ev("tamper.emulator_check", api="SystemProperties.get"),
    )
    findings = await AntiTamperCoverageAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert "integrity" in f.evidence["missing_categories"]
    assert "debugger" in f.evidence["missing_categories"]


# ---------- D_005 ----------


@pytest.mark.asyncio
async def test_d005_no_capture_skips(ctx, memory):
    agent = DynamicCodeLoadingAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d005_external_storage_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.dex_load",
            loader_class="dalvik.system.DexClassLoader",
            path="/sdcard/Download/payload.dex"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d005_network_origin_to_cache_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.dex_load",
            loader_class="dalvik.system.DexClassLoader",
            path="/data/data/com.example.app/cache/dlmodule.dex",
            stack="okhttp3.OkHttpClient.newCall <- com.example.app.Downloader.run"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d005_native_load_from_tmp_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.native_load",
            loader_class="java.lang.System.load",
            path="/data/local/tmp/libdrop.so"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_d005_apk_internal_load_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.dex_load",
            loader_class="dalvik.system.PathClassLoader",
            path="/data/app/com.example.app/base.apk"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d005_unknown_path_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.dex_load",
            loader_class="dalvik.system.DexClassLoader",
            path="/opt/oem/preinstalled-feature.jar"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d005_runtime_exec_external_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("code_loading.exec",
            loader_class="java.lang.Runtime.exec",
            path="/sdcard/Download/run.sh"),
    )
    findings = await DynamicCodeLoadingAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
