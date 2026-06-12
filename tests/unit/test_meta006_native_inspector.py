"""Unit tests for META_006 Native Library Inspector."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.agents.meta.meta006_native_inspector import NativeInspectorAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.native_analyzer import ElfAnalysis, NativeAnalysisResult
from sentinel.tools.result import ToolResult


def _make_fake_apk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return path


def _make_ctx(tmp_path: Path, with_lib: bool = True) -> ScanContext:
    apk = _make_fake_apk(tmp_path / "test.apk")
    resources = tmp_path / "resources"
    resources.mkdir()
    if with_lib:
        (resources / "lib" / "arm64-v8a").mkdir(parents=True)
        (resources / "lib" / "arm64-v8a" / "libnative.so").write_bytes(b"\x7fELF")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.resources_dir = resources
    return ctx


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


@pytest.mark.asyncio
async def test_not_applicable_when_no_lib_dir(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=False)
    agent = NativeInspectorAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_when_lib_dir_present(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=True)
    agent = NativeInspectorAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


@pytest.mark.asyncio
async def test_tamper_strings_emit_dynamic_target(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=True)
    agent = NativeInspectorAgent(context=ctx, memory=memory)

    fake = NativeAnalysisResult(
        total_libs=1, analyzed_libs=1, architectures=["EM_AARCH64"],
        analyses=[ElfAnalysis(
            path="arm64-v8a/libnative.so",
            arch="EM_AARCH64",
            tamper_detection_strings=["frida-server", "/system/xbin/su"],
        )],
    )
    with patch(
        "sentinel.agents.meta.meta006_native_inspector.NativeAnalyzer.analyze_directory",
        new=AsyncMock(return_value=ToolResult.ok(fake)),
    ):
        findings = await agent.analyze()

    assert any(
        "Dynamic Testing Target" in f.vuln_class
        and f.evidence.get("dynamic_target") is True
        for f in findings
    )


@pytest.mark.asyncio
async def test_security_symbols_categorized(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=True)
    agent = NativeInspectorAgent(context=ctx, memory=memory)

    fake = NativeAnalysisResult(
        total_libs=1, analyzed_libs=1,
        analyses=[ElfAnalysis(
            path="arm64-v8a/libnative.so",
            security_symbols={
                "ssl_tls": ["SSL_CTX_set_verify"],
                "anti_debug": ["ptrace"],
            },
        )],
    )
    with patch(
        "sentinel.agents.meta.meta006_native_inspector.NativeAnalyzer.analyze_directory",
        new=AsyncMock(return_value=ToolResult.ok(fake)),
    ):
        findings = await agent.analyze()

    classes = {f.vuln_class for f in findings}
    assert "TLS API Surface in Native Library" in classes
    assert "Anti-Debug Symbols in Native Library" in classes


@pytest.mark.asyncio
async def test_high_entropy_strings_severity_bucketing(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=True)
    agent = NativeInspectorAgent(context=ctx, memory=memory)

    fake = NativeAnalysisResult(
        total_libs=1, analyzed_libs=1,
        analyses=[ElfAnalysis(
            path="arm64-v8a/libnative.so",
            high_entropy_strings=[
                {"value": "abcd***wxyz", "length": 40, "entropy": 4.8, "offset": 0},
                {"value": "abcd***wxyz", "length": 40, "entropy": 4.2, "offset": 1},
                {"value": "abcd***wxyz", "length": 40, "entropy": 3.5, "offset": 2},
            ],
        )],
    )
    with patch(
        "sentinel.agents.meta.meta006_native_inspector.NativeAnalyzer.analyze_directory",
        new=AsyncMock(return_value=ToolResult.ok(fake)),
    ):
        findings = await agent.analyze()

    sev = [f.severity for f in findings if "High-Entropy" in f.vuln_class]
    # 4.8 → MEDIUM, 4.2 → LOW, 3.5 → dropped
    assert Severity.MEDIUM in sev
    assert Severity.LOW in sev
    assert len(sev) == 2


@pytest.mark.asyncio
async def test_empty_result_no_findings(tmp_path, memory):
    ctx = _make_ctx(tmp_path, with_lib=True)
    agent = NativeInspectorAgent(context=ctx, memory=memory)
    with patch(
        "sentinel.agents.meta.meta006_native_inspector.NativeAnalyzer.analyze_directory",
        new=AsyncMock(return_value=ToolResult.ok(NativeAnalysisResult())),
    ):
        findings = await agent.analyze()
    assert findings == []
