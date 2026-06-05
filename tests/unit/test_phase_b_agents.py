"""Unit tests for Phase B additions: NL_001, IPC_001, RES_001, META_001
framework detection, and the dedup post-processor.

Each agent test follows the existing convention: synth a ScanContext
with the minimum scaffolding the agent needs, drop a few fixture files,
call analyze(), assert the finding shape.
"""
from __future__ import annotations

import pytest

from sentinel.agents.meta import ObfuscationDetectorAgent
from sentinel.agents.native import NativeLibraryAgent
from sentinel.agents.platform import IpcExposureAgent
from sentinel.agents.resilience import AntiTamperAgent
from sentinel.core.dedup import dedupe
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

# ---------- Shared fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def basic_context(tmp_path):
    """ScanContext with manifest + decompiled dir + resources dir."""
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)
    resources = ws / "resources"
    resources.mkdir(parents=True)

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.resources_dir = resources
    ctx.manifest = {
        "package": "com.example.test",
        "exported_components": [],
    }
    return ctx


# ---------- NL_001 NativeLibraryAgent ----------

@pytest.mark.asyncio
async def test_nl001_no_lib_dir_skips(memory, basic_context):
    """No resources/lib/ directory → is_applicable returns False."""
    agent = NativeLibraryAgent(context=basic_context, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_nl001_extracts_urls_and_flags_framework(memory, basic_context):
    """A planted lib with a backend URL + Flutter marker → 2 findings."""
    libdir = basic_context.resources_dir / "lib" / "arm64-v8a"
    libdir.mkdir(parents=True)
    # Build a fake .so containing a URL and Flutter markers.
    blob = (
        b"\x7fELF" + b"\x00" * 32
        + b"FlutterEngine_initialize\x00"
        + b"flutter_assets\x00"
        + b"https://api.example.com/v2/users\x00"
        + b"libapp.so\x00"
    )
    (libdir / "libapp.so").write_bytes(blob)

    agent = NativeLibraryAgent(context=basic_context, memory=memory)
    assert await agent.is_applicable() is True
    findings = await agent.analyze()

    vuln_classes = {f.vuln_class for f in findings}
    assert "Hardcoded URLs in Native Library" in vuln_classes
    assert "Application Framework Detected" in vuln_classes


@pytest.mark.asyncio
async def test_nl001_detects_aws_key(memory, basic_context):
    """A planted AWS access key in a .so → Critical finding."""
    libdir = basic_context.resources_dir / "lib" / "arm64-v8a"
    libdir.mkdir(parents=True)
    blob = b"\x7fELF" + b"\x00" * 32 + b"\x00AKIAIOSFODNN7EXAMPLE\x00"
    (libdir / "libfoo.so").write_bytes(blob)

    agent = NativeLibraryAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    aws = [f for f in findings if "AWS" in f.vuln_class]
    assert len(aws) == 1
    assert aws[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_nl001_detects_anti_tamper_signals(memory, basic_context):
    """A .so with anti-Frida + Magisk strings → anti-tamper INFO finding."""
    libdir = basic_context.resources_dir / "lib" / "arm64-v8a"
    libdir.mkdir(parents=True)
    blob = (
        b"\x7fELF" + b"\x00" * 32
        + b"frida-server\x00"
        + b"/sbin/.magisk\x00"
        + b"TracerPid\x00"
    )
    (libdir / "libnative.so").write_bytes(blob)

    agent = NativeLibraryAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    at = [f for f in findings
          if "Anti-Tamper" in f.vuln_class
          or "Anti-Debug" in f.vuln_class]
    assert len(at) == 1
    assert at[0].severity == Severity.INFO
    assert "signals" in at[0].evidence


# ---------- IPC_001 IpcExposureAgent ----------

@pytest.mark.asyncio
async def test_ipc001_no_exported_components_skips(memory, basic_context):
    """Empty exported_components → is_applicable False."""
    basic_context.manifest["exported_components"] = []
    agent = IpcExposureAgent(context=basic_context, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_ipc001_flags_exported_service_without_permission(
    memory, basic_context,
):
    """Service exported with intent filter and no permission → HIGH."""
    basic_context.manifest["exported_components"] = [
        {
            "type": "service",
            "name": "com.example.test.PayService",
            "explicitly_exported": True,
            "has_intent_filter": True,
            "permission": "",
        },
    ]
    agent = IpcExposureAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    # Service base = HIGH; name "Pay" matches dangerous hints → bumps to CRITICAL
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert findings[0].evidence["component_type"] == "service"
    assert findings[0].evidence["has_permission_guard"] is False


@pytest.mark.asyncio
async def test_ipc001_demotes_when_no_intent_filter(memory, basic_context):
    """No intent-filter → severity demoted one tier."""
    basic_context.manifest["exported_components"] = [
        {
            "type": "activity",
            "name": "com.example.test.RandomActivity",
            "explicitly_exported": True,
            "has_intent_filter": False,
            "permission": "",
        },
    ]
    agent = IpcExposureAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    # Activity base MEDIUM demoted to LOW
    assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_ipc001_low_when_permission_present(memory, basic_context):
    """Permission attribute present → LOW (situational awareness)."""
    basic_context.manifest["exported_components"] = [
        {
            "type": "receiver",
            "name": "com.example.test.UpdateReceiver",
            "explicitly_exported": True,
            "has_intent_filter": True,
            "permission": "com.example.test.permission.UPDATE",
        },
    ]
    agent = IpcExposureAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].evidence["has_permission_guard"] is True


# ---------- RES_001 AntiTamperAgent ----------

@pytest.mark.asyncio
async def test_res001_emits_none_tier_when_no_signals(memory, basic_context):
    """Empty Java tree → INFO finding, tier=None."""
    agent = AntiTamperAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].evidence["tier"] == "None"


@pytest.mark.asyncio
async def test_res001_strong_tier_with_attestation(memory, basic_context):
    """Play Integrity reference present → Strong tier."""
    java = basic_context.decompiled_dir / "AntiTamper.java"
    java.write_text("""
        package com.example.test;
        import com.google.android.play.core.integrity.IntegrityManager;
        public class AntiTamper {
            void check() {
                IntegrityManager mgr = new IntegrityManager();
                mgr.requestIntegrityToken();
            }
        }
    """)
    agent = AntiTamperAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["tier"].startswith("Strong")
    assert "Integrity attestation" in findings[0].evidence["categories_present"]


@pytest.mark.asyncio
async def test_res001_moderate_tier_multi_category(memory, basic_context):
    """3 distinct categories without attestation → Moderate tier."""
    (basic_context.decompiled_dir / "Root.java").write_text(
        "import com.scottyab.rootbeer.RootBeer;",
    )
    (basic_context.decompiled_dir / "Debug.java").write_text(
        "Debug.isDebuggerConnected();",
    )
    (basic_context.decompiled_dir / "Emu.java").write_text(
        "String fp = Build.FINGERPRINT;",
    )
    agent = AntiTamperAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings[0].evidence["tier"].startswith("Moderate")


# ---------- META_001 framework detection ----------

@pytest.mark.asyncio
async def test_meta001_detects_flutter_from_java_path(memory, basic_context):
    """io/flutter/ paths under decompiled_dir → framework finding emitted."""
    flutter_dir = basic_context.decompiled_dir / "io" / "flutter" / "embedding"
    flutter_dir.mkdir(parents=True)
    (flutter_dir / "FlutterFragment.java").write_text("class FlutterFragment {}")

    agent = ObfuscationDetectorAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()

    fw_findings = [
        f for f in findings if f.vuln_class == "Application Framework Detected"
    ]
    assert len(fw_findings) == 1
    assert "Flutter" in fw_findings[0].evidence["frameworks"]


# ---------- Dedup ----------

def _mk(vuln_class: str, severity: Severity, file_path: str,
        agent_id: str = "C_007", confidence: float = 0.75) -> Finding:
    return Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=confidence,
        evidence={"file": file_path, "package": "com.example.test"},
        recommendation="x",
        session_id="testsession12345",
    )


def test_dedup_collapses_weak_crypto_duplicates():
    """SG_001 weak-crypto + C_007 weak-crypto on same file → 1 finding."""
    findings = [
        _mk("Weak Cryptography", Severity.MEDIUM,
            "com/example/Foo.java", "C_007", 0.80),
        _mk("Broken Crypto Primitive", Severity.HIGH,
            "com/example/Foo.java", "SG_001", 0.90),
    ]
    result = dedupe(findings)
    assert len(result) == 1
    # Higher severity wins
    assert result[0].severity == Severity.HIGH
    assert result[0].agent_id == "SG_001"
    assert "_deduped_from" in result[0].evidence


def test_dedup_keeps_different_files_apart():
    """Same vuln_class, different files → both survive."""
    findings = [
        _mk("Weak Cryptography", Severity.MEDIUM, "a/A.java"),
        _mk("Weak Cryptography", Severity.MEDIUM, "b/B.java"),
    ]
    result = dedupe(findings)
    assert len(result) == 2


def test_dedup_keeps_unrelated_classes_apart():
    """Different canonical categories never collapse."""
    findings = [
        _mk("Weak Cryptography", Severity.MEDIUM,
            "shared/Foo.java", "C_007"),
        _mk("Insecure WebView", Severity.HIGH,
            "shared/Foo.java", "C_004"),
    ]
    result = dedupe(findings)
    assert len(result) == 2
