"""Unit tests for Sprint 5 agents: N_002, A_004, C_002."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import HardcodedSecretsAgent
from sentinel.agents.data_storage import WorldReadableStorageAgent
from sentinel.agents.network import CleartextTrafficAgent
from sentinel.core.finding import BountyScope, Severity
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
        "uses_cleartext_traffic": False,
        "exported_components": [],
    }
    return ctx


# ---------- N_002 Cleartext Traffic ----------

@pytest.mark.asyncio
async def test_n002_no_findings_when_clean(memory, basic_context):
    """Clean app with HTTPS only and no manifest flag → no finding."""
    java = basic_context.decompiled_dir / "Api.java"
    java.write_text('private static final String BASE = "https://api.example.com";')

    agent = CleartextTrafficAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_n002_manifest_flag_only_emits_medium(memory, basic_context):
    """Manifest flag set, no http URLs in code → Medium."""
    basic_context.manifest["uses_cleartext_traffic"] = True

    agent = CleartextTrafficAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["manifest_uses_cleartext_traffic"] is True


@pytest.mark.asyncio
async def test_n002_http_urls_in_code_emit_finding(memory, basic_context):
    """Hardcoded http:// URLs → Low or Medium depending on count."""
    java = basic_context.decompiled_dir / "Net.java"
    java.write_text(
        'String url1 = "http://api.example.com/v1/users";\n'
        'String url2 = "http://api.example.com/v1/posts";\n'
    )

    agent = CleartextTrafficAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["http_urls_count"] == 2


@pytest.mark.asyncio
async def test_n002_combined_signals_emit_high(memory, basic_context):
    """Manifest flag AND http URLs → High."""
    basic_context.manifest["uses_cleartext_traffic"] = True
    java = basic_context.decompiled_dir / "Api.java"
    java.write_text('String x = "http://insecure.example.com/login";')

    agent = CleartextTrafficAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_n002_skips_xmlns_namespaces(memory, basic_context):
    """XML namespace URIs and localhost should NOT trigger a finding."""
    java = basic_context.decompiled_dir / "X.java"
    java.write_text(
        'String ns = "http://schemas.android.com/apk/res/android";\n'
        'String dev = "http://localhost:8080/api";\n'
        'String emu = "http://10.0.2.2:3000/test";\n'
    )

    agent = CleartextTrafficAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- A_004 Hardcoded Secrets ----------

@pytest.mark.asyncio
async def test_a004_no_findings_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Clean.java"
    java.write_text("public class Clean { void hello() { } }")

    agent = HardcodedSecretsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_a004_detects_aws_access_key(memory, basic_context):
    """AWS access key pattern should fire as Critical."""
    java = basic_context.decompiled_dir / "Aws.java"
    java.write_text(
        'private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
    )

    agent = HardcodedSecretsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "AWS" in f.evidence["provider"]


@pytest.mark.asyncio
async def test_a004_detects_google_api_key(memory, basic_context):
    java = basic_context.decompiled_dir / "Maps.java"
    java.write_text(
        'String mapsKey = "AIzaSyDxKL3jK7NHgL8a9XyzZ1234567890abcdEFG";\n'
    )

    agent = HardcodedSecretsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_a004_skips_test_fixtures(memory, basic_context):
    """Lines containing 'test', 'example', 'fake' should be filtered out."""
    java = basic_context.decompiled_dir / "TestKeys.java"
    java.write_text(
        '// example AWS key for testing\n'
        'String testKey = "AKIAIOSFODNN7EXAMPLE";\n'
    )

    agent = HardcodedSecretsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_a004_detects_pem_private_key(memory, basic_context):
    java = basic_context.decompiled_dir / "Crypto.java"
    java.write_text(
        'String pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIB..."\n'
    )

    agent = HardcodedSecretsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


# ---------- C_002 World-Readable Storage ----------

@pytest.mark.asyncio
async def test_c002_no_findings_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Clean.java"
    java.write_text(
        'SharedPreferences sp = getSharedPreferences("p", Context.MODE_PRIVATE);'
    )

    agent = WorldReadableStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_c002_detects_world_readable_constant(memory, basic_context):
    java = basic_context.decompiled_dir / "Storage.java"
    java.write_text(
        'SharedPreferences sp = getSharedPreferences("p", MODE_WORLD_READABLE);'
    )

    agent = WorldReadableStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.evidence["total_hits"] >= 1


@pytest.mark.asyncio
async def test_c002_detects_world_writeable_emits_high(memory, basic_context):
    java = basic_context.decompiled_dir / "Bad.java"
    java.write_text(
        'fos = openFileOutput("creds.txt", MODE_WORLD_WRITEABLE);'
    )

    agent = WorldReadableStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_c002_not_applicable_without_decompiled(memory, tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    agent = WorldReadableStorageAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False
