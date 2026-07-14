"""Unit tests for STG_007 InsecureFileProviderAgent."""
from __future__ import annotations

import asyncio

import pytest

from sentinel.agents.shared_prefs import InsecureFileProviderAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, manifest=None, resources=True):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if resources:
        res = ws / "resources"
        (res / "res" / "xml").mkdir(parents=True, exist_ok=True)
        ctx.resources_dir = res
    if manifest is not None:
        ctx.manifest = manifest
    return ctx


def _plant_xml(ctx: ScanContext, name: str, content: str) -> None:
    f = ctx.resources_dir / "res" / "xml" / name
    f.write_text(content)


def _file_provider_entry(*, exported: bool = True, perm: str = "") -> dict:
    return {
        "type": "provider",
        "name": "androidx.core.content.FileProvider",
        "explicitly_exported": exported,
        "has_intent_filter": False,
        "permission": perm,
    }


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_with_no_resources_and_no_manifest(memory, tmp_path):
    ctx = _make_ctx(tmp_path, resources=False)
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- root-path always flagged ----------


@pytest.mark.asyncio
async def test_root_path_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "file_paths.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <root-path name="root" path="." />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].agent_id == "STG_007"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["tag"] == "root-path"


# ---------- wildcard external-path ----------


@pytest.mark.asyncio
async def test_wildcard_external_path_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <external-path name="all_ext" path="" />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "external-path" in findings[0].evidence["tag"]


# ---------- wildcard files-path ----------


@pytest.mark.asyncio
async def test_wildcard_files_path_is_medium(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <files-path name="all_files" path="/" />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_path_mapping_proof_is_static_not_fake_content_read(tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [],
        },
    )
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <cache-path name="all_cache" path="." />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=object())  # type: ignore[arg-type]
    [finding] = asyncio.run(agent.analyze())

    assert finding.verification_status == "Code-level only"
    assert finding.reproduction_commands
    assert any("apktool d target.apk" in c for c in finding.reproduction_commands)
    assert any("getUriForFile" in c for c in finding.reproduction_commands)
    assert not any("content://" in c for c in finding.reproduction_commands)
    assert finding.observed_result
    assert finding.observed_result.startswith("Static proof only")
    assert "not dynamically verified" in finding.observed_result
    assert "image_cache/secret.bin" not in finding.observed_result
    assert "can read any file reachable" not in finding.observed_result


# ---------- narrow path is safe ----------


@pytest.mark.asyncio
async def test_narrow_files_path_not_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <files-path name="shared" path="shared/" />
  <cache-path name="downloads" path="downloads/" />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_non_paths_xml_ignored(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "preferences.xml", """<?xml version="1.0" encoding="utf-8"?>
<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">
  <CheckBoxPreference android:key="foo" />
</PreferenceScreen>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- exported FileProvider in manifest ----------


@pytest.mark.asyncio
async def test_exported_file_provider_is_critical(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_file_provider_entry()],
        },
    )
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].vuln_class == "Exported FileProvider"


@pytest.mark.asyncio
async def test_exported_non_file_provider_ignored(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [
                {"type": "provider", "name": "com.x.MyContentProvider",
                 "explicitly_exported": True, "has_intent_filter": False,
                 "permission": ""},
            ],
        },
    )
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- combined ----------


@pytest.mark.asyncio
async def test_combined_emits_independently(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_file_provider_entry()],
        },
    )
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <root-path name="root" path="." />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    severities = sorted(f.severity for f in findings)
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities


# ---------- finding schema ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant_xml(ctx, "fp.xml", """<?xml version="1.0" encoding="utf-8"?>
<paths>
  <root-path name="r" path="." />
</paths>
""")
    agent = InsecureFileProviderAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.masvs and f.masvs.startswith("MSTG-")
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
