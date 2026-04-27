"""Unit tests for P_004 Content Provider IDOR Agent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import ContentProviderIDORAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def context_with_provider(tmp_path):
    """ScanContext set up with a fake decompiled provider."""
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    return ctx


def _plant_provider(decompiled_dir, fqcn, contents):
    """Helper: create a fake decompiled Java file at the canonical path for a provider class."""
    parts = fqcn.split(".")
    java_file = decompiled_dir.joinpath(*parts).with_suffix(".java")
    java_file.parent.mkdir(parents=True, exist_ok=True)
    java_file.write_text(contents)
    return java_file


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_without_manifest(memory, tmp_path):
    """Skips when Phase 1 didn't produce a manifest."""
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    agent = ContentProviderIDORAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled_dir(memory, tmp_path):
    """Skips when JADX didn't run."""
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    ctx.manifest = {"package": "com.x", "exported_components": []}
    agent = ContentProviderIDORAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_when_phase1_complete(memory, context_with_provider):
    """Runs when both manifest and decompiled dir are present."""
    context_with_provider.manifest = {"package": "com.x", "exported_components": []}
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    assert await agent.is_applicable() is True


# ---------- analyze: no providers ----------

@pytest.mark.asyncio
async def test_no_findings_when_no_exported_providers(memory, context_with_provider):
    """No exported providers → no findings."""
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "activity", "name": "com.x.MainActivity"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- analyze: provider source unavailable ----------

@pytest.mark.asyncio
async def test_unguarded_provider_no_source_emits_medium(memory, context_with_provider):
    """Provider exported with no permission, source missing → Medium finding."""
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "provider", "name": "com.x.LibraryProvider"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.agent_id == "P_004"
    assert f.evidence["provider"] == "com.x.LibraryProvider"
    assert f.evidence.get("source_file") is None


# ---------- analyze: clean source, no risks ----------

@pytest.mark.asyncio
async def test_unguarded_provider_clean_source_emits_medium(memory, context_with_provider):
    """Provider exported with no permission, source clean → Medium (exposure-only)."""
    _plant_provider(
        context_with_provider.decompiled_dir,
        "com.x.GoodProvider",
        """
package com.x;
import android.content.ContentProvider;
public class GoodProvider extends ContentProvider {
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return db.query("table", projection, selection, selectionArgs, null, null, sortOrder);
    }
}
""",
    )
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "provider", "name": "com.x.GoodProvider"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.evidence["sqli_indicators_found"] == 0


# ---------- analyze: SQLi pattern ----------

@pytest.mark.asyncio
async def test_unguarded_provider_with_sqli_emits_critical(memory, context_with_provider):
    """Exported + no permission + SQL injection pattern → Critical."""
    _plant_provider(
        context_with_provider.decompiled_dir,
        "com.x.BadProvider",
        """
package com.x;
import android.content.ContentProvider;
public class BadProvider extends ContentProvider {
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        return db.rawQuery("SELECT * FROM users WHERE " + selection, null);
    }
}
""",
    )
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "provider", "name": "com.x.BadProvider"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.evidence["sqli_indicators_found"] >= 1


# ---------- analyze: permission-guarded provider ----------

@pytest.mark.asyncio
async def test_permission_guarded_provider_emits_low(memory, context_with_provider):
    """Permission-guarded provider with clean source → Low (informational)."""
    _plant_provider(
        context_with_provider.decompiled_dir,
        "com.x.GuardedProvider",
        """
package com.x;
import android.content.ContentProvider;
public class GuardedProvider extends ContentProvider {
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        return db.query("t", projection, selection, args, null, null, sort);
    }
}
""",
    )
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {
                "type": "provider",
                "name": "com.x.GuardedProvider",
                "permission": "com.x.permission.READ_DATA",
            },
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert f.evidence["has_any_guard"] is True


# ---------- analyze: multiple providers in one APK ----------

@pytest.mark.asyncio
async def test_multiple_providers_each_get_finding(memory, context_with_provider):
    """One finding per exported provider."""
    _plant_provider(
        context_with_provider.decompiled_dir, "com.x.A", "class A { }"
    )
    _plant_provider(
        context_with_provider.decompiled_dir, "com.x.B", "class B { }"
    )
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "provider", "name": "com.x.A"},
            {"type": "provider", "name": "com.x.B"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    provider_names = {f.evidence["provider"] for f in findings}
    assert provider_names == {"com.x.A", "com.x.B"}


# ---------- analyze: only providers, not other components ----------

@pytest.mark.asyncio
async def test_ignores_exported_activities_and_receivers(memory, context_with_provider):
    """P_004 only cares about providers, not activities/receivers/services."""
    context_with_provider.manifest = {
        "package": "com.x",
        "exported_components": [
            {"type": "activity", "name": "com.x.MainActivity"},
            {"type": "receiver", "name": "com.x.BootReceiver"},
            {"type": "service", "name": "com.x.SyncService"},
        ],
    }
    agent = ContentProviderIDORAgent(context=context_with_provider, memory=memory)
    findings = await agent.analyze()
    assert findings == []
