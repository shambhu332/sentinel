"""Tests for D_063 ContentProvider SQLi + D_065 FileProvider fuzzer."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d063_provider_sqli import ProviderSqliAgent
from sentinel.agents.dynamic.d065_file_provider_fuzzer import (
    FileProviderFuzzerAgent,
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
# D_063 ContentProvider SQLi
# ============================================================

@pytest.mark.asyncio
async def test_d063_flags_exported_provider_with_raw_sql(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "MyProvider.java").write_text(
        "public class MyProvider extends ContentProvider {\n"
        "  public Cursor query(Uri uri, String[] proj, String selection, "
        "String[] args, String sort) {\n"
        "    return db.rawQuery(\"SELECT * FROM users WHERE \" + selection, null);\n"
        "  }\n"
        "  static UriMatcher um = new UriMatcher(UriMatcher.NO_MATCH);\n"
        "  static {\n"
        "    um.addURI(\"com.x.provider\", \"users\", 1);\n"
        "    um.addURI(\"com.x.provider\", \"users/#\", 2);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "providers": [
            {"name": "com.x.MyProvider",
             "authority": "com.x.provider",
             "exported": True},
        ],
    }
    findings = await ProviderSqliAgent(context=ctx, memory=memory).analyze()
    assert any(
        f.evidence.get("authority") == "com.x.provider"
        and f.evidence.get("dynamic_target") is True
        and f.severity == Severity.HIGH
        for f in findings
    )
    payload = findings[0].evidence.get("frida_payload") or {}
    assert any("users" in u for u in payload.get("candidate_uris", []))
    assert "' OR 1=1--" in payload.get("probe_payloads", [])
    assert payload.get("safety_budget", {}).get("max_actions_total") == 50


@pytest.mark.asyncio
async def test_d063_skips_non_exported_provider(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "PrivateProvider.java").write_text(
        "public class PrivateProvider extends ContentProvider {\n"
        "  public Cursor query(Uri u, String[] p, String s, String[] a, String x) {\n"
        "    return db.rawQuery(\"SELECT * FROM x WHERE \" + s, null);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "providers": [
            {"name": "com.x.PrivateProvider",
             "authority": "com.x.private",
             "exported": False},
        ],
    }
    findings = await ProviderSqliAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d063_skips_parameter_bound_query(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Safe.java").write_text(
        "public class Safe extends ContentProvider {\n"
        "  public Cursor query(Uri u, String[] p, String s, String[] a, String x) {\n"
        "    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();\n"
        "    qb.setSelectionArgs(a);\n"
        "    return qb.rawQuery(\"SELECT * FROM x\", a);\n"
        "  }\n"
        "}\n"
    )
    ctx.manifest = {
        "providers": [
            {"name": "com.x.Safe",
             "authority": "com.x.safe",
             "exported": True},
        ],
    }
    findings = await ProviderSqliAgent(context=ctx, memory=memory).analyze()
    assert findings == []


# ============================================================
# D_065 FileProvider active fuzzer
# ============================================================

def _ctx_with_resources(tmp_path: Path) -> tuple[ScanContext, Path, Path]:
    apk = tmp_path / "t.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    decompiled = tmp_path / "decompiled"
    resources = tmp_path / "resources"
    decompiled.mkdir()
    (resources / "res" / "xml").mkdir(parents=True)
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.resources_dir = resources
    return ctx, decompiled, resources


@pytest.mark.asyncio
async def test_d065_emits_traversal_payload(tmp_path, memory):
    ctx, decompiled, resources = _ctx_with_resources(tmp_path)
    (decompiled / "Share.java").write_text(
        "import androidx.core.content.FileProvider;\n"
        "class Share {\n"
        "  Uri get(Context ctx, File f) {\n"
        "    return FileProvider.getUriForFile(ctx, \"com.x.fp\", f);\n"
        "  }\n"
        "}\n"
    )
    (resources / "res" / "xml" / "paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<paths>\n'
        '  <files-path name="shared" path="shared/" />\n'
        '  <external-files-path name="ext" path="" />\n'
        '</paths>\n'
    )
    ctx.manifest = {
        "providers": [
            {"name": "androidx.core.content.FileProvider",
             "authority": "com.x.fp",
             "exported": False},
        ],
    }
    findings = await FileProviderFuzzerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence.get("authority") == "com.x.fp"
    assert f.evidence.get("dynamic_target") is True
    payload = f.evidence.get("frida_payload") or {}
    assert len(payload.get("probe_paths", [])) >= 5
    assert any(".." in p for p in payload.get("probe_paths", []))
    # Declared roots parsed from xml
    assert len(payload.get("declared_roots", [])) == 2
    kinds = {r["kind"] for r in payload["declared_roots"]}
    assert "files-path" in kinds
    assert "external-files-path" in kinds


@pytest.mark.asyncio
async def test_d065_skips_when_no_fileprovider_in_java(tmp_path, memory):
    ctx, decompiled, resources = _ctx_with_resources(tmp_path)
    (decompiled / "Unrelated.java").write_text(
        "class Unrelated { void x() { log(\"hi\"); } }\n"
    )
    ctx.manifest = {
        "providers": [
            {"name": "androidx.core.content.FileProvider",
             "authority": "com.x.fp"},
        ],
    }
    findings = await FileProviderFuzzerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d065_skips_when_no_fileprovider_in_manifest(tmp_path, memory):
    ctx, decompiled, _ = _ctx_with_resources(tmp_path)
    (decompiled / "Share.java").write_text(
        "import androidx.core.content.FileProvider;\n"
        "class Share { void x() { FileProvider.getUriForFile(c, a, f); } }\n"
    )
    ctx.manifest = {"providers": []}
    findings = await FileProviderFuzzerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
