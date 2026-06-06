"""Unit tests for STG_011 SqliteWalLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.shared_prefs import SqliteWalLeakAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, decompiled=True, allow_backup=False):
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
    if decompiled:
        d = ws / "decompiled"
        d.mkdir(exist_ok=True)
        ctx.decompiled_dir = d
    ctx.manifest = {"package": "com.x", "allow_backup": allow_backup}
    return ctx


def _plant(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False)
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_credential_table_without_pragma_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.TokenDb", """
import android.database.sqlite.SQLiteDatabase;
class TokenDb {
  void store(SQLiteDatabase db, String token) {
    db.execSQL("INSERT INTO auth_tokens (jwt) VALUES (?)", new String[]{token});
  }
  SQLiteDatabase open() {
    return SQLiteDatabase.openOrCreateDatabase("/tmp/x.db", null);
  }
}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "STG_011"
    assert f.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_credential_table_with_backup_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path, allow_backup=True)
    _plant(ctx.decompiled_dir, "com.x.TokenDb", """
import android.database.sqlite.SQLiteDatabase;
class TokenDb {
  SQLiteDatabase open() {
    return SQLiteDatabase.openOrCreateDatabase("/tmp/x.db", null);
  }
  void store(SQLiteDatabase db, String token) {
    db.insert("session_table", null, null);
  }
}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_secure_delete_pragma_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path, allow_backup=True)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import android.database.sqlite.SQLiteDatabase;
class Good {
  SQLiteDatabase open() {
    SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase("/tmp/x.db", null);
    db.execSQL("PRAGMA secure_delete = ON");
    db.execSQL("INSERT INTO tokens VALUES (?)", new String[]{"x"});
    return db;
  }
}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_credential_table_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Notes", """
import android.database.sqlite.SQLiteDatabase;
class Notes {
  void save(SQLiteDatabase db, String body) {
    db.execSQL("INSERT INTO notes (body) VALUES (?)", new String[]{body});
  }
  SQLiteDatabase open() {
    return SQLiteDatabase.openOrCreateDatabase("/tmp/notes.db", null);
  }
}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_room_database_with_credential_table_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path, allow_backup=True)
    _plant(ctx.decompiled_dir, "com.x.AppDb", """
import androidx.room.Room;
class AppDb {
  void wire(android.content.Context ctx) {
    Room.databaseBuilder(ctx, AppDatabase.class, "user_credentials.db").build();
  }
  void purge(android.database.sqlite.SQLiteDatabase db) {
    db.execSQL("DELETE FROM auth_session WHERE expired = 1");
  }
}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path, allow_backup=True)
    _plant(ctx.decompiled_dir, "com.x.S", """
import android.database.sqlite.SQLiteDatabase;
class S { void w(SQLiteDatabase db) {
  SQLiteDatabase.openOrCreateDatabase("/tmp/x.db", null);
  db.execSQL("INSERT INTO tokens VALUES (?)", new String[]{"x"});
}}
""")
    agent = SqliteWalLeakAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M9: Insecure Data Storage"
    assert f.masvs == "MSTG-STORAGE-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
    assert "secure_delete" in f.recommendation
