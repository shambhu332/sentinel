"""Unit tests for C_010 SQLCipherKeyDerivationAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import SQLCipherKeyDerivationAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, decompiled: bool = True):
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
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(tmp_path, decompiled=False)
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_sqlcipher_import_no_findings(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
import android.database.sqlite.SQLiteDatabase;
class Plain {
  void open() {
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", "hardcoded", null);
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_hardcoded_passphrase_is_critical(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bad", """
import net.sqlcipher.database.SQLiteDatabase;
class Bad {
  void open() {
    SQLiteDatabase.openOrCreateDatabase("/data/data/com.x/db.sqlite",
        "mypassword", null);
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "C_010"
    assert f.severity == Severity.CRITICAL
    assert "hardcoded" in f.evidence["reason"]


@pytest.mark.asyncio
async def test_buildconfig_passphrase_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bc", """
import net.sqlcipher.database.SQLiteDatabase;
class Bc {
  void open() {
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", BuildConfig.DB_KEY, null);
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "BuildConfig" in findings[0].evidence["reason"]


@pytest.mark.asyncio
async def test_static_final_string_constant_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Sf", """
import net.sqlcipher.database.SQLiteDatabase;
class Sf {
  private static final String DB_PASSPHRASE = "letmein";
  void open() {
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", DB_PASSPHRASE, null);
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "static final" in findings[0].evidence["reason"]


@pytest.mark.asyncio
async def test_pbkdf2_in_tail_suppresses_finding(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Good", """
import net.sqlcipher.database.SQLiteDatabase;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
class Good {
  void open(String user, byte[] salt) {
    char[] pw = user.toCharArray();
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", derive(pw, salt), null);
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
  }
  byte[] derive(char[] p, byte[] s) { return new byte[0]; }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_prefs_read_without_kdf_is_medium(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Prefs", """
import net.sqlcipher.database.SQLiteDatabase;
class Prefs {
  void open(android.content.SharedPreferences prefs) {
    String pw = prefs.getString("db_key", "");
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", pw, null);
    prefs.getString("misc", "");  // tail-window prefs hit
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bad", """
import net.sqlcipher.database.SQLiteDatabase;
class Bad {
  void open() {
    SQLiteDatabase.openOrCreateDatabase("/tmp/x", "pw", null);
  }
}
""")
    agent = SQLCipherKeyDerivationAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.vuln_class == "Insecure SQLCipher Key Derivation"
    assert f.owasp == "M10: Insufficient Cryptography"
    assert f.masvs == "MSTG-CRYPTO-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
