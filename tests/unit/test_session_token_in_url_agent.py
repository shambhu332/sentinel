"""Unit tests for A_010 SessionTokenInUrlAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.auth import SessionTokenInUrlAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, decompiled=True):
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


def _plant(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False)
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_retrofit_access_token_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Api", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface Api {
  @GET("/users") Object users(@Query("access_token") String t);
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "A_010"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["vector"] == "retrofit_query"


@pytest.mark.asyncio
async def test_url_literal_session_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
class Net {
  String build() {
    return "https://api.example.com/me?sessionId=abc123&page=1";
  }
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["vector"] == "url_literal"


@pytest.mark.asyncio
async def test_uri_builder_token_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Bu", """
import android.net.Uri;
class Bu {
  Uri build(String t) {
    return new Uri.Builder()
        .scheme("https").authority("api.example.com")
        .appendQueryParameter("token", t).build();
  }
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["vector"] == "uri_builder"
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_api_key_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Ak", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface Ak {
  @GET("/weather") Object q(@Query("api_key") String k);
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_non_credential_query_param_not_flagged(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface Plain {
  @GET("/search") Object q(@Query("q") String query, @Query("page") int p);
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_duplicate_same_vector_collapses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Dup", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface Dup {
  @GET("/a") Object a(@Query("token") String t);
  @GET("/b") Object b(@Query("token") String t);
}
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # Same vector + same normalized key → single finding per file.
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
import retrofit2.http.Query;
interface S { Object x(@Query("token") String t); }
""")
    agent = SessionTokenInUrlAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Communication"
    assert f.masvs == "MSTG-AUTH-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
