"""Unit tests for B_005 OAuthRedirectUriAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.business import OAuthRedirectUriAgent
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
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_oauth_path_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
class Plain {
  String build(String r) {
    return "https://api.example.com/me?redirect_uri=" + r;
  }
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_concat_with_intent_extra_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
class Auth {
  String build(Intent intent) {
    String returnUrl = intent.getStringExtra("return_url");
    return "https://idp.example.com/oauth/authorize?client_id=abc&"
        + "redirect_uri=" + returnUrl;
  }
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "B_005"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["taint_in_scope"] is True


@pytest.mark.asyncio
async def test_uri_builder_with_deep_link_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Auth", """
import android.content.Intent;
import android.net.Uri;
class Auth {
  Uri build(Intent intent) {
    String redirect = intent.getData().getQueryParameter("redirect");
    return new Uri.Builder()
        .scheme("https").authority("idp.example.com")
        .appendPath("oauth").appendPath("authorize")
        .appendQueryParameter("redirect_uri", redirect)
        .build();
  }
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["vector"] == "uri_builder"


@pytest.mark.asyncio
async def test_retrofit_query_without_taint_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.OAuthApi", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface OAuthApi {
  @GET("/oauth/authorize")
  Object authorize(@Query("client_id") String c, @Query("redirect_uri") String r);
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["taint_in_scope"] is False


@pytest.mark.asyncio
async def test_literal_safe_redirect_suppresses(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Safe", """
import android.net.Uri;
class Safe {
  Uri build() {
    String fixed = "com.x://oauth/cb";
    Uri u = Uri.parse("https://idp.example.com/oauth/authorize"
        + "?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb");
    return new Uri.Builder()
        .appendQueryParameter("redirect_uri", fixed).build();
  }
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    # The literal safe pattern in the same method suppresses the
    # uri_builder finding (no taint), so we expect zero.
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.OAuthApi", """
import retrofit2.http.GET;
import retrofit2.http.Query;
interface OAuthApi {
  @GET("/oauth/authorize")
  Object x(@Query("redirect_uri") String r);
}
""")
    agent = OAuthRedirectUriAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-AUTH-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
