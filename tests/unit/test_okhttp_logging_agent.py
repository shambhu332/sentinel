"""Unit tests for N_010 OkHttpLoggingAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import OkHttpLoggingAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, decompiled=True):
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


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(tmp_path, decompiled=False)
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- ungated Level.BODY → HIGH ----------


@pytest.mark.asyncio
async def test_ungated_body_is_high(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor;
class Net {
  HttpLoggingInterceptor build() {
    HttpLoggingInterceptor i = new HttpLoggingInterceptor();
    i.setLevel(HttpLoggingInterceptor.Level.BODY);
    return i;
  }
}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_010"
    assert f.severity == Severity.HIGH
    assert f.evidence["level_body"] is True
    assert f.evidence["guard_detected"] is False


# ---------- ungated Level.HEADERS → MEDIUM ----------


@pytest.mark.asyncio
async def test_ungated_headers_is_medium(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor;
class Net {
  HttpLoggingInterceptor build() {
    HttpLoggingInterceptor i = new HttpLoggingInterceptor();
    i.setLevel(HttpLoggingInterceptor.Level.HEADERS);
    return i;
  }
}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["level_headers"] is True


# ---------- BuildConfig.DEBUG guard demotes to INFO ----------


@pytest.mark.asyncio
async def test_guarded_body_is_info(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor;
import com.x.BuildConfig;
class Net {
  HttpLoggingInterceptor build() {
    HttpLoggingInterceptor i = new HttpLoggingInterceptor();
    if (BuildConfig.DEBUG) {
      i.setLevel(HttpLoggingInterceptor.Level.BODY);
    }
    return i;
  }
}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].evidence["guard_detected"] is True


# ---------- BASIC / NONE not flagged ----------


@pytest.mark.asyncio
async def test_basic_level_not_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor;
class Net {
  HttpLoggingInterceptor build() {
    HttpLoggingInterceptor i = new HttpLoggingInterceptor();
    i.setLevel(HttpLoggingInterceptor.Level.BASIC);
    return i;
  }
}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- short-form Level.BODY (static import style) ----------


@pytest.mark.asyncio
async def test_short_form_level_body_matches(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor.Level;
import okhttp3.logging.HttpLoggingInterceptor;
class Net {
  HttpLoggingInterceptor build() {
    HttpLoggingInterceptor i = new HttpLoggingInterceptor();
    i.setLevel(Level.BODY);
    return i;
  }
}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


# ---------- finding schema ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Net", """
import okhttp3.logging.HttpLoggingInterceptor;
class Net { void w() {
  HttpLoggingInterceptor i = new HttpLoggingInterceptor();
  i.setLevel(HttpLoggingInterceptor.Level.BODY);
}}
""")
    agent = OkHttpLoggingAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M9: Insecure Data Storage"
    assert f.masvs == "MSTG-STORAGE-3"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
