"""Unit tests for B_007 ClientSideAuthzAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.business import ClientSideAuthzAgent
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
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_is_admin_gate_calls_api_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Admin", """
class Admin {
  void deleteOther(User user, ApiService api) {
    if (user.isAdmin()) {
      api.deleteAccount("target");
    }
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "B_007"
    assert f.severity == Severity.HIGH
    assert f.evidence["predicate"] == "isAdmin"


@pytest.mark.asyncio
async def test_can_show_feature_flag_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Feat", """
class Feat {
  void wire(FeatureFlags flags, ApiService api) {
    if (flags.canShow()) {
      api.fetchExperimentData();
    }
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_gate_without_api_call_in_body_is_skipped(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.UI", """
class UI {
  void wire(User user) {
    if (user.isAdmin()) {
      // pure UI — show a button
      button.setVisibility(View.VISIBLE);
    }
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_predicate_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Plain", """
class Plain {
  void wire(ApiService api) {
    api.fetchProducts();
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_no_api_receiver_in_file_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.NoApi", """
class NoApi {
  boolean check(User user) {
    return user.isAdmin();
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_multiple_gates_one_per_method(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Multi", """
class Multi {
  void a(User user, ApiService api) {
    if (user.isAdmin()) { api.x(); }
  }
  void b(User user, ApiService api) {
    if (user.hasRole()) { api.y(); }
  }
}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.S", """
class S { void w(User user, ApiService api) {
  if (user.isAdmin()) { api.deleteAccount("t"); }
}}
""")
    agent = ClientSideAuthzAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Authentication / Authorization"
    assert f.masvs == "MSTG-ARCH-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
