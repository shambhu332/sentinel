"""Unit tests for EXP_002 Deep Link / Intent PoC agent."""
from __future__ import annotations

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.exploit.exp_002_deep_link import EXP002DeepLinkAgent
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
    ws.mkdir()
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(in_scope_packages=["com.example.app"]),
    )


def _finding(agent_id="P_001", **ev_extra) -> Finding:
    ev = {"scheme": "https", "host": "example.com", "path": "/pay",
          "target_package": "com.example.app", **ev_extra}
    return Finding(
        agent_id=agent_id, session_id=generate_session_id(),
        vuln_class="Exported Deep Link Handler", severity=Severity.HIGH,
        confidence=0.85, evidence=ev, recommendation="Add permission.",
        compliance_tags=["CWE-940"],
    )


def _agent(ctx, memory, finding=None, dry_run=True):
    return EXP002DeepLinkAgent(context=ctx, memory=memory, finding=finding, dry_run=dry_run)


class TestCanExploit:
    def test_true_for_p001(self, ctx, memory):
        assert _agent(ctx, memory).can_exploit(_finding("P_001"))

    def test_true_for_wv001(self, ctx, memory):
        assert _agent(ctx, memory).can_exploit(_finding("WV_001"))

    def test_true_for_deep_link_vuln_class(self, ctx, memory):
        f = Finding(agent_id="X_001", session_id=generate_session_id(),
                    vuln_class="deep link hijack", severity=Severity.HIGH,
                    confidence=0.8, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert _agent(ctx, memory).can_exploit(f)

    def test_false_for_crypto_agent(self, ctx, memory):
        f = Finding(agent_id="C_001", session_id=generate_session_id(),
                    vuln_class="ECB mode", severity=Severity.HIGH,
                    confidence=0.9, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert not _agent(ctx, memory).can_exploit(f)


class TestGeneratePocAdb:
    @pytest.mark.asyncio
    async def test_creates_shell_script(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.absolute_path.suffix == ".sh"

    @pytest.mark.asyncio
    async def test_watermark_in_script(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "AUTHORIZED SECURITY TESTING ONLY" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_adb_command_present(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "adb shell am start" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_deep_link_in_script(self, ctx, memory):
        f = _finding(scheme="myapp", host="launch")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "myapp://launch" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_package_in_script(self, ctx, memory):
        f = _finding(target_package="com.victim.app")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "com.victim.app" in artifact.absolute_path.read_text()


class TestGeneratePocHtml:
    @pytest.mark.asyncio
    async def test_html_when_js_bridge_exposed(self, ctx, memory):
        f = _finding(js_bridge_exposed=True, js_bridge_name="NativeBridge")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.absolute_path.suffix == ".html"

    @pytest.mark.asyncio
    async def test_bridge_name_in_html(self, ctx, memory):
        f = _finding(js_bridge_exposed=True, js_bridge_name="MyBridge")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "MyBridge" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_watermark_in_html(self, ctx, memory):
        f = _finding(js_bridge_exposed=True)
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "AUTHORIZED" in artifact.absolute_path.read_text()


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_empty_without_finding(self, ctx, memory):
        assert await _agent(ctx, memory).analyze() == []

    @pytest.mark.asyncio
    async def test_returns_finding_with_poc(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f).analyze()
        assert len(results) == 1
        assert results[0].poc_artifacts

    @pytest.mark.asyncio
    async def test_exploitation_status_code_only(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f).analyze()
        assert results[0].exploitation_status == "Code_Only"
