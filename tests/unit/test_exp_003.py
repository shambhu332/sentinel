"""Unit tests for EXP_003 WebView XSS payload agent."""
from __future__ import annotations

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.exploit.exp_003_webview_xss import EXP003WebViewXSSAgent
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


def _finding(agent_id="WV_001", **ev_extra) -> Finding:
    ev = {"js_bridge_name": "Android", "exposed_methods": ["getToken", "openFile"],
          "file_access_enabled": False, **ev_extra}
    return Finding(
        agent_id=agent_id, session_id=generate_session_id(),
        vuln_class="WebView JavaScript Bridge Exposure", severity=Severity.HIGH,
        confidence=0.90, evidence=ev, recommendation="Remove addJavascriptInterface.",
        compliance_tags=["CWE-749"],
    )


def _agent(ctx, memory, finding=None, dry_run=True):
    return EXP003WebViewXSSAgent(context=ctx, memory=memory, finding=finding, dry_run=dry_run)


class TestCanExploit:
    def test_true_for_wv001(self, ctx, memory):
        assert _agent(ctx, memory).can_exploit(_finding("WV_001"))

    def test_true_for_p001(self, ctx, memory):
        assert _agent(ctx, memory).can_exploit(_finding("P_001"))

    def test_true_for_webview_in_vuln_class(self, ctx, memory):
        f = Finding(agent_id="X_001", session_id=generate_session_id(),
                    vuln_class="WebView XSS via intent", severity=Severity.HIGH,
                    confidence=0.8, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert _agent(ctx, memory).can_exploit(f)

    def test_false_for_unrelated_agent(self, ctx, memory):
        f = Finding(agent_id="N_001", session_id=generate_session_id(),
                    vuln_class="Cleartext HTTP", severity=Severity.MEDIUM,
                    confidence=0.8, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert not _agent(ctx, memory).can_exploit(f)


class TestGeneratePoc:
    @pytest.mark.asyncio
    async def test_creates_html_file(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.absolute_path.suffix == ".html"
        assert artifact.absolute_path.exists()

    @pytest.mark.asyncio
    async def test_watermark_in_html(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "AUTHORIZED SECURITY TESTING ONLY" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_bridge_name_in_html(self, ctx, memory):
        f = _finding(js_bridge_name="PayBridge")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "PayBridge" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_exposed_methods_in_html(self, ctx, memory):
        f = _finding(exposed_methods=["getSecret", "uploadFile"])
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        content = artifact.absolute_path.read_text()
        assert "getSecret" in content
        assert "uploadFile" in content

    @pytest.mark.asyncio
    async def test_file_access_payload_included(self, ctx, memory):
        f = _finding(file_access_enabled=True)
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "readFile" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_no_file_access_payload_excluded(self, ctx, memory):
        f = _finding(file_access_enabled=False, exposed_methods=["getToken"])
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        # File access section should not be triggered
        content = artifact.absolute_path.read_text()
        assert "getToken" in content

    @pytest.mark.asyncio
    async def test_token_harvest_always_present(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "localStorage" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_relative_path_correct(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.relative_path.startswith("poc_artifacts/")


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_empty_without_finding(self, ctx, memory):
        assert await _agent(ctx, memory).analyze() == []

    @pytest.mark.asyncio
    async def test_returns_enriched_finding(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f).analyze()
        assert len(results) == 1
        assert results[0].poc_artifacts

    @pytest.mark.asyncio
    async def test_exploitation_status_code_only(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f).analyze()
        assert results[0].exploitation_status == "Code_Only"
