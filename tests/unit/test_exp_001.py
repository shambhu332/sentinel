"""Unit tests for EXP_001 BOLA/IDOR replay agent."""
from __future__ import annotations

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.exploit.exp_001_bola_replay import EXP001BOLAReplayAgent
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


def _finding(agent_id="API_002", **ev_extra) -> Finding:
    ev = {"endpoint_url": "https://api.example.com/users/123",
          "http_method": "GET", "original_id": "123", **ev_extra}
    return Finding(
        agent_id=agent_id,
        session_id=generate_session_id(),
        vuln_class="Broken Object Level Authorization (BOLA/IDOR)",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence=ev,
        recommendation="Use server-side authorization.",
        compliance_tags=["CWE-639"],
    )


def _agent(ctx, memory, finding=None, dry_run=True):
    return EXP001BOLAReplayAgent(
        context=ctx, memory=memory, finding=finding, dry_run=dry_run
    )


class TestCanExploit:
    def test_true_for_api_002(self, ctx, memory):
        assert _agent(ctx, memory).can_exploit(_finding("API_002"))

    def test_true_for_n_001_with_bola_vuln_class(self, ctx, memory):
        f = _finding("N_001")
        assert _agent(ctx, memory).can_exploit(f)

    def test_true_for_idor_in_vuln_class(self, ctx, memory):
        f = Finding(agent_id="X_001", session_id=generate_session_id(),
                    vuln_class="IDOR via sequential ID", severity=Severity.HIGH,
                    confidence=0.8, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert _agent(ctx, memory).can_exploit(f)

    def test_false_for_unrelated_agent(self, ctx, memory):
        f = Finding(agent_id="C_001", session_id=generate_session_id(),
                    vuln_class="Insecure Cipher Mode", severity=Severity.HIGH,
                    confidence=0.9, evidence={}, recommendation="fix",
                    compliance_tags=[])
        assert not _agent(ctx, memory).can_exploit(f)


class TestIsApplicable:
    @pytest.mark.asyncio
    async def test_false_when_no_finding(self, ctx, memory):
        assert await _agent(ctx, memory).is_applicable() is False

    @pytest.mark.asyncio
    async def test_true_when_finding_set(self, ctx, memory):
        assert await _agent(ctx, memory, finding=_finding()).is_applicable() is True


class TestGeneratePoc:
    @pytest.mark.asyncio
    async def test_creates_python_file(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.absolute_path.exists()
        assert artifact.absolute_path.suffix == ".py"

    @pytest.mark.asyncio
    async def test_watermark_in_script(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        content = artifact.absolute_path.read_text()
        assert "AUTHORIZED SECURITY TESTING ONLY" in content

    @pytest.mark.asyncio
    async def test_endpoint_in_script(self, ctx, memory):
        f = _finding(endpoint_url="https://api.example.com/orders/456")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert "api.example.com" in artifact.absolute_path.read_text()

    @pytest.mark.asyncio
    async def test_perturbations_in_script(self, ctx, memory):
        f = _finding(original_id="100")
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        content = artifact.absolute_path.read_text()
        assert "99" in content  # 100-1

    @pytest.mark.asyncio
    async def test_relative_path_set(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.relative_path.startswith("poc_artifacts/")

    @pytest.mark.asyncio
    async def test_kind_is_python_requests(self, ctx, memory):
        f = _finding()
        artifact = await _agent(ctx, memory, finding=f).generate_poc(f, ctx)
        assert artifact.kind == "python_requests"


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_returns_empty_without_finding(self, ctx, memory):
        assert await _agent(ctx, memory).analyze() == []

    @pytest.mark.asyncio
    async def test_returns_finding_with_poc_artifacts(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f).analyze()
        assert len(results) == 1
        assert results[0].poc_artifacts

    @pytest.mark.asyncio
    async def test_exploitation_status_code_only_dry_run(self, ctx, memory):
        f = _finding()
        results = await _agent(ctx, memory, finding=f, dry_run=True).analyze()
        assert results[0].exploitation_status == "Code_Only"

    @pytest.mark.asyncio
    async def test_empty_when_wrong_finding_type(self, ctx, memory):
        f = Finding(agent_id="C_001", session_id=generate_session_id(),
                    vuln_class="ECB mode", severity=Severity.HIGH,
                    confidence=0.9, evidence={}, recommendation="fix",
                    compliance_tags=[])
        results = await _agent(ctx, memory, finding=f).analyze()
        assert results == []
