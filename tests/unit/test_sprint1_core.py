"""Unit tests for Sprint 1.1 core contracts + LLM router."""
import json

import httpx
import pytest
from pydantic import ValidationError

from sentinel.core.config import Settings, reset_settings
from sentinel.core.finding import BountyScope, Finding, Severity, TriageState
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.llm.router import FreeProviderRouter, RouterError


def _finding(**kw):
    base = dict(
        agent_id="F_001", vuln_class="Firebase", severity=Severity.CRITICAL,
        confidence=0.9, recommendation="fix it",
        session_id="abcd1234efgh5678", evidence={"k": "v"},
    )
    base.update(kw)
    return Finding(**base)


# ---- Finding ----
def test_finding_valid():
    f = _finding()
    assert f.severity == Severity.CRITICAL
    assert f.triage == TriageState.UNREVIEWED
    assert len(f.finding_id) == 16

def test_finding_id_stable():
    assert _finding().finding_id == _finding().finding_id

def test_finding_rejects_bad_agent_id():
    with pytest.raises(ValidationError):
        _finding(agent_id="bad-id")

def test_finding_rejects_bad_session_id():
    with pytest.raises(ValidationError):
        _finding(session_id="short")

def test_finding_rejects_extra_field():
    with pytest.raises(ValidationError):
        Finding(
            agent_id="F_001", vuln_class="x", severity=Severity.LOW,
            confidence=0.5, recommendation="x", session_id="abcd1234efgh5678",
            malicious="injected",
        )

def test_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        _finding(confidence=1.5)
    with pytest.raises(ValidationError):
        _finding(confidence=-0.1)


# ---- BountyScope ----
def test_scope_unrestricted():
    s = BountyScope()
    assert s.is_unrestricted()
    assert s.package_in_scope("com.any")
    assert s.technique_allowed("anything")

def test_scope_restricts_packages():
    s = BountyScope(in_scope_packages=["com.acme"])
    assert s.package_in_scope("com.acme")
    assert not s.package_in_scope("com.evil")

def test_scope_forbids_techniques():
    s = BountyScope(forbidden_techniques={"dos"})
    assert not s.technique_allowed("dos")
    assert s.technique_allowed("static")


# ---- Config ----
def test_settings_secret_not_in_repr(monkeypatch):
    reset_settings()
    monkeypatch.setenv("CEREBRAS_API_KEY", "super-secret-xyz")
    s = Settings()
    assert "super-secret-xyz" not in repr(s)
    assert s.has_cerebras_key()

def test_settings_rejects_bad_log_level(monkeypatch):
    monkeypatch.setenv("SENTINEL_LOG_LEVEL", "BOGUS")
    with pytest.raises(ValidationError):
        Settings()


# ---- ScanContext ----
def test_scan_context_valid(tmp_path):
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path / "w",
    )
    assert ctx.apk_path.is_absolute()
    assert not ctx.is_private

def test_scan_context_missing_apk(tmp_path):
    with pytest.raises(FileNotFoundError):
        ScanContext(
            session_id=generate_session_id(),
            apk_path=tmp_path / "nope.apk", workspace=tmp_path,
        )

def test_scan_context_bad_sensitivity(tmp_path):
    apk = tmp_path / "a.apk"; apk.write_bytes(b"x")
    with pytest.raises(ValueError):
        ScanContext(
            session_id=generate_session_id(),
            apk_path=apk, workspace=tmp_path, data_sensitivity="bad",
        )


# ---- Router ----
class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = body
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        return httpx.Response(status_code=self.status, json=self.body, request=request)


@pytest.mark.asyncio
async def test_router_cerebras_success(monkeypatch):
    reset_settings()
    monkeypatch.setenv("CEREBRAS_API_KEY", "test-key")
    router = FreeProviderRouter()
    router._client = httpx.AsyncClient(transport=MockTransport(
        200, {"choices": [{"message": {"content": "ok"}}]},
    ))
    result = await router.query(messages=[{"role": "user", "content": "hi"}])
    assert result["provider"] == "cerebras"
    assert result["content"] == "ok"
    await router.close()


@pytest.mark.asyncio
async def test_router_force_local(monkeypatch):
    reset_settings()
    monkeypatch.setenv("CEREBRAS_API_KEY", "test-key")
    router = FreeProviderRouter(force_local=True)
    router._client = httpx.AsyncClient(transport=MockTransport(
        200, {"message": {"content": "local response"}},
    ))
    result = await router.query(messages=[{"role": "user", "content": "hi"}])
    assert result["provider"] == "ollama"
    assert result["content"] == "local response"
    await router.close()


@pytest.mark.asyncio
async def test_router_json_mode_strips_fences(monkeypatch):
    reset_settings()
    monkeypatch.setenv("CEREBRAS_API_KEY", "test-key")
    router = FreeProviderRouter()
    router._client = httpx.AsyncClient(transport=MockTransport(
        200, {"choices": [{"message": {
            "content": '```json\n{"ok": true}\n```',
        }}]},
    ))
    result = await router.query_json(messages=[{"role": "user", "content": "x"}])
    assert result["content"] == {"ok": True}
    await router.close()


def test_session_id_valid_format():
    for _ in range(10):
        sid = generate_session_id()
        assert 8 <= len(sid) <= 64