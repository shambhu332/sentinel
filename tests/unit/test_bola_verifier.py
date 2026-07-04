"""Unit tests for API_002 BOLA verifier agent."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from sentinel.agents.api_security import BOLAVerifierAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _mk_context(tmp_path, scope=None, flows=None):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=scope or BountyScope(),
    )
    if flows is not None:
        ctx.sources["mitmproxy"] = MitmproxyCapture(
            flows=flows,
            capture_file=tmp_path / "mitm_capture.jsonl",
            duration_seconds=0.0,
            flow_count=len(flows),
        )
    return ctx


def _flow(**overrides) -> CapturedFlow:
    defaults = dict(
        method="GET",
        url="https://api.example.com/v1/users/42",
        scheme="https",
        host="api.example.com",
        path="/v1/users/42",
        request_headers={"Authorization": "Bearer aaa.bbb.ccc",
                         "Accept": "application/json"},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body=json.dumps({"id": 42, "email": "a@b.c", "name": "Alice"}),
        tls_failed=False,
        timestamp=0.0,
    )
    defaults.update(overrides)
    return CapturedFlow(**defaults)


class _StubTransport(httpx.MockTransport):
    """MockTransport that records requests and returns caller-supplied responses."""

    def __init__(self, responder):
        self.calls: list[httpx.Request] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            return responder(request)

        super().__init__(_handler)


def _patch_client(monkeypatch, transport):
    """Force BOLAVerifierAgent's httpx.AsyncClient() to use our transport."""
    import sentinel.agents.api_security.bola_verifier as mod

    orig = mod.httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return orig(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", factory)


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_without_capture(memory, tmp_path):
    ctx = _mk_context(tmp_path)
    agent = BOLAVerifierAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_without_auth_header(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow(request_headers={})])
    agent = BOLAVerifierAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_authenticated_get_and_id(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow()])
    agent = BOLAVerifierAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- Positive detection ----------

@pytest.mark.asyncio
async def test_emits_critical_finding_on_bola(memory, tmp_path, monkeypatch):
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        # A different user's data — same JSON shape, distinct identifiers.
        body = json.dumps({"id": 43, "email": "victim@example.com", "name": "Bob"})
        return httpx.Response(200, text=body,
                              headers={"content-type": "application/json"})

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0, "canary_id": "1"},
    )
    findings = await agent.analyze()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.agent_id == "API_002"
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["host"] == "api.example.com"
    assert finding.evidence["endpoint"] == "/v1/users/42"
    assert finding.evidence["mutated_id"] == "43"  # +1 tried first
    assert finding.evidence["baseline_status"] == 200
    assert finding.evidence["mutated_status"] == 200
    assert "replay_logs" in finding.evidence
    assert len(finding.evidence["replay_logs"]) >= 1
    # Auth headers were sent to the target host
    assert transport.calls[0].headers.get("authorization") == "Bearer aaa.bbb.ccc"


# ---------- Negative: identical response ----------

@pytest.mark.asyncio
async def test_no_finding_when_response_matches_baseline(memory, tmp_path, monkeypatch):
    """If the mutated request returns the exact same body, that's not BOLA."""
    baseline = _flow()
    ctx = _mk_context(tmp_path, flows=[baseline])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=baseline.response_body,
                              headers={"content-type": "application/json"})

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []


# ---------- Negative: 403/404 ----------

@pytest.mark.asyncio
async def test_no_finding_when_mutated_request_is_denied(memory, tmp_path, monkeypatch):
    """403/404 on mutation means auth check worked — the healthy case."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text='{"error":"forbidden"}')

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []


# ---------- Scope gate ----------

@pytest.mark.asyncio
async def test_skips_out_of_scope_host(memory, tmp_path, monkeypatch):
    scope = BountyScope(in_scope_domains=["api.other.com"])
    ctx = _mk_context(tmp_path, scope=scope, flows=[_flow()])

    called = False

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, text="{}")

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []
    assert called is False, "must not send requests to out-of-scope host"


@pytest.mark.asyncio
async def test_allows_wildcard_in_scope_domain(memory, tmp_path, monkeypatch):
    scope = BountyScope(in_scope_domains=["*.example.com"])
    ctx = _mk_context(tmp_path, scope=scope, flows=[_flow()])

    responder = lambda req: httpx.Response(200, text=json.dumps(
        {"id": 43, "email": "b@c.d"}))
    _patch_client(monkeypatch, _StubTransport(responder))

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert len(findings) == 1


# ---------- Safety: no enumeration ----------

@pytest.mark.asyncio
async def test_bounded_mutation_count(memory, tmp_path, monkeypatch):
    """Numeric ID: at most 3 attempts (base+1, base-1, canary). No mass enum."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0},
    )
    await agent.analyze()
    assert len(transport.calls) <= 3


@pytest.mark.asyncio
async def test_opaque_id_only_probes_canary(memory, tmp_path, monkeypatch):
    """Non-numeric IDs skip ±1 mutation — only the canary is tried."""
    flow = _flow(path="/v1/tokens/aBcDeF0123456789xyzq")
    ctx = _mk_context(tmp_path, flows=[flow])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = BOLAVerifierAgent(
        context=ctx, memory=memory,
        config={"delay_seconds": 0.0, "canary_id": "1"},
    )
    await agent.analyze()
    assert len(transport.calls) == 1
