"""Unit tests for API_003 Mass Assignment fuzzer."""
from __future__ import annotations

import json

import httpx
import pytest

from sentinel.agents.api_security import MassAssignmentFuzzerAgent
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
        method="POST",
        url="https://api.example.com/v1/users",
        scheme="https",
        host="api.example.com",
        path="/v1/users",
        request_headers={
            "Authorization": "Bearer aaa.bbb.ccc",
            "Content-Type": "application/json",
        },
        request_body=json.dumps({"email": "a@b.c", "name": "Alice"}),
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body=json.dumps({"id": 1, "email": "a@b.c", "name": "Alice"}),
        tls_failed=False,
        timestamp=0.0,
    )
    defaults.update(overrides)
    return CapturedFlow(**defaults)


class _StubTransport(httpx.MockTransport):
    def __init__(self, responder):
        self.calls: list[httpx.Request] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            return responder(request)

        super().__init__(_handler)


def _patch_client(monkeypatch, transport):
    import sentinel.agents.api_security.mass_assignment as mod

    orig = mod.httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return orig(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", factory)


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_without_capture(memory, tmp_path):
    ctx = _mk_context(tmp_path)
    agent = MassAssignmentFuzzerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_for_get_only_traffic(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow(method="GET", request_body="")])
    agent = MassAssignmentFuzzerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_without_auth(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow(request_headers={
        "Content-Type": "application/json",
    })])
    agent = MassAssignmentFuzzerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_for_non_json_body(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow(
        request_body="email=a@b.c&name=Alice",
    )])
    agent = MassAssignmentFuzzerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_authenticated_json_post(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow()])
    agent = MassAssignmentFuzzerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- Positive detection ----------

@pytest.mark.asyncio
async def test_reflected_payload_yields_critical_finding(memory, tmp_path, monkeypatch):
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        # Server echoes the mutated body — clear reflection signal.
        payload = json.loads(request.content)
        return httpx.Response(200, json={"id": 1, **payload})

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()

    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "API_003"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["signal_key"] == "is_admin"  # first payload wins
    assert f.evidence["reflected_in_response"] is True
    assert f.evidence["mutated_status"] == 200
    assert f.evidence["host"] == "api.example.com"
    assert "replay_logs" in f.evidence
    # Auth header must have gone with the mutated request.
    assert transport.calls[0].headers.get("authorization") == "Bearer aaa.bbb.ccc"


@pytest.mark.asyncio
async def test_accepted_without_reflection_yields_high_finding(memory, tmp_path, monkeypatch):
    """2xx without reflection is a weaker but still-actionable signal."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "email": "a@b.c", "name": "Alice"})

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["reflected_in_response"] is False


# ---------- Negative: 400/422 ----------

@pytest.mark.asyncio
async def test_400_rejection_produces_no_finding(memory, tmp_path, monkeypatch):
    """A 400 on the extra field is the healthy case."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "unknown field"})

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_422_rejection_produces_no_finding(memory, tmp_path, monkeypatch):
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"errors": ["is_admin: not allowed"]})

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []


# ---------- Skip payloads that collide with baseline body ----------

@pytest.mark.asyncio
async def test_skips_payloads_already_present_in_baseline(memory, tmp_path, monkeypatch):
    """If the baseline already sends `role`, injecting a different `role` value
    is an override — a different vulnerability, not mass assignment."""
    body = json.dumps({"email": "a@b.c", "role": "user"})
    ctx = _mk_context(tmp_path, flows=[_flow(request_body=body)])

    def responder(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        # Verify no attempt carried role=admin (would collide with baseline).
        assert payload.get("role") == "user"
        return httpx.Response(400)

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    await agent.analyze()
    # is_admin and price still fire — but not role.
    payloads_sent = [json.loads(c.content) for c in transport.calls]
    keys_seen = {k for p in payloads_sent for k in p.keys() if k not in body}
    assert "role" not in keys_seen
    assert keys_seen == {"is_admin", "price", "balance"}


# ---------- Scope gate ----------

@pytest.mark.asyncio
async def test_out_of_scope_host_is_skipped(memory, tmp_path, monkeypatch):
    scope = BountyScope(in_scope_domains=["api.other.com"])
    ctx = _mk_context(tmp_path, scope=scope, flows=[_flow()])

    called = False

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"is_admin": True})

    _patch_client(monkeypatch, _StubTransport(responder))

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert findings == []
    assert called is False


# ---------- Safety bound ----------

@pytest.mark.asyncio
async def test_no_more_than_four_probes_per_endpoint(memory, tmp_path, monkeypatch):
    """At most 4 default payloads (is_admin/role/price/balance); no combinatorial fuzzing."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400)

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    await agent.analyze()
    assert len(transport.calls) <= 4


@pytest.mark.asyncio
async def test_stops_after_first_hit(memory, tmp_path, monkeypatch):
    """Once mass assignment is proven, don't keep firing payloads."""
    ctx = _mk_context(tmp_path, flows=[_flow()])

    def responder(request: httpx.Request) -> httpx.Response:
        # Every payload gets accepted+reflected, but agent should stop after 1.
        payload = json.loads(request.content)
        return httpx.Response(200, json={"id": 1, **payload})

    transport = _StubTransport(responder)
    _patch_client(monkeypatch, transport)

    agent = MassAssignmentFuzzerAgent(
        context=ctx, memory=memory, config={"delay_seconds": 0.0},
    )
    findings = await agent.analyze()
    assert len(findings) == 1
    assert len(transport.calls) == 1
