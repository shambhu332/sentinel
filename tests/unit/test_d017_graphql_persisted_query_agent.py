"""Unit tests for D_017 GraphqlPersistedQueryAgent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agents.dynamic import GraphqlPersistedQueryAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _flow(
    *, host: str = "api.example.com",
    path: str = "/graphql",
    method: str = "POST",
    req_body: str = "",
    resp_body: str = "{}",
    status: int = 200,
) -> CapturedFlow:
    return CapturedFlow(
        method=method, url=f"https://{host}{path}",
        scheme="https", host=host, path=path,
        request_body=req_body,
        response_status=status, response_body=resp_body,
    )


def _capture(*flows: CapturedFlow) -> MitmproxyCapture:
    return MitmproxyCapture(
        flows=list(flows), capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=10.0, flow_count=len(flows),
    )


def _gql_body(query: str = "", persisted_hash: str = "") -> str:
    body = {}
    if query:
        body["query"] = query
    if persisted_hash:
        body["extensions"] = {"persistedQuery":
                              {"version": 1, "sha256Hash": persisted_hash}}
    return json.dumps(body)


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path, scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = GraphqlPersistedQueryAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_hash_only_no_finding(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(req_body=_gql_body(persisted_hash="a" * 64)),
    )
    findings = await GraphqlPersistedQueryAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_hash_plus_query_is_critical(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(req_body=_gql_body(
            query="query { me { id } }",
            persisted_hash="a" * 64,
        )),
    )
    findings = await GraphqlPersistedQueryAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1


@pytest.mark.asyncio
async def test_introspection_via_apq_is_high(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(
            req_body=_gql_body(
                query="query { __schema { types { name } } }",
                persisted_hash="b" * 64,
            ),
            resp_body='{"data":{"__schema":{"types":[]}}}',
        ),
    )
    findings = await GraphqlPersistedQueryAgent(
        context=ctx, memory=memory,
    ).analyze()
    intro = [f for f in findings if "Introspection" in f.vuln_class]
    assert len(intro) == 1
    assert intro[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_register_and_retry_handshake_is_medium(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        # First request: hash only, server returns PersistedQueryNotFound.
        _flow(
            req_body=_gql_body(persisted_hash="c" * 64),
            resp_body='{"errors":[{"message":"PersistedQueryNotFound"}]}',
        ),
        # Second request: hash + query, server accepts.
        _flow(
            req_body=_gql_body(query="query { ping }",
                               persisted_hash="c" * 64),
            resp_body='{"data":{"ping":"pong"}}',
        ),
    )
    findings = await GraphqlPersistedQueryAgent(
        context=ctx, memory=memory,
    ).analyze()
    hs = [f for f in findings if "Handshake" in f.vuln_class]
    assert len(hs) == 1
    assert hs[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_non_graphql_flow_ignored(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(
        _flow(path="/api/v1/users", req_body='{"foo":1}'),
    )
    findings = await GraphqlPersistedQueryAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
