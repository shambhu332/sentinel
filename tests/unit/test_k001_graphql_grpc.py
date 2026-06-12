"""Unit tests for K_001 GraphQL + gRPC schema analyzer."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.network.k001_graphql_grpc_analyzer import (
    GraphQLGrpcAnalyzerAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


def _make_apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx_with_assets(tmp_path: Path) -> tuple[ScanContext, Path]:
    apk = _make_apk(tmp_path / "test.apk")
    resources = tmp_path / "resources"
    (resources / "assets").mkdir(parents=True)
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.resources_dir = resources
    return ctx, resources / "assets"


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


@pytest.mark.asyncio
async def test_graphql_introspection_flagged(tmp_path, memory):
    ctx, assets = _ctx_with_assets(tmp_path)
    (assets / "schema.graphql").write_text(
        "type Query { __schema: String }\n"
        + "type Query { user(id: ID!): User }\n" * 60
    )
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    classes = {f.vuln_class for f in findings}
    assert "GraphQL Schema Ships Introspection Surface" in classes


@pytest.mark.asyncio
async def test_graphql_mutation_without_auth_flagged(tmp_path, memory):
    ctx, assets = _ctx_with_assets(tmp_path)
    (assets / "ops.graphql").write_text(
        "type Query { me: User }\n"
        "type Mutation { transferFunds(amount: Int!): Bool }\n"
    )
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    classes = {f.vuln_class for f in findings}
    assert "GraphQL Mutations/Subscriptions Without Auth Directives" in classes


@pytest.mark.asyncio
async def test_graphql_with_auth_directive_not_flagged(tmp_path, memory):
    ctx, assets = _ctx_with_assets(tmp_path)
    (assets / "ops.graphql").write_text(
        "type Query { me: User }\n"
        "type Mutation { transferFunds(amount: Int!): Bool @auth }\n"
    )
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    classes = {f.vuln_class for f in findings}
    assert "GraphQL Mutations/Subscriptions Without Auth Directives" not in classes


@pytest.mark.asyncio
async def test_proto_without_auth_hints_flagged(tmp_path, memory):
    ctx, assets = _ctx_with_assets(tmp_path)
    (assets / "wallet.proto").write_text(
        'syntax = "proto3";\n'
        'service Wallet {\n'
        '  rpc GetBalance(BalanceRequest) returns (BalanceResponse);\n'
        '  rpc StreamTxns(TxRequest) returns (stream Tx);\n'
        '}\n'
    )
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    classes = {f.vuln_class for f in findings}
    assert "gRPC Service Without Auth Metadata Annotations" in classes
    assert "gRPC Streaming RPC Surface" in classes


@pytest.mark.asyncio
async def test_proto_with_auth_hint_not_flagged(tmp_path, memory):
    ctx, assets = _ctx_with_assets(tmp_path)
    (assets / "wallet.proto").write_text(
        'service Wallet {\n'
        '  rpc GetBalance(BalanceRequest) returns (BalanceResponse) {\n'
        '    option (google.api.http) = { get: "/v1/balance" };\n'
        '  }\n'
        '}\n'
    )
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    classes = {f.vuln_class for f in findings}
    assert "gRPC Service Without Auth Metadata Annotations" not in classes


@pytest.mark.asyncio
async def test_empty_resources_returns_no_findings(tmp_path, memory):
    ctx, _assets = _ctx_with_assets(tmp_path)
    agent = GraphQLGrpcAnalyzerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []
