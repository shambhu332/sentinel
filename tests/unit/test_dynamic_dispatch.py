"""Tests for hybrid SAST→DAST dynamic-target dispatch."""
from __future__ import annotations

import pytest

from sentinel.core.dynamic_dispatch import dispatch_dynamic_targets
from sentinel.core.finding import Finding, Severity


class _Frida:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def dispatch_rpc(self, method, payload, timeout_s=30.0):
        from sentinel.tools.result import ToolResult
        self.calls.append((method, payload))
        return ToolResult.ok({"method": method})


def _finding(agent_id: str, payload: dict | None) -> Finding:
    evidence = {"dynamic_target": payload is not None}
    if payload is not None:
        evidence["frida_payload"] = payload
    return Finding(
        agent_id=agent_id,
        vuln_class="x",
        severity=Severity.HIGH,
        confidence=0.8,
        evidence=evidence,
        recommendation="fix",
        session_id="session123",
    )


@pytest.mark.asyncio
async def test_dispatch_maps_recent_hybrid_agents():
    frida = _Frida()
    summary = await dispatch_dynamic_targets(
        [
            _finding("D_073", {"type": "pending_intent_probe"}),
            _finding("D_074", {"type": "scheme_probe"}),
            _finding("D_078", {"type": "biometric_unwrap_probe"}),
            _finding("D_081", None),
        ],
        frida,
    )

    assert summary["dispatched"] == 3
    assert summary["succeeded"] == 3
    assert [method for method, _ in frida.calls] == [
        "pendingintentesc",
        "schemeconfuser",
        "biometricunwrapper",
    ]
