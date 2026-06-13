"""Tests for D_073 PendingIntent escalation + D_074 scheme confuser."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.dynamic.d073_pending_intent_esc import (
    PendingIntentEscalationAgent,
)
from sentinel.agents.dynamic.d074_scheme_confuser import SchemeConfuserAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id


class _Memory:
    async def save_finding(self, finding):
        return None

    async def publish_event(self, session_id, event_type, payload):
        return None


def _apk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return path


def _ctx(tmp_path: Path) -> tuple[ScanContext, Path]:
    apk = _apk(tmp_path / "t.apk")
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    return ctx, decompiled


@pytest.mark.asyncio
async def test_d073_flags_pending_intent_without_immutable(tmp_path):
    ctx, root = _ctx(tmp_path)
    (root / "Notify.java").write_text(
        "package com.x;\n"
        "import android.app.PendingIntent;\n"
        "class Notify {\n"
        "  void build(Context ctx, Intent i) {\n"
        "    PendingIntent pi = PendingIntent.getActivity(\n"
        "      ctx, 7, i, PendingIntent.FLAG_UPDATE_CURRENT\n"
        "    );\n"
        "  }\n"
        "}\n"
    )
    findings = await PendingIntentEscalationAgent(
        context=ctx,
        memory=_Memory(),
    ).analyze()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.agent_id == "D_073"
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["factory"] == "getActivity"
    assert finding.evidence["class_name"] == "com.x.Notify"
    assert finding.evidence["dynamic_target"] is True
    payload = finding.evidence["frida_payload"]
    assert payload["type"] == "pending_intent_probe"
    assert payload["class_name"] == "com.x.Notify"
    assert payload["probe_extra_value"] == "SENTINEL_PROBE"


@pytest.mark.asyncio
async def test_d073_skips_immutable_pending_intent(tmp_path):
    ctx, root = _ctx(tmp_path)
    (root / "Safe.java").write_text(
        "class Safe {\n"
        "  void build(Context ctx, Intent i) {\n"
        "    PendingIntent.getBroadcast(ctx, 1, i,\n"
        "      PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);\n"
        "  }\n"
        "}\n"
    )
    findings = await PendingIntentEscalationAgent(
        context=ctx,
        memory=_Memory(),
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d073_flags_explicit_mutable_service(tmp_path):
    ctx, root = _ctx(tmp_path)
    (root / "Work.java").write_text(
        "class Work {\n"
        "  void build(Context ctx, Intent i) {\n"
        "    PendingIntent.getService(ctx, 2, i, PendingIntent.FLAG_MUTABLE);\n"
        "  }\n"
        "}\n"
    )
    findings = await PendingIntentEscalationAgent(
        context=ctx,
        memory=_Memory(),
    ).analyze()
    assert len(findings) == 1
    assert findings[0].evidence["explicit_mutable"] is True


@pytest.mark.asyncio
async def test_d074_emits_scheme_probe_for_view_activity(tmp_path):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.x",
        "activities": [
            {
                "name": "com.x.DeepLinkActivity",
                "exported": True,
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.VIEW"],
                        "schemes": ["https", "myapp"],
                        "hosts": ["trusted.example"],
                    },
                ],
            },
        ],
    }
    findings = await SchemeConfuserAgent(context=ctx, memory=_Memory()).analyze()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.agent_id == "D_074"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["dynamic_target"] is True
    assert finding.evidence["activity"] == "com.x.DeepLinkActivity"
    payload = finding.evidence["frida_payload"]
    assert payload["type"] == "scheme_probe"
    assert payload["activity"] == "com.x.DeepLinkActivity"
    assert payload["schemes"] == ["https", "myapp"]
    assert "https://evil.com@trusted.example/sentinel-probe" in (
        payload["confusion_payloads"]
    )


@pytest.mark.asyncio
async def test_d074_skips_non_view_or_scheme_less_activity(tmp_path):
    ctx, _ = _ctx(tmp_path)
    ctx.manifest = {
        "activities": [
            {
                "name": "com.x.Main",
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.MAIN"],
                        "schemes": ["myapp"],
                    },
                ],
            },
            {
                "name": "com.x.ViewNoScheme",
                "intent_filters": [
                    {"actions": ["android.intent.action.VIEW"]},
                ],
            },
        ],
    }
    findings = await SchemeConfuserAgent(context=ctx, memory=_Memory()).analyze()
    assert findings == []
