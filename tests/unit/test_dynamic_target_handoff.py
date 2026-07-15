"""Unit coverage for SAST-to-DAST dynamic_target handoff."""
from __future__ import annotations

import asyncio
from pathlib import Path

from sentinel.agents.base.ai_autonomous_agent import Candidate
from sentinel.agents.platform.p005_excessive_permissions import (
    ExcessivePermissionsAgent,
)
from sentinel.agents.platform.p015_deep_link_mapper import DeepLinkMapperAgent
from sentinel.agents.platform.p_001_deep_link_hijack import P001DeepLinkHijackAgent
from sentinel.core.finding import BountyScope
from sentinel.core.scan_context import ScanContext, generate_session_id


def _ctx(tmp_path: Path) -> ScanContext:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.workspace.mkdir()
    return ctx


def test_p001_emits_dynamic_target_not_repro_command(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.example",
        "deep_links": [{
            "activity": "com.example.MainActivity",
            "data_elements": [{"scheme": "mhlcrypto", "host": "showPage"}],
        }],
    }
    agent = P001DeepLinkHijackAgent(ctx, object())

    target = agent._dynamic_target_for_candidate(
        Candidate(
            code_snippet="getIntent().getData()",
            file_path="sources/com/example/MainActivity.java",
            line_number=12,
            column=8,
            rule_triggered="P_001",
            rule_confidence=0.85,
            context_window="Uri data = getIntent().getData();",
        ),
        None,  # hook does not inspect the LLM verdict
    )

    assert target == {
        "type": "deep_link",
        "scheme": "mhlcrypto",
        "host": "showPage",
        "params": "url=https%3A%2F%2F10.11.3.1%2F",
        "target_component": "com.example.MainActivity",
    }


def test_p005_emits_permission_dynamic_target_not_repro_command(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.example",
        "permissions": ["android.permission.SYSTEM_ALERT_WINDOW"],
    }

    finding = asyncio.run(
        ExcessivePermissionsAgent(ctx, object()).analyze(),
    )[0]

    assert finding.dynamic_target == {
        "type": "permission_check",
        "permission": "android.permission.SYSTEM_ALERT_WINDOW",
    }
    assert finding.reproduction_commands == []


def test_p015_emits_dynamic_targets_not_repro_commands(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.manifest = {
        "package": "com.example",
        "activities": ["com.example.LinkActivity"],
        "deep_links": [{
            "activity": "com.example.LinkActivity",
            "actions": "android.intent.action.VIEW",
            "categories": "android.intent.category.BROWSABLE",
            "auto_verify": False,
            "data_elements": [{
                "scheme": "https",
                "host": "example.com",
                "pathPrefix": "/oauth/callback",
            }],
        }],
    }

    findings = asyncio.run(DeepLinkMapperAgent(ctx, object()).analyze())

    assert findings
    for finding in findings:
        assert finding.dynamic_target
        assert finding.dynamic_target["type"] == "deep_link"
        assert finding.dynamic_target["scheme"] == "https"
        assert finding.dynamic_target["host"].startswith("example.com")
        assert finding.reproduction_commands == []
        assert finding.observed_result is None
