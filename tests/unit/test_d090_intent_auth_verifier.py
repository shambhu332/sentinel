"""Unit tests for D_090 — Auth-Gated Intent Handler Verifier."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sentinel.agents.dynamic.d090_intent_auth_verifier import (
    IntentAuthVerifierAgent,
    _classify_outcome,
    _collect_targets,
    _looks_auth_gated,
)
from sentinel.core.finding import Severity


MANIFEST = {
    "package": "com.example.app",
    "activities": [
        {
            "name": ".DeepLinkActivity",
            "exported": True,
            "intent_filters": [{
                "action": "android.intent.action.VIEW",
                "schemes": ["myapp"],
                "hosts": ["open"],
            }],
        },
        {
            "name": ".InternalActivity",
            "exported": False,
            "intent_filters": [],
        },
    ],
}


# --- Helpers ----------------------------------------------------------------

def test_collect_targets_filters_to_exported_view_activities():
    out = _collect_targets(MANIFEST)
    assert len(out) == 1
    assert out[0]["activity"] == ".DeepLinkActivity"
    assert out[0]["schemes"] == ["myapp"]
    assert out[0]["hosts"] == ["open"]
    assert out[0]["exported"] is True


def test_collect_targets_skips_view_filters_without_schemes():
    manifest = {"activities": [{
        "name": ".X",
        "exported": True,
        "intent_filters": [{"action": "android.intent.action.VIEW"}],
    }]}
    assert _collect_targets(manifest) == []


def test_looks_auth_gated_recognises_login_activity():
    assert _looks_auth_gated("Starting LoginActivity ...", "", "/p.webp")
    assert _looks_auth_gated("", "Permission Denial: ...", "/p.webp")
    assert not _looks_auth_gated(
        "Starting Activity .Home", "", "/evidence/p.webp",
    )


def test_looks_auth_gated_missing_shot_with_stderr_counts_as_gated():
    assert _looks_auth_gated("", "error 5", None)
    # Missing screenshot with no stderr is not enough.
    assert not _looks_auth_gated("", "", None)


def test_classify_outcome_verified_when_not_blocked():
    state, status, severity = _classify_outcome(
        blocked=False,
        logged_in_shot=None,
        logged_in_stdout="",
        logged_in_stderr="",
    )
    assert state == "verified"
    assert severity == Severity.HIGH


def test_classify_outcome_verified_after_successful_login():
    state, _, _ = _classify_outcome(
        blocked=True,
        logged_in_shot="evidence/x.webp",
        logged_in_stdout="Starting .Home",
        logged_in_stderr="",
    )
    assert state == "verified"


def test_classify_outcome_remains_auth_gated_when_login_unavailable():
    state, status, severity = _classify_outcome(
        blocked=True,
        logged_in_shot=None,
        logged_in_stdout="",
        logged_in_stderr="",
    )
    assert state == "auth_gated"
    assert severity == Severity.MEDIUM
    assert "login" in status.lower()


# --- Full agent flow --------------------------------------------------------

class _FakeAdb:
    def __init__(self, *, blocked_first: bool, login_succeeds: bool = True):
        self._blocked_first = blocked_first
        self._login_succeeds = login_succeeds
        self.calls: list[tuple[str, str]] = []

    async def execute_adb_command_and_capture(
        self, cmd, *, session_id, context, workspace, **kw,
    ):
        self.calls.append((cmd, context))
        if "logged_out" in context:
            if self._blocked_first:
                return "Starting LoginActivity{}", "", "evidence/lo.webp"
            return "Starting .DeepLinkActivity", "", "evidence/lo.webp"
        # logged_in
        return "Starting .DeepLinkActivity", "", "evidence/li.webp"


class _FakeCredentials:
    def __init__(self, succeed: bool):
        self.has_credentials = True
        self._succeed = succeed

    async def auto_login(self, package, **kw):
        return SimpleNamespace(
            outcome="success" if self._succeed else "auth_gated",
            reason="",
            credential_label="TEST_USER",
            duration_ms=10,
            succeeded=self._succeed,
        )


def _make_agent(tmp_path: Path) -> IntentAuthVerifierAgent:
    ctx = SimpleNamespace(
        session_id="sess-d090-0001",
        workspace=tmp_path,
        manifest=MANIFEST,
    )
    memory = SimpleNamespace()
    return IntentAuthVerifierAgent(ctx, memory)


def _run(agent: IntentAuthVerifierAgent, adb, credentials):
    with patch.object(
        agent, "_resolve_runtime_deps",
        return_value=(adb, credentials, None),
    ):
        return asyncio.run(agent.analyze())


def test_is_applicable_requires_exported_deep_link(tmp_path):
    agent = _make_agent(tmp_path)
    assert asyncio.run(agent.is_applicable())

    agent_no_targets = _make_agent(tmp_path)
    agent_no_targets._context.manifest = {
        "package": "com.x",
        "activities": [{"name": ".Y", "exported": False, "intent_filters": []}],
    }
    assert not asyncio.run(agent_no_targets.is_applicable())


def test_analyze_verified_when_handler_reachable_without_auth(tmp_path):
    agent = _make_agent(tmp_path)
    adb = _FakeAdb(blocked_first=False)
    findings = _run(agent, adb, credentials=None)
    assert len(findings) == 1
    f = findings[0]
    assert f.verification_state == "verified"
    assert f.severity == Severity.HIGH
    assert f.severity_rationale is None
    assert f.test_credentials_used is False
    assert f.blocking_state_screenshot is None
    assert any(s["label"] == "logged_out" for s in (f.screenshots or []))


def test_analyze_runs_auto_login_when_blocked_and_creds_present(tmp_path):
    agent = _make_agent(tmp_path)
    adb = _FakeAdb(blocked_first=True)
    creds = _FakeCredentials(succeed=True)

    findings = _run(agent, adb, credentials=creds)

    assert len(findings) == 1
    f = findings[0]
    assert f.test_credentials_used is True
    assert f.verification_state == "verified"
    # Two adb captures: one before login, one after
    contexts = [c[1] for c in adb.calls]
    assert any("logged_out" in c for c in contexts)
    assert any("logged_in" in c for c in contexts)


def test_analyze_emits_auth_gated_when_login_fails(tmp_path):
    agent = _make_agent(tmp_path)
    adb = _FakeAdb(blocked_first=True)
    creds = _FakeCredentials(succeed=False)

    findings = _run(agent, adb, credentials=creds)

    assert len(findings) == 1
    f = findings[0]
    assert f.verification_state == "auth_gated"
    assert f.blocking_state_screenshot == "evidence/lo.webp"
    assert f.severity_rationale  # filled by fallback
    assert "authenticated users" in f.severity_rationale
    assert f.test_credentials_used is True


def test_analyze_caps_login_attempts_per_scan(tmp_path):
    # Two qualifying activities; only one auto_login attempt should fire
    # because we hard-cap at _MAX_LOGIN_ATTEMPTS=2 but each blocked target
    # consumes one attempt — we ensure the cap is enforced across calls.
    multi_manifest = {
        "package": "com.example.app",
        "activities": [
            {
                "name": f".Act{i}",
                "exported": True,
                "intent_filters": [{
                    "action": "android.intent.action.VIEW",
                    "schemes": ["myapp"],
                    "hosts": [f"h{i}"],
                }],
            }
            for i in range(4)
        ],
    }
    agent = _make_agent(tmp_path)
    agent._context.manifest = multi_manifest

    login_calls = {"n": 0}

    class _CountingCreds(_FakeCredentials):
        async def auto_login(self, package, **kw):
            login_calls["n"] += 1
            return await super().auto_login(package, **kw)

    creds = _CountingCreds(succeed=False)
    adb = _FakeAdb(blocked_first=True)

    findings = _run(agent, adb, credentials=creds)

    assert len(findings) == 4
    # Cap is 2 attempts per scan no matter how many targets.
    assert login_calls["n"] == 2
    used = sum(1 for f in findings if f.test_credentials_used)
    assert used == 2


# --- AdbRunner.execute_adb_command_and_capture -------------------------------

def test_execute_adb_command_and_capture_returns_triple(tmp_path):
    from sentinel.tools.adb_runner import AdbRunner

    runner = AdbRunner()

    class _OkResult:
        success = True
        data = SimpleNamespace(stdout="OK", stderr="", exit_code=0)
        error = None

    async def fake_run(args, serial=None, timeout=None):
        return _OkResult()

    async def fake_shot(session_id, filename, *, workspace, **kw):
        return {"path": f"evidence/{filename}.webp"}

    with patch.object(runner, "_run_adb", side_effect=fake_run), \
         patch.object(runner, "capture_screenshot", side_effect=fake_shot):
        stdout, stderr, shot = asyncio.run(
            runner.execute_adb_command_and_capture(
                "shell am start -a VIEW",
                session_id="s",
                context="probe",
                workspace=tmp_path,
                settle_seconds=0,
            ),
        )

    assert stdout == "OK"
    assert stderr == ""
    assert shot == "evidence/probe.webp"


def test_execute_adb_command_and_capture_survives_adb_failure(tmp_path):
    from sentinel.tools.adb_runner import AdbRunner

    runner = AdbRunner()

    class _FailResult:
        success = False
        data = None
        error = "boom"

    async def fake_run(args, serial=None, timeout=None):
        return _FailResult()

    async def fake_shot(session_id, filename, *, workspace, **kw):
        return {"path": None, "failed": True, "reason": "no device"}

    with patch.object(runner, "_run_adb", side_effect=fake_run), \
         patch.object(runner, "capture_screenshot", side_effect=fake_shot):
        stdout, stderr, shot = asyncio.run(
            runner.execute_adb_command_and_capture(
                ["shell", "am", "start"],
                session_id="s",
                context="probe",
                workspace=tmp_path,
                settle_seconds=0,
            ),
        )

    assert stdout == ""
    assert stderr == "boom"
    assert shot is None
