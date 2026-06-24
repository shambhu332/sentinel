"""Unit tests for the preflight self-check."""
from __future__ import annotations

import asyncio

from sentinel.tools.preflight import (
    CheckResult,
    _check_compiled_agent,
    _check_login_scripts,
    _check_test_credentials,
    _check_frida_python,
)


def test_check_result_render_marker():
    ok = CheckResult("x", True, "fine").render()
    fail = CheckResult("y", False, "boom").render()
    assert ok.startswith("[OK  ]")
    assert fail.startswith("[FAIL]")


def test_login_scripts_check_finds_bundled_samples():
    r = _check_login_scripts()
    assert r.ok
    assert "com.example.app" in r.detail


def test_compiled_agent_check_reports_state():
    r = _check_compiled_agent()
    # Either we have the agent compiled or we have a clear remediation
    # message — both shapes are valid; never a crash.
    if r.ok:
        assert "_agent.js" in r.detail
    else:
        assert "npm run build" in r.detail


def test_test_credentials_check_returns_bool_with_detail():
    r = _check_test_credentials()
    assert isinstance(r.ok, bool)
    assert r.detail  # never empty


def test_frida_python_check_is_either_ok_or_remediation():
    r = _check_frida_python()
    if r.ok:
        assert "v" in r.detail.lower()
    else:
        assert "not installed" in r.detail
