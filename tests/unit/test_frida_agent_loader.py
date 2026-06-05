"""Tests for sentinel.tools.frida_runner.load_runtime_hooks.

These tests don't touch Node.js or the real compiled agent — they
manipulate the module-level _AGENT_PATH so we can simulate both the
"agent present" and "agent missing" cases deterministically.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.tools import frida_runner


@pytest.fixture
def restore_agent_path():
    """Snapshot/restore frida_runner._AGENT_PATH around each test."""
    original = frida_runner._AGENT_PATH
    yield
    frida_runner._AGENT_PATH = original


def test_load_runtime_hooks_returns_file_content(tmp_path, restore_agent_path):
    """When the compiled agent exists on disk, return its contents verbatim."""
    fake_agent = tmp_path / "_agent.js"
    sentinel_marker = "/* SENTINEL TEST AGENT MARKER */"
    fake_agent.write_text(sentinel_marker + "\nconsole.log('hi');\n")
    frida_runner._AGENT_PATH = fake_agent

    out = frida_runner.load_runtime_hooks()
    assert sentinel_marker in out
    assert "console.log('hi');" in out


def test_load_runtime_hooks_falls_back_when_missing(
    tmp_path, restore_agent_path, caplog,
):
    """When the agent file is absent, return the inline fallback and warn."""
    missing = tmp_path / "does_not_exist" / "_agent.js"
    assert not missing.exists()
    frida_runner._AGENT_PATH = missing

    with caplog.at_level("WARNING"):
        out = frida_runner.load_runtime_hooks()

    # Fallback marker check: the fallback script declares the
    # `crypto.hooks_installed` event with `fallback: true`
    assert "fallback" in out
    assert "Cipher.getInstance" in out

    # Warning should mention the build instructions
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any(
        "npm run build" in m or "Build the agent" in m for m in warnings
    )


def test_load_runtime_hooks_no_node_dependency(restore_agent_path):
    """Importing and calling the loader must not require Node.js to exist."""
    # Whatever the current _AGENT_PATH is (real or test), the function
    # must always return a non-empty string.
    out = frida_runner.load_runtime_hooks()
    assert isinstance(out, str)
    assert len(out) > 100


def test_all_runtime_hooks_is_string():
    """ALL_RUNTIME_HOOKS is the public alias the orchestrator imports."""
    assert isinstance(frida_runner.ALL_RUNTIME_HOOKS, str)
    assert len(frida_runner.ALL_RUNTIME_HOOKS) > 0


def test_agent_path_points_inside_frida_agent_dir():
    """Sanity: the resolved path points at frida_agent/dist/_agent.js."""
    p = Path(frida_runner._AGENT_PATH)
    parts = p.parts
    assert "frida_agent" in parts
    assert parts[-2:] == ("dist", "_agent.js")
