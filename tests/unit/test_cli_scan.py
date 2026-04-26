"""Unit tests for the CLI scan command — exercises Click without real APKs."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from sentinel.cli import main

# ---------- Smoke tests ----------

def test_cli_help():
    """`sentinel --help` lists subcommands."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "serve" in result.output
    assert "scope" in result.output
    assert "agents" in result.output
    assert "status" in result.output


def test_cli_version():
    """`sentinel --version` works."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_scan_help():
    """`sentinel scan --help` documents all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--scope-url" in result.output
    assert "--scope-file" in result.output
    assert "--scope-text" in result.output
    assert "--private" in result.output
    assert "--output" in result.output


def test_scan_requires_apk():
    """`sentinel scan` without an APK path fails."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code != 0


def test_scan_rejects_missing_apk(tmp_path):
    """`sentinel scan` with a non-existent APK fails cleanly."""
    runner = CliRunner()
    fake_apk = tmp_path / "does-not-exist.apk"
    result = runner.invoke(main, ["scan", str(fake_apk)])
    assert result.exit_code != 0


# ---------- scope subcommand ----------

def test_scope_parse_help():
    """`sentinel scope parse --help` works."""
    runner = CliRunner()
    result = runner.invoke(main, ["scope", "parse", "--help"])
    assert result.exit_code == 0
    assert "--url" in result.output
    assert "--file" in result.output
    assert "--text" in result.output


def test_scope_parse_no_input():
    """`sentinel scope parse` without any input flag errors out."""
    runner = CliRunner()
    result = runner.invoke(main, ["scope", "parse"])
    assert result.exit_code != 0


def test_scope_parse_inline_text():
    """`sentinel scope parse --text "..."` succeeds with valid input.

    The scope parser distinguishes packages from domains by checking if the
    first segment is a known reverse-DNS prefix (com, org, io, etc.).
    """
    runner = CliRunner()
    result = runner.invoke(main, [
        "scope", "parse",
        "--text",
        "Program: TestProgram\nIn scope: com.example.app, com.example.api\nOut of scope: com.example.test",
    ])
    if result.exit_code != 0:
        # Print diagnostic info if it fails so we know why
        print("STDOUT:", result.output)
        print("EXCEPTION:", result.exception)
    assert result.exit_code == 0


# ---------- status ----------

def test_status_command():
    """`sentinel status` always works (just prints config)."""
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "Workspace" in result.output


# ---------- agents (offline) ----------

def test_agents_command_without_gateway():
    """`sentinel agents` prints a friendly error when the gateway is down."""
    runner = CliRunner()

    # Force httpx.get to raise a connection error to simulate gateway down
    import httpx

    def fake_get(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch("httpx.get", side_effect=fake_get):
        result = runner.invoke(main, ["agents"])

    # Should NOT crash — should print friendly message and exit 0
    assert result.exit_code == 0, f"Expected 0, got {result.exit_code}. Output: {result.output}"
    assert "Cannot reach" in result.output or "gateway" in result.output.lower()
