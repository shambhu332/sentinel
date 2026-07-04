"""Unit tests for sentinel.exploit.poc_generator."""
from __future__ import annotations

import stat
from pathlib import Path

import pytest

from sentinel.core.finding import Finding, Severity
from sentinel.exploit.poc_generator import (
    ARTIFACTS_DIR_NAME,
    PoCArtifact,
    PoCGenerator,
)


# ---------- Fixtures ----------

@pytest.fixture
def workspace(tmp_path) -> Path:
    return tmp_path


def _api_finding() -> Finding:
    return Finding(
        agent_id="API_002",
        vuln_class="Broken Object Level Authorization",
        severity=Severity.CRITICAL,
        confidence=0.9,
        recommendation="Enforce object-level authz.",
        session_id="abcdefgh",
        evidence={
            "host": "api.example.com",
            "endpoint": "/v1/users/42",
            "method": "GET",
            "scheme": "https",
            "auth_header_names": ["Authorization"],
        },
    )


def _deep_link_finding() -> Finding:
    return Finding(
        agent_id="P_001",
        vuln_class="Deep Link Hijack",
        severity=Severity.HIGH,
        confidence=0.85,
        recommendation="Verify Intent origin before handling.",
        session_id="abcdefgh",
        evidence={"package": "com.acme.app"},
    )


def _token_finding() -> Finding:
    return Finding(
        agent_id="C_010",
        vuln_class="JWT Storage Weakness",
        severity=Severity.HIGH,
        confidence=0.8,
        recommendation="Store tokens in Keystore.",
        session_id="abcdefgh",
        evidence={"storage_key": "access_token"},
    )


# ---------- Directory scaffolding ----------

def test_generator_creates_artifacts_dir(workspace):
    gen = PoCGenerator(workspace)
    assert (workspace / ARTIFACTS_DIR_NAME).is_dir()
    # Idempotent — re-instantiating must not blow up if the dir exists.
    PoCGenerator(workspace)


# ---------- Python (requests) template ----------

def test_python_requests_emits_valid_script(workspace):
    gen = PoCGenerator(workspace)
    art = gen.python_requests(_api_finding(), hint={
        "url": "https://api.example.com/v1/users/43",
        "method": "GET",
        "auth_header_names": ["Authorization"],
    })
    assert isinstance(art, PoCArtifact)
    assert art.kind == "python_requests"
    assert art.relative_path.startswith(f"{ARTIFACTS_DIR_NAME}/")
    body = art.absolute_path.read_text()
    assert body.startswith("#!/usr/bin/env python3")
    assert "AUTHORIZED USE ONLY" in body
    assert "requests" in body
    assert "https://api.example.com/v1/users/43" in body
    # Auth header appears with a placeholder — never the raw token.
    assert '<paste Authorization value here>' in body
    assert "time.sleep(1.0)" in body  # rate limit enforced in template


def test_python_requests_serialises_dict_payload(workspace):
    gen = PoCGenerator(workspace)
    art = gen.python_requests(_api_finding(), hint={
        "mutated_payload": {"is_admin": True},
        "method": "POST",
    })
    body = art.absolute_path.read_text()
    assert '"is_admin": true' in body  # JSON-encoded, not Python-repr'd
    assert "METHOD = " in body


# ---------- ADB Bash template ----------

def test_adb_bash_is_executable_and_uses_intent(workspace):
    gen = PoCGenerator(workspace)
    art = gen.adb_bash(_deep_link_finding(), hint={
        "package": "com.acme.app",
        "payload_url": "acme://x/exfil?next=http://127.0.0.1:8888/beacon",
    })
    assert art.kind == "adb_bash"
    mode = art.absolute_path.stat().st_mode
    # Owner-executable bit set.
    assert mode & stat.S_IXUSR
    body = art.absolute_path.read_text()
    assert body.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in body
    assert "am start" in body
    assert "com.acme.app" in body
    assert "acme://x/exfil?next=http://127.0.0.1:8888/beacon" in body


def test_adb_bash_shell_escapes_single_quotes(workspace):
    gen = PoCGenerator(workspace)
    art = gen.adb_bash(_deep_link_finding(), hint={
        "package": "com.acme.app",
        "payload_url": "custom://it's/tricky",
    })
    body = art.absolute_path.read_text()
    # Correct POSIX shell escaping is '\'' (close quote + escaped quote + reopen).
    assert "it'\\''s" in body


# ---------- Frida JS template ----------

def test_frida_js_hooks_token_manager_and_shared_prefs(workspace):
    gen = PoCGenerator(workspace)
    art = gen.frida_js(_token_finding(), hint={
        "forged_token": "eyJhbGciOiJub25lIn0.forged.",
        "storage_key": "access_token",
        "token_manager_class": "com.acme.TokenManager",
    })
    assert art.kind == "frida_js"
    body = art.absolute_path.read_text()
    assert body.startswith("// SENTINEL PoC")
    assert "Java.perform" in body
    assert "com.acme.TokenManager" in body
    assert "getAccessToken.implementation" in body
    assert "SharedPreferencesImpl" in body
    assert "access_token" in body


# ---------- Dispatch ----------

def test_generate_for_api_finding_yields_python_only(workspace):
    gen = PoCGenerator(workspace)
    arts = gen.generate_for(_api_finding())
    kinds = {a.kind for a in arts}
    assert kinds == {"python_requests"}


def test_generate_for_deep_link_finding_yields_bash(workspace):
    gen = PoCGenerator(workspace)
    arts = gen.generate_for(_deep_link_finding())
    kinds = {a.kind for a in arts}
    assert "adb_bash" in kinds


def test_generate_for_token_finding_yields_frida(workspace):
    gen = PoCGenerator(workspace)
    arts = gen.generate_for(_token_finding())
    kinds = {a.kind for a in arts}
    assert "frida_js" in kinds


def test_relative_paths_match_workspace(workspace):
    gen = PoCGenerator(workspace)
    arts = gen.generate_for(_api_finding())
    for art in arts:
        # Frontend "Download PoC" URL joins session_id + relative_path,
        # so the path MUST be relative to the workspace root, not absolute.
        assert not Path(art.relative_path).is_absolute()
        assert art.relative_path.startswith(f"{ARTIFACTS_DIR_NAME}/")
        assert art.absolute_path.exists()
