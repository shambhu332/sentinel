"""Contract tests for the Djini-parity verification pipeline.

Covers:
  - Finding model: new fields + derive_verification_state mapping
  - CredentialManager: env loading, real-user guard, auto_login outcomes
  - severity_rationale: LLM JSON parsing + fallback shape
  - dispatch_dynamic_targets: auth-gated routing populates the right
    Finding fields and skips the RPC
  - bucket_for_section: prefers verification_state over the free-form
    verification_status string
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.core.finding import (
    Finding,
    Severity,
    derive_verification_state,
)
from sentinel.tools.credential_manager import (
    AuthResult,
    CredentialManager,
    TestCredential,
)
from sentinel.llm.severity_rationale import (
    RationaleInput,
    _fallback_rationale,
    generate_auth_gated_rationale,
)


SESSION = "test-session-1234"


# --- Finding model ----------------------------------------------------------

def _base_finding(**overrides) -> Finding:
    payload = dict(
        session_id=SESSION,
        agent_id="D_074",
        vuln_class="Deep Link Scheme Confusion Probe",
        severity=Severity.HIGH,
        confidence=0.8,
        recommendation="x",
        evidence={
            "dynamic_target": True,
            "frida_payload": {"package": "com.example.app"},
            "package": "com.example.app",
        },
    )
    payload.update(overrides)
    return Finding(**payload)


def test_finding_accepts_djini_fields():
    f = _base_finding(
        verification_state="auth_gated",
        verification_status="Unverified due to auth gating — login required",
        blocking_state_screenshot="evidence/screenshots/d_074_auth_blocked_1.webp",
        test_credentials_used=True,
    )
    assert f.verification_state == "auth_gated"
    assert f.blocking_state_screenshot.endswith(".webp")
    assert f.test_credentials_used is True


def test_finding_rejects_invalid_verification_state():
    with pytest.raises(Exception):
        _base_finding(verification_state="totally_made_up")


def test_derive_verification_state_prefers_explicit_enum():
    f = _base_finding(
        verification_state="verified",
        verification_status="Code-level only",  # contradicts on purpose
    )
    assert derive_verification_state(f) == "verified"


def test_derive_verification_state_maps_legacy_strings():
    cases = {
        "Code-level only":                  "code_only",
        "Verified by LLM triage":           "verified",
        "Runtime-verified via Frida":       "verified",
        "Unverified at runtime — boom":     "runtime_failed",
        "LLM triage uncertain — needs DAST": "runtime_failed",
        "Unverified due to auth gating":    "auth_gated",
        "blocked by login activity":        "auth_gated",
        "":                                 None,
        "completely freeform sentence":     None,
    }
    for status, expected in cases.items():
        f = _base_finding(verification_status=status or None)
        assert derive_verification_state(f) == expected, status


# --- Bucket classifier ------------------------------------------------------

def test_bucket_classifier_prefers_state_over_status():
    from sentinel.agents.reporting.models import (
        BUCKET_AI_POWERED, BUCKET_STATIC_TOOL, FindingSection,
        bucket_for_section,
    )

    auth_gated = _base_finding(
        verification_state="auth_gated",
        verification_status="Code-level only",  # would be static_tool otherwise
    )
    assert bucket_for_section(FindingSection(finding=auth_gated)) == BUCKET_AI_POWERED

    static_only = _base_finding(
        verification_state="code_only",
        verification_status="Code-level only",
        evidence={"package": "com.example.app"},  # no dynamic_target hint
    )
    assert bucket_for_section(FindingSection(finding=static_only)) == BUCKET_STATIC_TOOL


# --- CredentialManager ------------------------------------------------------

def test_credential_manager_parses_env_file(tmp_path: Path):
    env = tmp_path / ".env.test"
    env.write_text(
        "# comment\n"
        "TEST_USER_ALPHA_USERNAME=alice@example.com\n"
        "TEST_USER_ALPHA_PASSWORD='hunter2'\n"
        "TEST_USER_BETA_USERNAME=bob.tester\n"
        "TEST_USER_BETA_PASSWORD=\"correct horse\"\n"
        "UNRELATED=ignored\n",
        encoding="utf-8",
    )
    cm = CredentialManager.from_env(workspace_root=tmp_path)
    assert set(cm.labels()) == {"ALPHA", "BETA"}
    assert cm.has_credentials


def test_credential_manager_rejects_real_looking_user(tmp_path: Path, caplog):
    env = tmp_path / ".env.test"
    env.write_text(
        # No TEST_/QA_/STAGING_ prefix on the *label*, real-domain user → reject.
        "TEST_USER_REAL_USERNAME=victim@gmail.com\n"
        "TEST_USER_REAL_PASSWORD=secret\n",
        encoding="utf-8",
    )
    cm = CredentialManager.from_env(workspace_root=tmp_path)
    # REAL doesn't start with TEST_/QA_/STAGING_/SANDBOX_ and the domain
    # is in the real-domain hint list, so it must be refused.
    assert cm.labels() == []


def test_test_credential_validates_username():
    with pytest.raises(ValueError):
        TestCredential("X", "has spaces", "p")
    with pytest.raises(ValueError):
        TestCredential("X", "ok", "p" * 1000)


def test_auto_login_no_credentials_returns_no_credentials():
    cm = CredentialManager()
    result = asyncio.run(cm.auto_login("com.example.app"))
    assert result.outcome == "no_credentials"
    assert result.credential_label is None


def test_auto_login_without_script_returns_auth_gated():
    cm = CredentialManager(
        credentials={
            "ALPHA": TestCredential("ALPHA", "alice", "hunter2"),
        },
    )
    result = asyncio.run(cm.auto_login("com.example.app"))
    assert result.outcome == "auth_gated"
    assert "no Frida login script" in result.reason
    assert result.credential_label == "ALPHA"


def test_auto_login_success_path():
    class FakeFrida:
        async def run_login_script(self, **kwargs):
            return True

    cm = CredentialManager(
        credentials={"T": TestCredential("T", "alice", "p")},
    )
    cm.register_login_script(
        "com.example.app",
        "send({event:'auth.ok'})",
    )
    result = asyncio.run(cm.auto_login("com.example.app", frida=FakeFrida()))
    assert result.outcome == "success"
    assert result.succeeded


def test_auto_login_script_crash_is_auth_gated():
    class CrashingFrida:
        async def run_login_script(self, **kwargs):
            raise RuntimeError("device disconnected")

    cm = CredentialManager(
        credentials={"T": TestCredential("T", "alice", "p")},
    )
    cm.register_login_script("com.example.app", "send({})")
    result = asyncio.run(cm.auto_login("com.example.app", frida=CrashingFrida()))
    assert result.outcome == "auth_gated"
    assert "device disconnected" in result.reason


# --- Severity rationale generator ------------------------------------------

def test_fallback_rationale_two_sentences():
    payload = RationaleInput(
        vuln_class="Deep Link Scheme Confusion",
        static_evidence={"hosts": ["example.com"]},
        observed_runtime_behavior="Redirected to LoginActivity",
        blocking_reason="auto-login script returned auth.fail",
    )
    rationale = _fallback_rationale(payload)
    # Djini-spec shape is one comma-joined sentence pair:
    #   "Dynamic exploitability was not confirmed because X, but
    #    the risk remains for authenticated users if Y."
    assert rationale.startswith("Dynamic exploitability was not confirmed")
    assert "but the risk remains for authenticated users" in rationale
    assert rationale.endswith(".")


def test_generate_uses_router_response():
    class StubRouter:
        async def query(self, **kwargs):
            return {
                "content": (
                    '{"rationale": "Dynamic exploitability was not '
                    'confirmed because the login gate blocked the probe, '
                    'but the risk remains for authenticated users if a '
                    'session reaches the deep-link handler."}'
                ),
            }

    payload = RationaleInput(
        vuln_class="Deep Link Scheme Confusion",
        static_evidence={},
        observed_runtime_behavior="LoginActivity",
        blocking_reason="auto-login auth.fail",
    )
    rationale = asyncio.run(
        generate_auth_gated_rationale(payload, router=StubRouter()),
    )
    assert "Dynamic exploitability was not confirmed" in rationale
    assert "but the risk remains" in rationale


def test_generate_falls_back_when_router_returns_garbage():
    class BadRouter:
        async def query(self, **kwargs):
            return {"content": "not json at all"}

    payload = RationaleInput(
        vuln_class="Deep Link Scheme Confusion",
        static_evidence={},
        observed_runtime_behavior="x",
        blocking_reason="y",
    )
    rationale = asyncio.run(
        generate_auth_gated_rationale(payload, router=BadRouter()),
    )
    assert rationale  # never empty


# --- Dispatcher auth-gated path --------------------------------------------

def test_dispatch_marks_auth_gated_without_firing_rpc(tmp_path: Path):
    """When auto_login fails, the dispatcher must NOT call frida.dispatch_rpc,
    must set verification_state='auth_gated' on the originating finding,
    flip test_credentials_used, and populate severity_rationale."""

    rpc_calls: list[str] = []

    class FakeFrida:
        async def dispatch_rpc(self, method, payload, timeout_s=30.0):
            rpc_calls.append(method)
            return SimpleNamespace(success=True, error=None, data={})

    class FakeAdb:
        async def capture_screenshot(self, **kwargs):
            return {
                "path": f"evidence/screenshots/{kwargs['filename']}_1.webp",
                "caption": kwargs.get("caption"),
                "step_index": kwargs.get("step_index"),
                "label": kwargs["filename"],
                "captured_at": "2026-06-23T20:48:00Z",
            }

    class AuthGatedCM:
        async def auto_login(self, package, *, frida=None, **_):
            return AuthResult(
                outcome="auth_gated",
                reason="login script not registered",
                credential_label="T",
            )

    # Stub the AdbRunner the dispatcher lazy-imports.
    import sentinel.tools.adb_runner as ar
    original = getattr(ar, "AdbRunner", None)
    ar.AdbRunner = FakeAdb  # type: ignore[assignment]
    try:
        from sentinel.core import dynamic_dispatch as dd

        f = _base_finding()
        result = asyncio.run(dd.dispatch_dynamic_targets(
            [f], FakeFrida(),
            session_id=SESSION, workspace=tmp_path,
            credential_manager=AuthGatedCM(),
        ))
    finally:
        if original is not None:
            ar.AdbRunner = original

    # No RPC fired — the auth gate short-circuited dispatch.
    assert rpc_calls == []
    # Per-finding state was lifted onto the Finding itself.
    assert f.verification_state == "auth_gated"
    assert f.test_credentials_used is True
    assert f.blocking_state_screenshot
    assert f.blocking_state_screenshot.endswith(".webp")
    assert f.severity_rationale
    assert "Dynamic exploitability was not confirmed" in f.severity_rationale
    # Dispatcher summary records the auth-gated result.
    assert any(r.get("auth_gated") for r in result["results"])


def test_dispatch_success_marks_state_verified(tmp_path: Path):
    """When the RPC succeeds, verification_state must end up 'verified'."""

    class FakeFrida:
        async def dispatch_rpc(self, method, payload, timeout_s=30.0):
            return SimpleNamespace(success=True, error=None, data={"ok": 1})

    class FakeAdb:
        async def capture_screenshot(self, **kwargs):
            return {
                "path": f"evidence/screenshots/{kwargs['filename']}_1.webp",
                "label": kwargs["filename"],
            }

    import sentinel.tools.adb_runner as ar
    original = getattr(ar, "AdbRunner", None)
    ar.AdbRunner = FakeAdb  # type: ignore[assignment]
    try:
        from sentinel.core import dynamic_dispatch as dd

        f = _base_finding()
        asyncio.run(dd.dispatch_dynamic_targets(
            [f], FakeFrida(),
            session_id=SESSION, workspace=tmp_path,
            # No credential manager → no auth gate.
        ))
    finally:
        if original is not None:
            ar.AdbRunner = original

    assert f.verification_state == "verified"
    assert f.test_credentials_used is False  # no CM → no attempt
