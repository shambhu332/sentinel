"""Unit tests for the verify engine and bundled verifiers.

Verifiers are exercised against fixture ``ScanContext`` instances —
no device, no Frida server, no mitmdump process required.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.verify import (
    VerificationOutcome,
    VerifierContext,
    VerifyEngine,
)
from sentinel.verify.verifiers.frida import (
    RuntimeCryptoVerifier,
    TlsPinningBypassVerifier,
)
from sentinel.verify.verifiers.manifest import (
    BackupRulesVerifier,
    DebuggableManifestVerifier,
    ExcessivePermissionsVerifier,
    InsecureFileProviderVerifier,
)
from sentinel.verify.verifiers.mitm import CleartextTrafficVerifier


# ---------- fixtures ----------


def _ctx(tmp_path, *, resources=False):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    scan = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if resources:
        res = ws / "resources"
        (res / "res" / "xml").mkdir(parents=True)
        scan.resources_dir = res
    return scan


def _finding(**overrides) -> Finding:
    defaults = {
        "agent_id": "META_002",
        "vuln_class": "Debuggable Release Build",
        "severity": Severity.CRITICAL,
        "confidence": 0.99,
        "evidence": {"package": "com.x"},
        "recommendation": "Set debuggable=false.",
        "session_id": generate_session_id(),
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ---------- engine ----------


@pytest.mark.asyncio
async def test_engine_returns_unsupported_when_no_verifier(tmp_path):
    engine = VerifyEngine()
    finding = _finding(agent_id="UNKNOWN_001")
    result = await engine.verify(finding, _ctx(tmp_path))
    assert result.outcome == VerificationOutcome.UNSUPPORTED
    assert "no verifier" in result.notes


@pytest.mark.asyncio
async def test_engine_persists_result_into_evidence(tmp_path):
    engine = VerifyEngine()
    engine.register(DebuggableManifestVerifier())
    scan = _ctx(tmp_path)
    scan.manifest = {"package": "com.x", "debuggable": True}
    finding = _finding(agent_id="META_002")
    await engine.verify_all([finding], scan)
    persisted = finding.evidence.get("_verify")
    assert persisted is not None
    assert persisted["outcome"] == "verified"


@pytest.mark.asyncio
async def test_engine_catches_verifier_exception(tmp_path):
    class Boom:
        AGENT_IDS = ("X_001",)
        async def verify(self, f, c):
            raise RuntimeError("kaboom")

    engine = VerifyEngine()
    engine.register(Boom())
    finding = _finding(agent_id="X_001")
    result = await engine.verify(finding, _ctx(tmp_path))
    assert result.outcome == VerificationOutcome.UNSUPPORTED
    assert "kaboom" in result.notes


def test_engine_register_default_wires_all_shipped(tmp_path):
    engine = VerifyEngine()
    engine.register_default_verifiers()
    for agent_id in ("META_002", "P_005", "STG_007", "STG_009",
                     "N_002", "A_003", "N_005"):
        assert agent_id in engine.supported_agents


# ---------- META_002 ----------


@pytest.mark.asyncio
async def test_meta_002_verified_when_manifest_debuggable_true(tmp_path):
    scan = _ctx(tmp_path)
    scan.manifest = {"package": "com.x", "debuggable": True}
    result = await DebuggableManifestVerifier().verify(
        _finding(agent_id="META_002"), VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_meta_002_refuted_when_debuggable_false(tmp_path):
    scan = _ctx(tmp_path)
    scan.manifest = {"package": "com.x", "debuggable": False}
    result = await DebuggableManifestVerifier().verify(
        _finding(agent_id="META_002"), VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.REFUTED


# ---------- P_005 ----------


@pytest.mark.asyncio
async def test_p_005_verified_when_permission_in_manifest(tmp_path):
    scan = _ctx(tmp_path)
    scan.manifest = {
        "package": "com.x",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        ],
    }
    finding = _finding(
        agent_id="P_005",
        evidence={"permission": "android.permission.READ_SMS"},
    )
    result = await ExcessivePermissionsVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_p_005_refuted_when_permission_absent(tmp_path):
    scan = _ctx(tmp_path)
    scan.manifest = {
        "package": "com.x",
        "permissions": ["android.permission.INTERNET"],
    }
    finding = _finding(
        agent_id="P_005",
        evidence={"permission": "android.permission.READ_SMS"},
    )
    result = await ExcessivePermissionsVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.REFUTED


# ---------- STG_007 ----------


@pytest.mark.asyncio
async def test_stg_007_path_xml_verified(tmp_path):
    scan = _ctx(tmp_path, resources=True)
    xml_dir = scan.resources_dir / "res" / "xml"
    (xml_dir / "fp.xml").write_text(
        """<?xml version="1.0"?>
<paths>
  <root-path name="root" path="." />
</paths>
""",
    )
    finding = _finding(
        agent_id="STG_007",
        evidence={
            "file": "res/xml/fp.xml",
            "tag": "root-path",
            "path": ".",
        },
    )
    result = await InsecureFileProviderVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_stg_007_exported_provider_verified(tmp_path):
    scan = _ctx(tmp_path)
    scan.manifest = {
        "package": "com.x",
        "exported_components": [{
            "type": "provider",
            "name": "androidx.core.content.FileProvider",
            "explicitly_exported": True,
            "has_intent_filter": False,
            "permission": "",
        }],
    }
    finding = _finding(
        agent_id="STG_007",
        evidence={"provider": "androidx.core.content.FileProvider"},
    )
    result = await InsecureFileProviderVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_stg_007_refuted_when_xml_gone(tmp_path):
    scan = _ctx(tmp_path, resources=True)
    xml_dir = scan.resources_dir / "res" / "xml"
    (xml_dir / "fp.xml").write_text(
        """<?xml version="1.0"?>
<paths>
  <files-path name="shared" path="shared/" />
</paths>
""",
    )
    finding = _finding(
        agent_id="STG_007",
        evidence={
            "file": "res/xml/fp.xml",
            "tag": "root-path",
            "path": ".",
        },
    )
    result = await InsecureFileProviderVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.REFUTED


# ---------- STG_009 ----------


@pytest.mark.asyncio
async def test_stg_009_verified(tmp_path):
    scan = _ctx(tmp_path, resources=True)
    xml_dir = scan.resources_dir / "res" / "xml"
    (xml_dir / "br.xml").write_text(
        """<?xml version="1.0"?>
<full-backup-content>
  <include domain="sharedpref" path="auth.xml" />
</full-backup-content>
""",
    )
    finding = _finding(
        agent_id="STG_009",
        evidence={
            "file": "res/xml/br.xml",
            "domain": "sharedpref",
            "path": "auth.xml",
        },
    )
    result = await BackupRulesVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


# ---------- N_002 cleartext ----------


@dataclass
class _FakeFlow:
    method: str
    url: str
    scheme: str
    host: str


@dataclass
class _FakeMitmCapture:
    flows: list[_FakeFlow] = field(default_factory=list)


@pytest.mark.asyncio
async def test_n_002_verified_when_http_flow_present(tmp_path):
    scan = _ctx(tmp_path)
    scan.sources = {
        "mitmproxy": _FakeMitmCapture(flows=[
            _FakeFlow("GET", "http://api.example.com/me",
                      "http", "api.example.com"),
            _FakeFlow("GET", "https://other.example.com/x",
                      "https", "other.example.com"),
        ]),
    }
    finding = _finding(
        agent_id="N_002",
        evidence={"url": "http://api.example.com/me"},
    )
    result = await CleartextTrafficVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED
    assert result.evidence["cleartext_flow_count"] == 1


@pytest.mark.asyncio
async def test_n_002_unsupported_when_no_capture(tmp_path):
    scan = _ctx(tmp_path)
    result = await CleartextTrafficVerifier().verify(
        _finding(agent_id="N_002"), VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.UNSUPPORTED


@pytest.mark.asyncio
async def test_n_002_refuted_when_only_https(tmp_path):
    scan = _ctx(tmp_path)
    scan.sources = {
        "mitmproxy": _FakeMitmCapture(flows=[
            _FakeFlow("GET", "https://api.example.com/me",
                      "https", "api.example.com"),
        ]),
    }
    finding = _finding(
        agent_id="N_002",
        evidence={"url": "http://api.example.com/me"},
    )
    result = await CleartextTrafficVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.REFUTED


# ---------- A_003 runtime crypto ----------


@dataclass
class _FakeFridaEvent:
    kind: str
    payload: dict[str, Any]


@dataclass
class _FakeFridaCapture:
    events: list[_FakeFridaEvent] = field(default_factory=list)


@pytest.mark.asyncio
async def test_a_003_verified_when_algorithm_in_events(tmp_path):
    scan = _ctx(tmp_path)
    scan.sources = {"frida": _FakeFridaCapture(events=[
        _FakeFridaEvent("crypto.cipher", {"algorithm": "DES/ECB/NoPadding"}),
    ])}
    finding = _finding(
        agent_id="A_003",
        evidence={"algorithm": "des"},
    )
    result = await RuntimeCryptoVerifier().verify(
        finding, VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_a_003_unsupported_without_capture(tmp_path):
    scan = _ctx(tmp_path)
    result = await RuntimeCryptoVerifier().verify(
        _finding(agent_id="A_003", evidence={"algorithm": "des"}),
        VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.UNSUPPORTED


# ---------- N_005 pinning bypass ----------


@pytest.mark.asyncio
async def test_n_005_verified_when_bypass_event_present(tmp_path):
    scan = _ctx(tmp_path)
    scan.sources = {"frida": _FakeFridaCapture(events=[
        _FakeFridaEvent("tls.bypass", {"library": "OkHttp CertificatePinner"}),
    ])}
    result = await TlsPinningBypassVerifier().verify(
        _finding(agent_id="N_005"), VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_n_005_inconclusive_when_only_pin_checks(tmp_path):
    scan = _ctx(tmp_path)
    scan.sources = {"frida": _FakeFridaCapture(events=[
        _FakeFridaEvent("tls.pin_check", {"library": "OkHttp CertificatePinner"}),
    ])}
    result = await TlsPinningBypassVerifier().verify(
        _finding(agent_id="N_005"), VerifierContext(scan=scan),
    )
    assert result.outcome == VerificationOutcome.INCONCLUSIVE
