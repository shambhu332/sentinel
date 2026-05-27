"""Unit tests for SemgrepAgent (SG_001).

Uses fixture Java files under tests/fixtures/semgrep/ — no APK
required. Tests that need the semgrep binary skip if it's absent so
CI without the dep can still run.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sentinel.agents.semgrep import SemgrepAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep"

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep binary not installed on this system",
)


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path: Path, *fixture_names: str) -> ScanContext:
    """Build a ScanContext whose decompiled_dir contains the named fixtures."""
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)
    for name in fixture_names:
        src = FIXTURES_DIR / name
        (decompiled / name).write_text(src.read_text())

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.manifest = {"package": "com.example.vuln"}
    return ctx


# ---------- 1: binary check ----------

def test_semgrep_binary_available():
    """If semgrep is installed at all, it must respond to --version."""
    binary = shutil.which("semgrep")
    if binary is None:
        pytest.skip("semgrep not installed")
    proc = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip()  # some version string


# ---------- 2: clean code ----------

@needs_semgrep
@pytest.mark.asyncio
async def test_agent_emits_no_findings_on_clean_code(memory, tmp_path):
    ctx = _make_ctx(tmp_path, "clean_code.java")
    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- 3: WebView addJavascriptInterface ----------

@needs_semgrep
@pytest.mark.asyncio
async def test_agent_detects_addjavascriptinterface(memory, tmp_path):
    ctx = _make_ctx(tmp_path, "vulnerable_webview.java")
    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert any(f.vuln_class == "WEBVIEW_JS_INTERFACE" for f in findings)


# ---------- 4: DES ----------

@needs_semgrep
@pytest.mark.asyncio
async def test_agent_detects_weak_crypto_des(memory, tmp_path):
    ctx = _make_ctx(tmp_path, "vulnerable_crypto.java")
    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # WEAK_CRYPTO comes from crypto-des / crypto-ecb-mode / crypto-md5 / sha1
    assert any(
        f.vuln_class == "WEAK_CRYPTO"
        and "crypto-des" in f.evidence.get("semgrep_rule_id", "")
        for f in findings
    )


# ---------- 5: MD5 ----------

@needs_semgrep
@pytest.mark.asyncio
async def test_agent_detects_md5(memory, tmp_path):
    ctx = _make_ctx(tmp_path, "vulnerable_crypto.java")
    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert any(
        "crypto-md5" in f.evidence.get("semgrep_rule_id", "")
        for f in findings
    )


# ---------- 6: missing binary ----------

@pytest.mark.asyncio
async def test_agent_handles_missing_binary(monkeypatch, memory, tmp_path, caplog):
    ctx = _make_ctx(tmp_path, "vulnerable_crypto.java")
    # Force shutil.which to report semgrep absent
    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.shutil.which",
        lambda _: None,
    )
    agent = SemgrepAgent(context=ctx, memory=memory)
    with caplog.at_level("WARNING"):
        findings = await agent.analyze()
    assert findings == []
    assert any("semgrep binary" in r.message for r in caplog.records)


# ---------- 7: timeout ----------

@pytest.mark.asyncio
async def test_agent_handles_timeout(monkeypatch, memory, tmp_path, caplog):
    ctx = _make_ctx(tmp_path, "vulnerable_crypto.java")

    def boom(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["semgrep"], timeout=1)

    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.shutil.which",
        lambda _: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.subprocess.run", boom,
    )

    agent = SemgrepAgent(context=ctx, memory=memory)
    with caplog.at_level("WARNING"):
        findings = await agent.analyze()
    assert findings == []
    assert any("timed out" in r.message for r in caplog.records)


# ---------- 8: malformed JSON ----------

@pytest.mark.asyncio
async def test_agent_handles_malformed_json(monkeypatch, memory, tmp_path, caplog):
    ctx = _make_ctx(tmp_path, "vulnerable_crypto.java")

    class _FakeProc:
        returncode = 0
        stdout = "{this is not valid json"
        stderr = ""

    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.shutil.which",
        lambda _: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.subprocess.run",
        lambda *a, **kw: _FakeProc(),
    )

    agent = SemgrepAgent(context=ctx, memory=memory)
    with caplog.at_level("WARNING"):
        findings = await agent.analyze()
    assert findings == []
    assert any("not valid JSON" in r.message for r in caplog.records)


# ---------- 9: schema compliance ----------

@needs_semgrep
@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path, "vulnerable_webview.java", "vulnerable_crypto.java")
    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings  # otherwise we're not testing anything
    for f in findings:
        assert f.agent_id == "SG_001"
        assert f.vuln_class
        assert isinstance(f.severity, Severity)
        assert 0.0 <= f.confidence <= 1.0
        assert f.recommendation
        # evidence holds file/line/rule-id
        assert "file" in f.evidence
        assert "line" in f.evidence
        assert "semgrep_rule_id" in f.evidence
        assert f.session_id == ctx.session_id


# ---------- 10: severity mapping ----------

@pytest.mark.asyncio
async def test_severity_mapping_explicit():
    """sentinel_severity in metadata overrides everything else."""
    # CRITICAL
    sev = SemgrepAgent._severity_for(
        {"sentinel_severity": "CRITICAL"}, {"extra": {"severity": "INFO"}},
    )
    assert sev == Severity.CRITICAL
    # HIGH
    assert SemgrepAgent._severity_for(
        {"sentinel_severity": "HIGH"}, {},
    ) == Severity.HIGH
    # MEDIUM, LOW, INFO
    assert SemgrepAgent._severity_for(
        {"sentinel_severity": "MEDIUM"}, {},
    ) == Severity.MEDIUM
    assert SemgrepAgent._severity_for(
        {"sentinel_severity": "LOW"}, {},
    ) == Severity.LOW
    assert SemgrepAgent._severity_for(
        {"sentinel_severity": "INFO"}, {},
    ) == Severity.INFO


@pytest.mark.asyncio
async def test_severity_mapping_fallback():
    """Without sentinel_severity, fall back to semgrep ERROR/WARNING/INFO."""
    assert SemgrepAgent._severity_for(
        {}, {"extra": {"severity": "ERROR"}},
    ) == Severity.HIGH
    assert SemgrepAgent._severity_for(
        {}, {"extra": {"severity": "WARNING"}},
    ) == Severity.MEDIUM
    assert SemgrepAgent._severity_for(
        {}, {"extra": {"severity": "INFO"}},
    ) == Severity.LOW
    # Unknown -> Medium
    assert SemgrepAgent._severity_for(
        {}, {"extra": {"severity": "??"}},
    ) == Severity.MEDIUM


# ---------- bonus: confidence clamp ----------

def test_confidence_parser_handles_strings_and_clamp():
    assert SemgrepAgent._confidence_for({"sentinel_confidence": "0.85"}) == 0.85
    assert SemgrepAgent._confidence_for({"sentinel_confidence": 1.5}) == 1.0
    assert SemgrepAgent._confidence_for({"sentinel_confidence": -0.5}) == 0.0
    assert SemgrepAgent._confidence_for({"sentinel_confidence": "junk"}) == 0.65
    assert SemgrepAgent._confidence_for({}) == 0.65


# ---------- bonus: is_applicable ----------

@pytest.mark.asyncio
async def test_is_applicable_without_decompiled(memory, tmp_path):
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    # No decompiled_dir set
    agent = SemgrepAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- bonus: empty results parses cleanly ----------

@pytest.mark.asyncio
async def test_agent_handles_empty_results(monkeypatch, memory, tmp_path):
    ctx = _make_ctx(tmp_path, "clean_code.java")

    class _FakeProc:
        returncode = 0
        stdout = json.dumps({"results": [], "errors": []})
        stderr = ""

    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.shutil.which",
        lambda _: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "sentinel.agents.semgrep.semgrep_agent.subprocess.run",
        lambda *a, **kw: _FakeProc(),
    )

    agent = SemgrepAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []
