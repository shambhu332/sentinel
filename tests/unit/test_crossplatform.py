"""Unit tests for RN_001 (React Native) and FL_001 (Flutter) agents."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

import pytest

from sentinel.agents.crossplatform import FlutterAgent, ReactNativeAgent
from sentinel.agents.crossplatform.flutter_agent import (
    VC_FL_CLEARTEXT,
    VC_FL_SECRET,
    VC_FLUTTER_EXPERIMENTAL,
)
from sentinel.agents.crossplatform.rn_agent import (
    VC_CLEARTEXT,
    VC_DANGEROUS_HTML,
    VC_HERMES_LIMIT,
    VC_INSEC_STORAGE,
    VC_SECRET,
    VC_WV_XSS,
)
from sentinel.core.finding import BountyScope, Severity, TriageState
from sentinel.core.scan_context import ScanContext

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "crossplatform"


# ---------- Plumbing ----------

class _StubMemory:
    def __init__(self) -> None:
        self.findings: list[Any] = []
        self.events: list[dict] = []

    async def save_finding(self, f: Any) -> None:
        self.findings.append(f)

    async def publish_event(
        self, session_id: str, event_type: str, payload: dict,
    ) -> None:
        self.events.append({"type": event_type, "payload": payload})


def _make_ctx(tmp_path: Path, resources_dir: Path | None) -> ScanContext:
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    return ScanContext(
        session_id="xp_test_session",
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
        resources_dir=resources_dir,
    )


def _layout_rn_plain(tmp_path: Path) -> Path:
    """apktool-style resources_dir with a plain-JS index.android.bundle."""
    res = tmp_path / "resources"
    (res / "assets").mkdir(parents=True, exist_ok=True)
    (res / "lib" / "arm64-v8a").mkdir(parents=True, exist_ok=True)
    shutil.copy(
        FIXTURES_DIR / "plain_bundle.js",
        res / "assets" / "index.android.bundle",
    )
    return res


def _layout_rn_hermes(tmp_path: Path) -> Path:
    res = tmp_path / "resources"
    (res / "assets").mkdir(parents=True, exist_ok=True)
    shutil.copy(
        FIXTURES_DIR / "hermes_header.bin",
        res / "assets" / "index.android.bundle",
    )
    return res


def _layout_flutter(tmp_path: Path) -> Path:
    res = tmp_path / "resources"
    abi = res / "lib" / "arm64-v8a"
    abi.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        FIXTURES_DIR / "libapp_strings.so", abi / "libapp.so",
    )
    # Tiny fake libflutter.so — the agent just needs its presence.
    (abi / "libflutter.so").write_bytes(b"\x7fELF" + b"\x00" * 64)
    return res


def _layout_empty(tmp_path: Path) -> Path:
    res = tmp_path / "resources"
    res.mkdir(parents=True, exist_ok=True)
    return res


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =========================================================================
# RN_001 tests
# =========================================================================

def test_rn_plain_bundle_emits_expected_findings(tmp_path: Path) -> None:
    """Plain-JS bundle exercises every detector. Each category fires
    exactly once (deduped by category at the agent level)."""
    res = _layout_rn_plain(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})

    assert _run(agent.is_applicable()) is True
    findings = _run(agent.run())

    by_class: dict[str, list] = {}
    for f in findings:
        by_class.setdefault(f.vuln_class, []).append(f)

    # Hermes case must NOT fire on a plain bundle.
    assert VC_HERMES_LIMIT not in by_class

    assert VC_INSEC_STORAGE in by_class
    assert by_class[VC_INSEC_STORAGE][0].severity == Severity.HIGH
    # 'auth_token' and 'jwt' fire; 'theme_pref' must NOT.
    storage_hits = by_class[VC_INSEC_STORAGE][0].evidence["hits"]
    assert len(storage_hits) == 2
    keys = sorted(h["key"] for h in storage_hits)
    assert keys == ["auth_token", "jwt"]

    assert VC_CLEARTEXT in by_class
    # localhost, 10.0.2.2, and https:// must NOT fire — only the one
    # production http URL is reported.
    ct_hits = by_class[VC_CLEARTEXT][0].evidence["hits"]
    assert len(ct_hits) == 1
    assert "api.example.com" in ct_hits[0]["url"]

    assert VC_SECRET in by_class
    secret_labels = [f.evidence["title"] for f in by_class[VC_SECRET]]
    # AWS plus the Google/Firebase regex (same pattern, fires for both
    # labels — documented by-design behaviour).
    assert any("AWS Access Key ID" in t for t in secret_labels)
    assert any("Google API Key" in t for t in secret_labels)

    assert VC_WV_XSS in by_class
    wv = by_class[VC_WV_XSS][0]
    assert wv.severity == Severity.MEDIUM
    assert wv.confidence == pytest.approx(0.75)

    assert VC_DANGEROUS_HTML in by_class
    assert by_class[VC_DANGEROUS_HTML][0].severity == Severity.LOW


def test_rn_hermes_bundle_short_circuits(tmp_path: Path) -> None:
    """A bundle whose first 4 bytes are the Hermes magic must emit
    exactly one HERMES_BYTECODE_LIMITATION finding and no garbage from
    regex-scanning the binary."""
    res = _layout_rn_hermes(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    findings = _run(agent.run())

    assert len(findings) == 1
    assert findings[0].vuln_class == VC_HERMES_LIMIT
    assert findings[0].severity == Severity.INFO
    assert "Hermes" in findings[0].evidence["title"]
    assert "0xC61FBC03" in findings[0].evidence["magic"]


def test_rn_hermes_magic_is_correct_endianness() -> None:
    """Documentation guard: the magic constant in the agent module
    must equal 0xC61FBC03 little-endian — if it ever gets reversed
    silently, every Hermes bundle would slip through to the regex path."""
    from sentinel.agents.crossplatform.rn_agent import _HERMES_MAGIC
    assert _HERMES_MAGIC == bytes([0x03, 0xBC, 0x1F, 0xC6])
    assert int.from_bytes(_HERMES_MAGIC, "little") == 0xC61FBC03


def test_rn_not_applicable_when_neither_bundle_nor_lib(tmp_path: Path) -> None:
    res = _layout_empty(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    assert _run(agent.is_applicable()) is False
    assert _run(agent.run()) == []


def test_rn_not_applicable_when_resources_dir_missing(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path, None)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    assert _run(agent.is_applicable()) is False


def test_rn_native_libs_without_bundle_emits_missing_notice(
    tmp_path: Path,
) -> None:
    """When apktool extracts libreactnativejni.so but drops the bundle,
    the agent emits an RN_BUNDLE_MISSING finding rather than silently
    saying 'nothing to see here'."""
    res = tmp_path / "resources"
    abi = res / "lib" / "arm64-v8a"
    abi.mkdir(parents=True, exist_ok=True)
    (abi / "libreactnativejni.so").write_bytes(b"\x7fELF" + b"\x00" * 64)
    ctx = _make_ctx(tmp_path, res)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    findings = _run(agent.run())
    assert len(findings) == 1
    assert findings[0].vuln_class == "RN_BUNDLE_MISSING"


def test_rn_finding_schema_compliance(tmp_path: Path) -> None:
    """Every emitted Finding from the plain-bundle scan must satisfy the
    Finding schema — Pydantic validation already happened, this test
    asserts the required fields are populated."""
    res = _layout_rn_plain(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    findings = _run(agent.run())
    for f in findings:
        assert f.agent_id == "RN_001"
        assert f.vuln_class
        assert 0.0 < f.confidence <= 1.0
        assert f.recommendation
        assert f.session_id == "xp_test_session"
        assert f.triage == TriageState.UNREVIEWED
        assert isinstance(f.evidence, dict) and f.evidence


# =========================================================================
# FL_001 tests
# =========================================================================

def test_flutter_emits_experimental_notice_and_string_findings(
    tmp_path: Path,
) -> None:
    """The synthesized libapp.so fixture contains a cleartext URL,
    AWS-shaped key, and Google-shaped key. FL_001 must surface each
    plus the always-on experimental notice."""
    res = _layout_flutter(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = FlutterAgent(context=ctx, memory=_StubMemory(), config={})

    assert _run(agent.is_applicable()) is True
    findings = _run(agent.run())

    by_class: dict[str, list] = {}
    for f in findings:
        by_class.setdefault(f.vuln_class, []).append(f)

    # The experimental notice is mandatory.
    assert VC_FLUTTER_EXPERIMENTAL in by_class
    notice = by_class[VC_FLUTTER_EXPERIMENTAL][0]
    assert notice.severity == Severity.INFO
    assert "experimental" in notice.evidence["title"].lower()
    assert "FlutterEngine" in notice.evidence["framework_tokens_seen"]
    assert "coverage_disclosure" in notice.evidence

    assert VC_FL_CLEARTEXT in by_class
    ct = by_class[VC_FL_CLEARTEXT][0]
    assert ct.severity == Severity.MEDIUM
    # Confidence intentionally low because AOT string-scan is noisy.
    assert 0.4 <= ct.confidence <= 0.6
    assert any(
        "flutterdemo.example.com" in h["url"] for h in ct.evidence["hits"]
    )

    assert VC_FL_SECRET in by_class
    labels = sorted(f.evidence["title"] for f in by_class[VC_FL_SECRET])
    assert any("AWS Access Key ID" in t for t in labels)
    assert any("Google API Key" in t for t in labels)


def test_flutter_libflutter_only_still_emits_experimental_notice(
    tmp_path: Path,
) -> None:
    """libflutter.so present but libapp.so absent (an APK Flutter shipped
    without compiled Dart — rare but happens in plug-in libs). The
    agent must still emit the experimental notice and bail before any
    string-scan."""
    res = tmp_path / "resources"
    abi = res / "lib" / "arm64-v8a"
    abi.mkdir(parents=True, exist_ok=True)
    (abi / "libflutter.so").write_bytes(b"\x7fELF" + b"\x00" * 64)
    ctx = _make_ctx(tmp_path, res)
    agent = FlutterAgent(context=ctx, memory=_StubMemory(), config={})
    findings = _run(agent.run())
    assert len(findings) == 1
    assert findings[0].vuln_class == VC_FLUTTER_EXPERIMENTAL


def test_flutter_not_applicable_when_no_flutter_libs(tmp_path: Path) -> None:
    res = tmp_path / "resources"
    (res / "lib" / "arm64-v8a").mkdir(parents=True, exist_ok=True)
    # Non-Flutter native lib.
    (res / "lib" / "arm64-v8a" / "libcrypto.so").write_bytes(b"\x7fELF" + b"\x00" * 32)
    ctx = _make_ctx(tmp_path, res)
    agent = FlutterAgent(context=ctx, memory=_StubMemory(), config={})
    assert _run(agent.is_applicable()) is False
    assert _run(agent.run()) == []


def test_flutter_confidence_below_rn_for_same_pattern(tmp_path: Path) -> None:
    """The AWS-key pattern fires in both agents on the same byte string;
    FL_001's confidence must be strictly lower to reflect the higher
    false-positive rate of AOT-binary string scans."""
    res_rn = _layout_rn_plain(tmp_path / "rn")
    res_fl = _layout_flutter(tmp_path / "fl")

    rn = ReactNativeAgent(
        context=_make_ctx(tmp_path / "rn", res_rn),
        memory=_StubMemory(), config={},
    )
    fl = FlutterAgent(
        context=_make_ctx(tmp_path / "fl", res_fl),
        memory=_StubMemory(), config={},
    )
    rn_findings = _run(rn.run())
    fl_findings = _run(fl.run())

    rn_aws = next(
        f for f in rn_findings
        if f.vuln_class == VC_SECRET
        and "AWS Access Key ID" in f.evidence["title"]
    )
    fl_aws = next(
        f for f in fl_findings
        if f.vuln_class == VC_FL_SECRET
        and "AWS Access Key ID" in f.evidence["title"]
    )
    assert fl_aws.confidence < rn_aws.confidence


def test_flutter_finding_schema_compliance(tmp_path: Path) -> None:
    res = _layout_flutter(tmp_path)
    ctx = _make_ctx(tmp_path, res)
    agent = FlutterAgent(context=ctx, memory=_StubMemory(), config={})
    findings = _run(agent.run())
    for f in findings:
        assert f.agent_id == "FL_001"
        assert f.vuln_class
        assert 0.0 < f.confidence <= 1.0
        assert f.recommendation
        assert f.session_id == "xp_test_session"


# =========================================================================
# Cross-agent: vanilla Android APK should silence both agents
# =========================================================================

def test_vanilla_apk_layout_silences_both_agents(tmp_path: Path) -> None:
    """No RN bundle, no Flutter libs, just a plain Android resources
    tree → both agents must skip applicability and produce zero
    findings."""
    res = tmp_path / "resources"
    (res / "lib" / "arm64-v8a").mkdir(parents=True, exist_ok=True)
    (res / "assets").mkdir(parents=True, exist_ok=True)
    (res / "lib" / "arm64-v8a" / "libnative.so").write_bytes(
        b"\x7fELF" + b"\x00" * 200,
    )
    ctx = _make_ctx(tmp_path, res)
    rn = ReactNativeAgent(context=ctx, memory=_StubMemory(), config={})
    fl = FlutterAgent(context=ctx, memory=_StubMemory(), config={})
    assert _run(rn.is_applicable()) is False
    assert _run(fl.is_applicable()) is False
    assert _run(rn.run()) == []
    assert _run(fl.run()) == []


# ---------- Regex precision spot-checks ----------

def test_rn_sensitive_key_regex_negatives() -> None:
    from sentinel.agents.crossplatform.rn_agent import _SENSITIVE_KEY_RE
    for benign in ("theme", "locale", "fontSize", "stepCount", "userName"):
        assert _SENSITIVE_KEY_RE.search(benign) is None, benign


def test_rn_sensitive_key_regex_positives() -> None:
    from sentinel.agents.crossplatform.rn_agent import _SENSITIVE_KEY_RE
    for tok in ("auth_token", "jwt_v2", "refreshToken",
                "apiKey", "session_id", "PASSWORD"):
        assert _SENSITIVE_KEY_RE.search(tok), tok


def test_rn_cleartext_url_regex_excludes_emulator_hosts() -> None:
    """Pattern must skip localhost / 127.0.0.1 / 10.0.2.2 to avoid
    nagging on dev builds."""
    from sentinel.agents.crossplatform.rn_agent import _CLEARTEXT_URL_RE
    text = (
        'fetch("http://localhost:9000/x"); '
        'fetch("http://127.0.0.1/y"); '
        'fetch("http://10.0.2.2:3000/z"); '
        'fetch("http://prod.example.com/path");'
    )
    matches = list(_CLEARTEXT_URL_RE.finditer(text))
    assert len(matches) == 1
    assert "prod.example.com" in matches[0].group(1)
