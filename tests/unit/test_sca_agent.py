"""Unit tests for SCA_001 (SCAAgent) — Supply Chain Vulnerability Scanner.

Tests cover all three detection tiers, semver range matching boundaries,
CVSS → Severity mapping, and the documented failure modes (missing DB,
malformed pom.properties, corrupt APK).

No network access. A hand-crafted sample OSV SQLite is materialised
into the test's tmp_path by build_sample_db().
"""
from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

from sentinel.agents.supply_chain import SCAAgent
from sentinel.agents.supply_chain.sca_agent import (
    DetectedLibrary,
    _severity_for_cvss,
    _version_in_any_range,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "sca"
POMS_DIR = FIXTURES_DIR / "poms"


# ---------- Fixture helpers ----------

def _load_build_sample_db():
    """Import the sample-DB builder from tests/fixtures/sca/."""
    spec = importlib.util.spec_from_file_location(
        "_sca_sample_db",
        FIXTURES_DIR / "build_sample_db.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.build_sample_db


def _make_fake_apk(path: Path, entries: dict[str, str]) -> Path:
    """Build a minimal valid zip at `path` containing the given entries."""
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def _pom_text(name: str) -> str:
    return (POMS_DIR / name).read_text()


def _make_ctx(
    tmp_path: Path,
    apk_entries: dict[str, str] | None = None,
    *,
    decompiled: dict[str, str] | None = None,
) -> ScanContext:
    """Build a ScanContext with the requested in-APK + decompiled layout."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    apk = tmp_path / "fake.apk"
    _make_fake_apk(apk, apk_entries or {"AndroidManifest.xml": ""})

    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)

    decompiled_dir: Path | None = None
    if decompiled:
        decompiled_dir = ws / "decompiled"
        decompiled_dir.mkdir(parents=True)
        for rel, body in decompiled.items():
            p = decompiled_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if decompiled_dir is not None:
        ctx.decompiled_dir = decompiled_dir
    ctx.manifest = {"package": "com.example.test"}
    return ctx


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def sample_db(tmp_path) -> Path:
    """Materialise the sample OSV DB into the test's tmp dir."""
    build_sample_db = _load_build_sample_db()
    return build_sample_db(tmp_path / "osv_sample.sqlite")


# ---------- 1: pom.properties extraction ----------

async def test_pom_properties_parsing_extracts_coordinate(memory, tmp_path):
    """Tier 1 extracts groupId:artifactId:version from a single pom.properties."""
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties":
            _pom_text("okhttp_3_12_0.properties"),
    })
    agent = SCAAgent(context=ctx, memory=memory)
    libs = agent._extract_libraries()
    assert len(libs) == 1
    assert libs[0].group_id == "com.squareup.okhttp3"
    assert libs[0].artifact_id == "okhttp"
    assert libs[0].version == "3.12.0"
    assert libs[0].source == "pom.properties"
    assert libs[0].confidence == pytest.approx(0.95)


# ---------- 2: okhttp 3.12.0 matched against known CVE ----------

async def test_okhttp_3_12_0_matched_against_known_cve(
    memory, tmp_path, sample_db,
):
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties":
            _pom_text("okhttp_3_12_0.properties"),
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    okhttp_findings = [
        f for f in findings
        if f.evidence.get("library") == "com.squareup.okhttp3:okhttp"
    ]
    assert len(okhttp_findings) == 1
    f = okhttp_findings[0]
    assert f.evidence["cve"] == "CVE-2021-0341"
    assert f.evidence["fixed_version"] == "4.9.2"
    assert f.evidence["version"] == "3.12.0"
    assert f.confidence == pytest.approx(0.95)
    assert f.severity == Severity.HIGH  # CVSS 7.5
    assert "Upgrade" in f.recommendation


# ---------- 3: okhttp 4.12.0 (patched) → no finding ----------

async def test_okhttp_4_12_0_patched_no_finding(
    memory, tmp_path, sample_db,
):
    """Version above fixed_version (4.9.2) must NOT match the CVE."""
    pom = _pom_text("okhttp_3_12_0.properties").replace(
        "version=3.12.0", "version=4.12.0",
    )
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties": pom,
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert findings == []


# ---------- 4: unknown-version library → LOW-confidence finding ----------

async def test_unknown_version_library_low_confidence_finding(
    memory, tmp_path, sample_db,
):
    """Tier-3 classpath match: no version recoverable, LOW confidence."""
    # No pom.properties, no version-marker — only a decompiled directory
    # tree exposing the fingerprint path.
    ctx = _make_ctx(
        tmp_path,
        apk_entries={"AndroidManifest.xml": ""},
        decompiled={
            "org/apache/commons/lang3/Stub.java": "package org.apache.commons.lang3;\nclass Stub {}\n",
        },
    )
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert findings, "expected a tier-3 LOW finding"
    f = findings[0]
    assert f.evidence["version"] == "UNKNOWN"
    assert f.evidence["detection_method"] == "classpath"
    assert f.confidence == pytest.approx(0.40)
    assert f.severity == Severity.CRITICAL  # CVSS 9.8 in sample


# ---------- 5: missing DB → empty findings + warning ----------

async def test_missing_db_returns_empty_with_warning(
    memory, tmp_path, caplog,
):
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties":
            _pom_text("okhttp_3_12_0.properties"),
    })
    nonexistent = tmp_path / "does-not-exist.sqlite"
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(nonexistent)},
    )
    with caplog.at_level("WARNING"):
        findings = await agent.analyze()
    assert findings == []
    assert any(
        "OSV CVE database not found" in r.message for r in caplog.records
    )


# ---------- 6: malformed pom.properties → skip, continue ----------

async def test_malformed_pom_properties_skipped_others_processed(
    memory, tmp_path, sample_db,
):
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/junk/junk/pom.properties":
            _pom_text("malformed.properties"),
        "META-INF/maven/com.google.code.gson/gson/pom.properties":
            _pom_text("gson_2_8_5.properties"),
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert any(
        f.evidence["cve"] == "CVE-2022-25647" for f in findings
    ), "gson should still be detected despite the malformed sibling pom"


# ---------- 7: semver boundary — fixed-version is exclusive ----------

def test_semver_boundary_exclusive_fixed():
    """version == fixed_version → NOT vulnerable; < fixed → vulnerable."""
    ranges = [{
        "type": "ECOSYSTEM",
        "events": [{"introduced": "0"}, {"fixed": "1.5.0"}],
    }]
    assert _version_in_any_range("1.4.99", ranges) is True
    assert _version_in_any_range("1.5.0", ranges) is False
    assert _version_in_any_range("1.5.1", ranges) is False


# ---------- 8: semver boundary — introduced-version is inclusive ----------

def test_semver_boundary_inclusive_introduced():
    """version == introduced → vulnerable; < introduced → NOT vulnerable."""
    ranges = [{
        "type": "ECOSYSTEM",
        "events": [{"introduced": "1.2.0"}, {"fixed": "1.5.0"}],
    }]
    assert _version_in_any_range("1.2.0", ranges) is True
    assert _version_in_any_range("1.1.99", ranges) is False
    assert _version_in_any_range("1.2.1", ranges) is True


# ---------- 9: CVSS → Severity mapping table ----------

def test_cvss_to_severity_mapping():
    # ≥ 9.0 → Critical
    assert _severity_for_cvss(10.0) == Severity.CRITICAL
    assert _severity_for_cvss(9.0) == Severity.CRITICAL
    # ≥ 7.0 → High
    assert _severity_for_cvss(8.9) == Severity.HIGH
    assert _severity_for_cvss(7.0) == Severity.HIGH
    # ≥ 4.0 → Medium
    assert _severity_for_cvss(6.9) == Severity.MEDIUM
    assert _severity_for_cvss(4.0) == Severity.MEDIUM
    # < 4.0 → Low
    assert _severity_for_cvss(3.9) == Severity.LOW
    assert _severity_for_cvss(0.0) == Severity.LOW


# ---------- 10: finding schema compliance ----------

async def test_finding_schema_compliance(memory, tmp_path, sample_db):
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties":
            _pom_text("okhttp_3_12_0.properties"),
        "META-INF/maven/com.google.code.gson/gson/pom.properties":
            _pom_text("gson_2_8_5.properties"),
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert findings  # otherwise we're asserting against nothing
    for f in findings:
        assert f.agent_id == "SCA_001"
        assert f.vuln_class == "VULNERABLE_DEPENDENCY"
        assert isinstance(f.severity, Severity)
        assert 0.0 <= f.confidence <= 1.0
        assert f.recommendation
        assert f.session_id == ctx.session_id
        # evidence required fields per spec
        assert "library" in f.evidence
        assert "version" in f.evidence
        assert "cve" in f.evidence
        assert "cvss" in f.evidence
        assert "osv_id" in f.evidence
        assert "fixed_version" in f.evidence
        assert "detection_method" in f.evidence
        # OWASP + MASVS classifications populated
        assert f.owasp and "Outdated" in f.owasp
        assert f.masvs == "MSTG-CODE-5"


# ---------- 11: clean library — no CVE row → no finding ----------

async def test_clean_recent_library_no_finding(
    memory, tmp_path, sample_db,
):
    """A library coordinate with NO row in the DB produces no finding."""
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.example.cleanlib/cleanlib-core/pom.properties":
            _pom_text("cleanlib_5_0_0.properties"),
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert findings == []


# ---------- 12: version-marker tier-2 detection ----------

async def test_version_marker_tier_detection(
    memory, tmp_path, sample_db,
):
    """No pom.properties — okhttp version recovered from decompiled marker."""
    ctx = _make_ctx(
        tmp_path,
        apk_entries={"AndroidManifest.xml": ""},
        decompiled={
            "okhttp/internal/Version.java": (
                "package okhttp.internal;\n"
                "class Version {\n"
                '    static final String UA = "okhttp/3.12.0";\n'
                "}\n"
            ),
        },
    )
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    okhttp = [
        f for f in findings
        if f.evidence.get("library") == "com.squareup.okhttp3:okhttp"
    ]
    assert okhttp, "tier-2 marker should detect okhttp 3.12.0"
    f = okhttp[0]
    assert f.evidence["detection_method"] == "version-marker"
    assert f.confidence == pytest.approx(0.80)
    assert f.evidence["version"] == "3.12.0"


# ---------- 13: corrupt APK → graceful empty findings ----------

async def test_corrupt_apk_zip_does_not_crash(memory, tmp_path, sample_db):
    apk = tmp_path / "corrupt.apk"
    apk.write_bytes(b"not a real zip file at all")
    ws = tmp_path / "ws"
    ws.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.manifest = {"package": "com.example.test"}
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    # Returns [] without raising
    findings = await agent.analyze()
    assert findings == []


# ---------- 14: is_applicable gate ----------

async def test_is_applicable_when_apk_present(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    agent = SCAAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- 15: edge-lib boundary semver verification end-to-end ----------

async def test_edge_lib_semver_end_to_end(memory, tmp_path, sample_db):
    """Range [1.2.0, 1.5.0): 1.3.0 IN; 1.1.9 OUT; 1.5.0 OUT."""
    # IN-range version
    pom_in = (
        "groupId=com.example.edge\n"
        "artifactId=edge-lib\n"
        "version=1.3.0\n"
    )
    ctx = _make_ctx(tmp_path, apk_entries={
        "META-INF/maven/com.example.edge/edge-lib/pom.properties": pom_in,
    })
    agent = SCAAgent(
        context=ctx, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    findings = await agent.analyze()
    assert any(f.evidence["cve"] == "CVE-EDGE-001" for f in findings)

    # OUT-of-range below
    pom_below = pom_in.replace("1.3.0", "1.1.9")
    ctx2 = _make_ctx(
        tmp_path / "below",
        apk_entries={
            "META-INF/maven/com.example.edge/edge-lib/pom.properties":
                pom_below,
        },
    )
    agent2 = SCAAgent(
        context=ctx2, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    assert await agent2.analyze() == []

    # OUT-of-range at exclusive fixed boundary
    pom_at_fixed = pom_in.replace("1.3.0", "1.5.0")
    ctx3 = _make_ctx(
        tmp_path / "atfixed",
        apk_entries={
            "META-INF/maven/com.example.edge/edge-lib/pom.properties":
                pom_at_fixed,
        },
    )
    agent3 = SCAAgent(
        context=ctx3, memory=memory,
        config={"osv_db_path": str(sample_db)},
    )
    assert await agent3.analyze() == []


# ---------- 16: DetectedLibrary coordinate is lowercase ----------

def test_detected_library_coordinate_normalizes_case():
    lib = DetectedLibrary(
        group_id="COM.Example.Foo",
        artifact_id="Bar",
        version="1.0.0",
        source="pom.properties",
        confidence=0.95,
    )
    assert lib.coordinate == "com.example.foo:bar"
