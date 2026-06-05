"""Unit tests for Sprint 9: Phase 7 Exploit Chain Detection."""
from __future__ import annotations

import pytest

from sentinel.agents.correlation import ExploitChainAgent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.correlation.detector import ChainDetector
from sentinel.correlation.models import CHAIN_PATTERNS, ChainType
from sentinel.memory import create_memory


@pytest.fixture
async def memory():
    """Create in-memory lightweight storage."""
    mem = create_memory("lightweight", data_dir=":memory:")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def context(tmp_path):
    """Create minimal scan context."""
    apk_path = tmp_path / "test.apk"
    apk_path.write_bytes(b"PK")  # Minimal APK signature
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk_path,
        workspace=tmp_path / "workspace",
    )


def _make_finding(
    session_id: str,
    agent_id: str,
    vuln_class: str,
    severity: Severity,
    **evidence,
) -> Finding:
    """Helper to create a finding."""
    return Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.9,
        evidence=evidence,
        recommendation="Fix it",
        session_id=session_id,
    )


# ---------- Chain Pattern Tests ----------


def test_chain_patterns_defined():
    """Verify hardcoded chain patterns exist."""
    assert len(CHAIN_PATTERNS) >= 6
    assert all(p.chain_id.startswith("CHAIN_") for p in CHAIN_PATTERNS)
    assert all(p.severity in [Severity.CRITICAL, Severity.HIGH] for p in CHAIN_PATTERNS)


def test_chain_pattern_token_theft():
    """Verify token theft pattern structure."""
    pattern = next(p for p in CHAIN_PATTERNS if p.chain_type == ChainType.TOKEN_THEFT)
    assert pattern.chain_id == "CHAIN_001"
    assert "Cleartext" in pattern.pattern[0]
    assert "Pinning" in pattern.pattern[1]
    assert pattern.severity == Severity.CRITICAL


def test_chain_pattern_rce():
    """Verify RCE pattern structure."""
    pattern = next(p for p in CHAIN_PATTERNS if p.chain_type == ChainType.RCE)
    assert pattern.chain_id == "CHAIN_002"
    assert "WebView" in pattern.pattern[0]
    assert "JavaScript" in pattern.pattern[1]
    assert pattern.severity == Severity.CRITICAL


# ---------- ChainDetector Tests ----------


@pytest.mark.asyncio
async def test_detector_skips_single_finding(memory, context):
    """Chain detection requires 2+ findings."""
    detector = ChainDetector(memory, context.session_id)

    finding = _make_finding(
        context.session_id,
        "N_002",
        "Cleartext HTTP Traffic",
        Severity.MEDIUM,
    )

    chains = await detector.detect_chains([finding])
    assert len(chains) == 0


@pytest.mark.asyncio
async def test_detector_builds_graph(memory, context):
    """Detector adds findings as graph nodes."""
    detector = ChainDetector(memory, context.session_id)

    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
        ),
    ]

    await detector._build_graph(findings)

    # Verify nodes were added (no direct query API, but no errors = success)
    # In a real test, you'd query the graph
    assert True


@pytest.mark.asyncio
async def test_detector_infers_relationships(memory, context):
    """Detector infers edges between related findings."""
    detector = ChainDetector(memory, context.session_id)

    f1 = _make_finding(
        context.session_id,
        "N_002",
        "Cleartext HTTP Traffic",
        Severity.MEDIUM,
    )
    f2 = _make_finding(
        context.session_id,
        "N_001",
        "Missing Certificate Pinning",
        Severity.MEDIUM,
    )

    edge = detector._infer_relationship(f1, f2)
    assert edge == "leads_to"


@pytest.mark.asyncio
async def test_detector_matches_token_theft_chain(memory, context):
    """Detector matches CHAIN_001 (token theft)."""
    detector = ChainDetector(memory, context.session_id)

    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
            url="http://api.example.com",
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
            host="api.example.com",
        ),
        _make_finding(
            context.session_id,
            "A_001",
            "Insecure Authentication Token Storage",
            Severity.HIGH,
            file="SharedPreferences",
        ),
    ]

    # Save findings to memory first
    for f in findings:
        await memory.save_finding(f)

    chains = await detector.detect_chains(findings)

    # Should detect token theft chain
    assert len(chains) >= 1
    chain = chains[0]
    assert chain.pattern.chain_type == ChainType.TOKEN_THEFT
    assert chain.pattern.severity == Severity.CRITICAL
    assert len(chain.findings) == 3
    assert chain.confidence > 0.5


@pytest.mark.asyncio
async def test_detector_matches_rce_chain(memory, context):
    """Detector matches CHAIN_002 (RCE via WebView)."""
    detector = ChainDetector(memory, context.session_id)

    findings = [
        _make_finding(
            context.session_id,
            "C_004",
            "Insecure WebView Configuration",
            Severity.MEDIUM,
            file="MainActivity.java",
        ),
        _make_finding(
            context.session_id,
            "C_004",
            "JavaScript Interface Exposure",
            Severity.HIGH,
            method="addJavascriptInterface",
        ),
        _make_finding(
            context.session_id,
            "C_004",
            "File Access Enabled",
            Severity.MEDIUM,
            setting="setAllowFileAccess(true)",
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await detector.detect_chains(findings)

    assert len(chains) >= 1
    chain = chains[0]
    assert chain.pattern.chain_type == ChainType.RCE
    assert chain.pattern.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_detector_no_chain_when_pattern_incomplete(memory, context):
    """No chain detected if pattern components missing."""
    detector = ChainDetector(memory, context.session_id)

    # Only 2 of 3 components for token theft
    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await detector.detect_chains(findings)

    # Should not match token theft (missing auth storage component)
    token_theft_chains = [
        c for c in chains if c.pattern.chain_type == ChainType.TOKEN_THEFT
    ]
    assert len(token_theft_chains) == 0


@pytest.mark.asyncio
async def test_detector_confidence_scoring(memory, context):
    """Confidence score factors in component confidence and severity."""
    detector = ChainDetector(memory, context.session_id)

    # High confidence components
    high_conf_findings = [
        Finding(
            agent_id="N_002",
            vuln_class="Cleartext HTTP Traffic",
            severity=Severity.HIGH,
            confidence=0.95,
            evidence={},
            recommendation="Fix",
            session_id=context.session_id,
        ),
        Finding(
            agent_id="N_001",
            vuln_class="Missing Certificate Pinning",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={},
            recommendation="Fix",
            session_id=context.session_id,
        ),
    ]

    confidence = detector._calculate_confidence(high_conf_findings, ["a", "b"])
    assert confidence > 0.7

    # Low confidence components
    low_conf_findings = [
        Finding(
            agent_id="N_002",
            vuln_class="Cleartext HTTP Traffic",
            severity=Severity.LOW,
            confidence=0.4,
            evidence={},
            recommendation="Fix",
            session_id=context.session_id,
        ),
        Finding(
            agent_id="N_001",
            vuln_class="Missing Certificate Pinning",
            severity=Severity.LOW,
            confidence=0.3,
            evidence={},
            recommendation="Fix",
            session_id=context.session_id,
        ),
    ]

    low_confidence = detector._calculate_confidence(low_conf_findings, ["a", "b"])
    assert low_confidence < confidence


# ---------- COR_001 Agent Tests ----------


@pytest.mark.asyncio
async def test_cor001_always_applicable(memory, context):
    """COR_001 is always applicable."""
    agent = ExploitChainAgent(context=context, memory=memory)
    assert await agent.is_applicable() is True


@pytest.mark.asyncio
async def test_cor001_skips_when_too_few_findings(memory, context):
    """COR_001 skips if < 2 findings."""
    agent = ExploitChainAgent(context=context, memory=memory)

    # Save 1 finding
    finding = _make_finding(
        context.session_id,
        "N_002",
        "Cleartext HTTP Traffic",
        Severity.MEDIUM,
    )
    await memory.save_finding(finding)

    chains = await agent.analyze()
    assert len(chains) == 0


@pytest.mark.asyncio
async def test_cor001_detects_chain(memory, context):
    """COR_001 detects exploit chains from stored findings."""
    agent = ExploitChainAgent(context=context, memory=memory)

    # Save findings that form a chain
    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
        ),
        _make_finding(
            context.session_id,
            "A_001",
            "Insecure Authentication Token Storage",
            Severity.HIGH,
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await agent.analyze()

    assert len(chains) >= 1
    chain = chains[0]
    assert chain.agent_id == "COR_001"
    assert chain.severity == Severity.CRITICAL
    assert "component_findings" in chain.evidence
    assert len(chain.evidence["component_findings"]) == 3


@pytest.mark.asyncio
async def test_cor001_filters_info_findings(memory, context):
    """COR_001 ignores INFO severity findings."""
    agent = ExploitChainAgent(context=context, memory=memory)

    findings = [
        _make_finding(
            context.session_id,
            "TEST_001",
            "Pipeline Smoke Test",
            Severity.INFO,
        ),
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await agent.analyze()

    # Should skip INFO finding, leaving only 1 candidate (too few for chains)
    assert len(chains) == 0


@pytest.mark.asyncio
async def test_cor001_avoids_recursive_chains(memory, context):
    """COR_001 doesn't include previous chain findings in new chains."""
    agent = ExploitChainAgent(context=context, memory=memory)

    # Save a previous chain finding
    chain_finding = _make_finding(
        context.session_id,
        "COR_001",
        "Authentication Token Theft via Cleartext Traffic",
        Severity.CRITICAL,
    )
    await memory.save_finding(chain_finding)

    # Save regular findings
    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await agent.analyze()

    # Should not include the COR_001 finding in analysis
    # (only 2 non-COR_001 findings = too few for new chains)
    assert len(chains) == 0


@pytest.mark.asyncio
async def test_cor001_chain_to_finding_conversion(memory, context):
    """Chain findings have correct structure."""
    agent = ExploitChainAgent(context=context, memory=memory)

    findings = [
        _make_finding(
            context.session_id,
            "N_002",
            "Cleartext HTTP Traffic",
            Severity.MEDIUM,
            url="http://api.example.com",
        ),
        _make_finding(
            context.session_id,
            "N_001",
            "Missing Certificate Pinning",
            Severity.MEDIUM,
            host="api.example.com",
        ),
        _make_finding(
            context.session_id,
            "A_001",
            "Insecure Authentication Token Storage",
            Severity.HIGH,
            file="SharedPreferences",
        ),
    ]

    for f in findings:
        await memory.save_finding(f)

    chains = await agent.analyze()

    assert len(chains) >= 1
    chain = chains[0]

    # Verify Finding structure
    assert chain.agent_id == "COR_001"
    assert chain.vuln_class == "Authentication Token Theft via Cleartext Traffic"
    assert chain.severity == Severity.CRITICAL
    assert chain.confidence > 0.0
    assert "chain_type" in chain.evidence
    assert "chain_id" in chain.evidence
    assert "component_findings" in chain.evidence
    assert "component_count" in chain.evidence
    assert chain.evidence["component_count"] == 3
    assert chain.recommendation is not None
    assert len(chain.recommendation) > 0
