"""Unit tests for the compliance citation mapper."""
from __future__ import annotations

from pathlib import Path

from sentinel.compliance import ComplianceMapper, default_mapper
from sentinel.compliance.mapper import Citation
from sentinel.core.finding import Finding, Severity


def _finding(agent_id: str = "A_004") -> Finding:
    return Finding(
        agent_id=agent_id,
        vuln_class="Hardcoded Secret",
        severity=Severity.CRITICAL,
        confidence=0.9,
        recommendation="x",
        session_id="abcdefgh1234",
    )


def test_default_mapper_loads_a004():
    cites = default_mapper.cite(_finding("A_004"))
    frameworks = {c.framework for c in cites}
    assert "PCI-DSS" in frameworks
    assert "GDPR" in frameworks


def test_unknown_agent_returns_empty():
    assert default_mapper.cite(_finding("ZZZ_999")) == []


def test_priv_001_has_dpdp_citation():
    cites = default_mapper.cite(_finding("PRIV_001"))
    assert any(c.framework == "DPDP" for c in cites)


def test_citation_render():
    c = Citation(framework="GDPR", reference="Art. 32(1)(a)", note="x")
    assert c.render() == "GDPR Art. 32(1)(a) — x"
    c2 = Citation(framework="GDPR", reference="Art. 32(1)(a)")
    assert c2.render() == "GDPR Art. 32(1)(a)"


def test_custom_mapper_path(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text(
        "X_001:\n"
        "  citations:\n"
        "    - { framework: GDPR, article: 'Art. 5', note: minimisation }\n"
    )
    m = ComplianceMapper(path=p)
    cites = m.cite_by_agent_id("X_001")
    assert len(cites) == 1
    assert cites[0].framework == "GDPR"
    assert cites[0].reference == "Art. 5"


def test_missing_yaml_returns_empty_no_crash(tmp_path):
    m = ComplianceMapper(path=tmp_path / "nope.yaml")
    assert m.cite_by_agent_id("A_004") == []
