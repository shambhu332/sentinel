"""Chain detection engine — finds exploit chains in the finding graph.

Algorithm:
1. Build graph from findings (nodes = findings, edges = relationships)
2. For each hardcoded pattern, search for matching paths
3. Score chains by confidence and severity
4. Optionally use LLM to discover novel chains
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.core.finding import Finding, Severity
from sentinel.correlation.models import CHAIN_PATTERNS, ChainFinding, ChainPattern
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)


class ChainDetector:
    """Detects exploit chains from a set of findings."""

    def __init__(self, memory: MemoryInterface, session_id: str) -> None:
        self._memory = memory
        self._session_id = session_id

    async def detect_chains(
        self,
        findings: list[Finding],
        use_llm: bool = False,
    ) -> list[ChainFinding]:
        """Detect all exploit chains in the findings.

        Args:
            findings: List of findings from Phase 2 agents
            use_llm: Whether to use LLM for novel chain discovery

        Returns:
            List of detected chains
        """
        if len(findings) < 2:
            logger.info("[%s] Too few findings (%d) for chain detection",
                        self._session_id, len(findings))
            return []

        # Build graph
        await self._build_graph(findings)

        # Match hardcoded patterns
        chains = await self._match_patterns(findings)

        # LLM-assisted discovery (optional)
        if use_llm:
            novel_chains = await self._discover_novel_chains(findings)
            chains.extend(novel_chains)

        logger.info("[%s] Detected %d exploit chains", self._session_id, len(chains))
        return chains

    async def _build_graph(self, findings: list[Finding]) -> None:
        """Build knowledge graph from findings.

        Nodes: findings
        Edges: relationships (leads_to, enables, exposes)
        """
        for finding in findings:
            # Add finding as node
            await self._memory.add_graph_node(
                session_id=self._session_id,
                node_id=finding.finding_id,
                node_type="finding",
                attrs={
                    "vuln_class": finding.vuln_class,
                    "severity": finding.severity.value,
                    "agent_id": finding.agent_id,
                },
            )

        # Add edges based on relationships
        await self._add_edges(findings)

    async def _add_edges(self, findings: list[Finding]) -> None:
        """Add edges between related findings.

        Heuristics:
        - Cleartext + Missing Pinning → leads_to
        - WebView + JS Interface → enables
        - World-Readable + Exported Provider → exposes
        """
        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1:]:
                edge_type = self._infer_relationship(f1, f2)
                if edge_type:
                    await self._memory.add_graph_edge(
                        session_id=self._session_id,
                        src=f1.finding_id,
                        dst=f2.finding_id,
                        edge_type=edge_type,
                        attrs={},
                    )

    def _infer_relationship(self, f1: Finding, f2: Finding) -> str | None:
        """Infer relationship type between two findings."""
        v1, v2 = f1.vuln_class, f2.vuln_class

        # Cleartext + Missing Pinning
        if "Cleartext" in v1 and "Pinning" in v2:
            return "leads_to"
        if "Cleartext" in v2 and "Pinning" in v1:
            return "leads_to"

        # WebView + JS Interface
        if "WebView" in v1 and "JavaScript" in v2:
            return "enables"
        if "WebView" in v2 and "JavaScript" in v1:
            return "enables"

        # Storage + Exported Component
        if "Storage" in v1 and "Exported" in v2:
            return "exposes"
        if "Storage" in v2 and "Exported" in v1:
            return "exposes"

        # Weak Crypto + Hardcoded Key
        if "Crypto" in v1 and "Hardcoded" in v2:
            return "enables"
        if "Crypto" in v2 and "Hardcoded" in v1:
            return "enables"

        # Pinning Bypass + Data in Transit
        if "Bypass" in v1 and "Transit" in v2:
            return "leads_to"
        if "Bypass" in v2 and "Transit" in v1:
            return "leads_to"

        return None

    async def _match_patterns(self, findings: list[Finding]) -> list[ChainFinding]:
        """Match findings against hardcoded chain patterns."""
        chains: list[ChainFinding] = []

        for pattern in CHAIN_PATTERNS:
            matched = await self._match_pattern(pattern, findings)
            chains.extend(matched)

        return chains

    async def _match_pattern(
        self,
        pattern: ChainPattern,
        findings: list[Finding],
    ) -> list[ChainFinding]:
        """Match a single pattern against findings.

        Matching is tolerant: pattern components are compared as a set of
        significant tokens against each finding's vuln_class. Stopwords
        and a small synonym map collapse known divergences ("Auth" ↔
        "Authentication", "Crypto" ↔ "Cryptographic" / "Cryptography",
        "Exposed" ↔ "Exported"). This is what makes the engine actually
        fire on real scan output where agent vuln_class strings drifted
        from the original pattern definitions.
        """
        chains: list[ChainFinding] = []

        # Check each pattern component against every finding via token match,
        # picking the highest-overlap finding per component.
        pattern_findings: list[Finding] = []
        used_ids: set[str] = set()
        for vuln_class in pattern.pattern:
            want = _normalise_tokens(vuln_class)
            if not want:
                return []
            best: Finding | None = None
            best_score = 0
            for f in findings:
                if f.finding_id in used_ids:
                    continue
                got = _normalise_tokens(f.vuln_class)
                if not want.issubset(got):
                    continue
                score = len(got & want)
                if score > best_score:
                    best_score = score
                    best = f
            if best is None:
                return []
            pattern_findings.append(best)
            used_ids.add(best.finding_id)

        # Pattern co-occurrence is the primary signal. Graph paths are
        # supplementary — they boost confidence when present, but a missing
        # path doesn't suppress the chain. _infer_relationship only encodes
        # edges for adjacent component pairs, so 3+ component patterns won't
        # have an end-to-end graph path even when the chain is real.
        if len(pattern_findings) >= 2:
            paths = await self._find_paths(pattern_findings)
            if not paths:
                paths = [[f.finding_id for f in pattern_findings]]

            for path in paths:
                confidence = self._calculate_confidence(pattern_findings, path)
                evidence = self._build_evidence(pattern_findings)

                chain = ChainFinding(
                    pattern=pattern,
                    findings=pattern_findings,
                    path=path,
                    confidence=confidence,
                    evidence=evidence,
                )
                chains.append(chain)

        return chains

    async def _find_paths(self, findings: list[Finding]) -> list[list[str]]:
        """Find paths through the graph connecting the findings."""
        if len(findings) < 2:
            return []

        # Try to find path from first to last finding
        src = findings[0].finding_id
        dst = findings[-1].finding_id

        paths = await self._memory.find_paths(
            session_id=self._session_id,
            src=src,
            dst=dst,
            max_length=5,
        )

        return paths if paths else []

    def _calculate_confidence(
        self,
        findings: list[Finding],
        path: list[str],
    ) -> float:
        """Calculate confidence score for a chain.

        Factors:
        - Average confidence of component findings
        - Path length (shorter = higher confidence)
        - Severity of components
        """
        if not findings:
            return 0.0

        # Average component confidence
        avg_confidence = sum(f.confidence for f in findings) / len(findings)

        # Path length penalty (longer paths = less confident)
        path_penalty = 1.0 / (1.0 + len(path) * 0.1)

        # Severity bonus (more high-severity components = higher confidence)
        severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2,
        }
        avg_severity = sum(
            severity_scores.get(f.severity, 0.5) for f in findings
        ) / len(findings)

        # Weighted average
        confidence = (
            avg_confidence * 0.5 +
            path_penalty * 0.2 +
            avg_severity * 0.3
        )

        return min(1.0, max(0.0, confidence))

    def _build_evidence(self, findings: list[Finding]) -> dict[str, str]:
        """Build evidence dict for a chain."""
        evidence: dict[str, Any] = {}

        # Extract key evidence from each component
        for i, f in enumerate(findings):
            prefix = f"component_{i + 1}"
            evidence[f"{prefix}_vuln"] = f.vuln_class
            evidence[f"{prefix}_severity"] = f.severity.value
            evidence[f"{prefix}_agent"] = f.agent_id

            # Extract key evidence fields
            if f.evidence:
                if "file" in f.evidence:
                    evidence[f"{prefix}_file"] = str(f.evidence["file"])
                if "package" in f.evidence:
                    evidence[f"{prefix}_package"] = str(f.evidence["package"])
                if "url" in f.evidence:
                    evidence[f"{prefix}_url"] = str(f.evidence["url"])

        return evidence

    async def _discover_novel_chains(
        self,
        findings: list[Finding],
    ) -> list[ChainFinding]:
        """Use LLM to discover novel chains not in hardcoded patterns.

        This is a placeholder for Sprint 9 Task #5.
        """
        # TODO: Implement LLM-assisted chain discovery
        logger.debug("[%s] LLM chain discovery not yet implemented", self._session_id)
        return []


# ---------- vuln_class normalisation ----------

# Stopwords stripped before token-set matching. They carry no signal for
# vulnerability identity (every class description includes "the", "of", etc.).
_STOPWORDS = frozenset({
    # English stopwords
    "a", "an", "the", "of", "in", "on", "to", "for", "with", "without",
    "and", "or", "via", "by", "at",
    # Domain fillers — words that carry no identity signal once the rest of
    # the phrase is in scope ("Weak Cryptographic Algorithm" vs "Weak
    # Cryptography"; "Insecure WebView Configuration" vs "Insecure WebView").
    "algorithm", "algorithms", "configuration", "config", "traffic",
    "issue", "issues", "attack", "vulnerability", "vuln",
})

# Synonym buckets — each variant in a bucket normalises to the bucket head.
# This is what makes "Insecure Auth Token Storage" match the pattern
# "Insecure Authentication Token Storage" without a fragile alias table.
_SYNONYMS: dict[str, str] = {
    "auth":           "authentication",
    "authn":          "authentication",
    "creds":          "credentials",
    "credential":     "credentials",
    "crypto":         "cryptographic",
    "cryptography":   "cryptographic",
    "encryption":     "cryptographic",
    "encrypt":        "cryptographic",
    "exposed":        "exported",
    "exposes":        "exported",
    "exposing":       "exported",
    "ipc":            "component",
    "intent":         "component",
    "perm":           "permission",
    "perms":          "permission",
    "permissions":    "permission",
    "config":         "configuration",
    "tls":            "certificate",
    "ssl":            "certificate",
    "pinning":        "pinning",
    "https":          "transit",
    "http":           "cleartext",
    "plaintext":      "cleartext",
    "key":            "key",
    "keys":           "key",
    "hardcoded":      "hardcoded",
}

def _normalise_tokens(text: str) -> frozenset[str]:
    """Lowercase, split on non-alphanumerics, drop stopwords, apply synonyms.

    Returns a frozenset so callers can use ``set`` algebra (issubset, &).
    """
    import re
    tokens: set[str] = set()
    for raw in re.split(r"[^a-zA-Z0-9]+", str(text or "").lower()):
        if not raw or raw in _STOPWORDS:
            continue
        tokens.add(_SYNONYMS.get(raw, raw))
    return frozenset(tokens)
