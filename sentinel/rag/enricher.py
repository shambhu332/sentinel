"""Public façade for SENTINEL's RAG layer.

The enricher is the one type the triager / report generator should
import. It owns a ``KnowledgeBase`` + ``KnowledgeRetriever`` and
exposes a single ``enrich`` coroutine that takes a ``Finding`` and
returns an ``EnrichedFinding``.

The enricher is deliberately tolerant of an unbuilt corpus: if the
knowledge base is empty (``await kb.count() == 0``), ``enrich``
returns the finding wrapped in an ``EnrichedFinding`` with no
passages instead of raising. That lets callers depend on the
enricher unconditionally — degraded gracefully on first run, before
``sentinel rag build`` has been run.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.rag.knowledge_base import KnowledgeBase
from sentinel.rag.passage import EnrichedFinding, Passage
from sentinel.rag.retriever import KnowledgeRetriever

if TYPE_CHECKING:
    from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)


class KnowledgeEnricher:
    """Attach retrieved knowledge passages to a finding."""

    def __init__(
        self,
        kb: KnowledgeBase | None = None,
        retriever: KnowledgeRetriever | None = None,
        top_k: int = 4,
    ) -> None:
        if kb is None and retriever is None:
            raise ValueError("KnowledgeEnricher needs a kb or a retriever")
        self._kb = kb
        self._retriever = retriever or KnowledgeRetriever(kb)  # type: ignore[arg-type]
        self._top_k = top_k

    async def enrich(self, finding: "Finding") -> EnrichedFinding:
        """Look up reference context for a single finding."""
        passages: list[Passage] = []
        try:
            passages = await self._retriever.retrieve_for_finding(
                finding=finding,
                top_k=self._top_k,
            )
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            logger.warning(
                "Knowledge retrieval failed for %s: %s",
                finding.agent_id, exc,
            )
        mapping = self._build_mapping(finding, passages)
        return EnrichedFinding(
            finding=finding,
            passages=passages,
            compliance_mapping=mapping,
        )

    async def enrich_many(
        self,
        findings: list["Finding"],
    ) -> list[EnrichedFinding]:
        """Bulk variant. Falls back to per-finding enrichment.

        Kept here so the triager has a single call site for batch
        flows; a future implementation can swap this for a batched
        ChromaDB query without changing callers.
        """
        out: list[EnrichedFinding] = []
        for f in findings:
            out.append(await self.enrich(f))
        return out

    # ---------- compliance mapping ----------

    @staticmethod
    def _build_mapping(
        finding: "Finding",
        passages: list[Passage],
    ) -> dict[str, str]:
        """Combine the finding's declared mapping with retrieved hits.

        The finding's own ``owasp`` and ``masvs`` fields are the
        agent's authoritative claim. We seed the mapping with those,
        then augment with any retrieved passage whose source id
        starts with a known prefix.
        """
        mapping: dict[str, str] = {}
        if finding.owasp:
            mapping[finding.owasp.split(":")[0].strip()] = finding.owasp
        if finding.masvs:
            mapping[finding.masvs] = finding.masvs
        for p in passages:
            if not p.source:
                continue
            if p.source not in mapping:
                mapping[p.source] = p.title or p.source
        return mapping
