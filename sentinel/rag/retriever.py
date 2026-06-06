"""Retriever interface for SENTINEL's RAG layer.

The retriever sits between the knowledge base and the enricher. Its
job is to translate a finding (or a free-form query) into the right
ChromaDB query and rank the result. The knowledge base only knows
about vectors; the retriever adds policy.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.rag.knowledge_base import KnowledgeBase
from sentinel.rag.passage import Passage

if TYPE_CHECKING:
    from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)


class KnowledgeRetriever:
    """Query the knowledge base on behalf of the enricher."""

    def __init__(self, kb: KnowledgeBase) -> None:
        self._kb = kb

    async def retrieve(
        self,
        query: str,
        top_k: int = 4,
        source_filter: str | None = None,
    ) -> list[Passage]:
        """Run a free-form text query.

        ``source_filter`` constrains results to a single corpus
        (``MASVS`` / ``OWASP_MOBILE`` / ``CWE`` / ``OSV``). When
        omitted, all corpora are searched together.
        """
        if not query.strip():
            return []
        where = {"source": source_filter} if source_filter else None
        raw = await self._kb.query(text=query, top_k=top_k, where=where)
        return [self._to_passage(r) for r in raw]

    async def retrieve_for_finding(
        self,
        finding: "Finding",
        top_k: int = 4,
    ) -> list[Passage]:
        """Build a query string from a finding and retrieve."""
        query = self._build_query(finding)
        return await self.retrieve(query=query, top_k=top_k)

    # ---------- query construction ----------

    @staticmethod
    def _build_query(finding: "Finding") -> str:
        """Concatenate the fields most likely to match the corpus.

        ``vuln_class`` is the strongest signal. ``masvs`` and
        ``owasp`` carry exact control ids that the corpus embeds
        verbatim, so they boost recall when present.
        """
        parts: list[str] = [finding.vuln_class]
        if finding.owasp:
            parts.append(finding.owasp)
        if finding.masvs:
            parts.append(finding.masvs)
        # Pull a short evidence snippet so the retrieval is somewhat
        # specific to the offending pattern, not just the class.
        evidence = finding.evidence or {}
        issue = evidence.get("issue") or evidence.get("reason")
        if isinstance(issue, str):
            parts.append(issue[:200])
        return " ".join(parts)

    # ---------- shaping ----------

    @staticmethod
    def _to_passage(record: dict) -> Passage:
        meta = record.get("metadata") or {}
        return Passage(
            source=str(meta.get("control_id") or record["id"]),
            title=str(meta.get("title") or ""),
            text=str(record.get("document") or ""),
            category=str(meta.get("category") or ""),
            score=float(record.get("score") or 0.0),
        )
