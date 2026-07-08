"""RAGAnalysisContext — structured knowledge package for LLM vulnerability analysis.

Built from Passage objects returned by KnowledgeRetriever and formatted into
a compact prompt section that grounds every LLM vulnerability decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.rag.passage import Passage


@dataclass
class RAGAnalysisContext:
    """All RAG passages retrieved for a single candidate analysis call."""

    passages: list[Passage] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Formatting — each method returns a short section for the LLM prompt #
    # ------------------------------------------------------------------ #

    def format_guidance(self, max_passages: int = 6) -> str:
        if not self.passages:
            return "No relevant knowledge retrieved."
        lines: list[str] = []
        for p in self.passages[:max_passages]:
            header = f"[{p.source}] {p.title}" if p.title else f"[{p.source}]"
            lines.append(f"### {header} (similarity {p.score:.2f})")
            lines.append(p.text[:600])
        return "\n".join(lines)

    def has_knowledge(self) -> bool:
        return bool(self.passages)

    def top_sources(self, n: int = 3) -> list[str]:
        return [p.source for p in self.passages[:n]]

    @classmethod
    def empty(cls) -> "RAGAnalysisContext":
        return cls(passages=[])
