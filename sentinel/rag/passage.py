"""Dataclasses for the RAG retrieval surface.

Kept I/O-free so the rest of the package and the test suite can pass
``Passage`` / ``EnrichedFinding`` instances around without depending
on ChromaDB being installed or initialized.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.core.finding import Finding


@dataclass(frozen=True)
class Passage:
    """A single retrieved knowledge passage.

    ``source`` is the canonical identifier — ``MSTG-AUTH-2``,
    ``CWE-926``, ``M5``, etc. ``score`` is a similarity score in
    ``[0, 1]`` (higher = closer); callers can use it for ranking but
    should not assume any particular distribution.
    """

    source: str
    title: str
    text: str
    category: str = ""
    score: float = 0.0

    def to_prompt_block(self) -> str:
        """Render the passage as a compact LLM-prompt block."""
        header = f"[{self.source}] {self.title}"
        if self.category:
            header += f" ({self.category})"
        return f"{header}\n{self.text}"


@dataclass
class EnrichedFinding:
    """A finding augmented with retrieved knowledge.

    ``compliance_mapping`` is a structured lookup keyed by control id
    (``MSTG-AUTH-2``, ``M5``, ``CWE-926``) and pointing at the
    short title of the control. The full text lives in ``passages``
    so callers can choose to render compactly or fully.
    """

    finding: "Finding"
    passages: list[Passage] = field(default_factory=list)
    compliance_mapping: dict[str, str] = field(default_factory=dict)

    def prompt_context(self, max_passages: int = 4) -> str:
        """Render the top-N passages as a single LLM-prompt section."""
        if not self.passages:
            return ""
        blocks = [p.to_prompt_block() for p in self.passages[:max_passages]]
        return "Reference context:\n\n" + "\n\n".join(blocks)
