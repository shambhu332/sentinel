"""SENTINEL retrieval-augmented generation layer.

Wires a small in-tree knowledge corpus (MASVS controls, OWASP Mobile
Top 10, the CWE subset SENTINEL findings reference) into a ChromaDB
vector store so the LLM triager can attach authoritative context to
every finding.

The package is deliberately split into four single-responsibility
modules so each part is testable in isolation:

* ``passage`` — small dataclasses (no I/O).
* ``ingester`` — reads the bundled JSON corpora and pushes them
  into a ChromaDB collection.
* ``retriever`` — query interface that returns scored passages for
  a finding or a free-form text query.
* ``enricher`` — public façade that takes a ``Finding`` and returns
  an ``EnrichedFinding`` carrying passages and a structured
  compliance mapping.
"""
from sentinel.rag.enricher import EnrichedFinding, KnowledgeEnricher
from sentinel.rag.knowledge_base import KnowledgeBase
from sentinel.rag.passage import Passage

__all__ = [
    "EnrichedFinding",
    "KnowledgeBase",
    "KnowledgeEnricher",
    "Passage",
]
