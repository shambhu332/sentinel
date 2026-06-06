"""Tests for the RAG-integration path in ``LLMTriager``.

The existing ``tests/unit/test_triage.py`` covers the LLM call shape
and failure modes; this file focuses narrowly on the RAG plumbing:

* The enricher is invoked once per triaged finding.
* Retrieved context is prepended to the user prompt sent to the LLM.
* The compliance mapping is persisted into the finding's evidence.
* A raising enricher does not break triage.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.rag.enricher import KnowledgeEnricher
from sentinel.rag.ingester import ingest_default_corpora
from sentinel.rag.knowledge_base import KnowledgeBase
from sentinel.rag.passage import EnrichedFinding, Passage
from sentinel.triage.triager import LLMTriager


def _verdict_response() -> dict[str, Any]:
    """A successful, schema-compliant LLM response."""
    return {
        "provider": "stub",
        "content": {
            "is_real_bug": True,
            "confidence": 0.85,
            "explanation": "Specific reasoning that references the code.",
            "adjusted_severity": None,
            "false_positive_reason": None,
        },
    }


def _finding(**overrides: Any) -> Finding:
    defaults: dict[str, Any] = {
        "agent_id": "P_010",
        "vuln_class": "Intent Redirect",
        "severity": Severity.HIGH,
        "confidence": 0.85,
        "evidence": {"issue": "demo"},
        "recommendation": "see knowledge base",
        "owasp": "M4: Insufficient Input/Output Validation",
        "masvs": "MSTG-PLATFORM-1",
        "session_id": generate_session_id(),
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _context(tmp_path) -> ScanContext:
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    apk = tmp_path / "f.apk"
    apk.write_bytes(b"PK\x03\x04")
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=workspace,
        scope=BountyScope(),
    )


@pytest.fixture
async def seeded_enricher():
    kb = KnowledgeBase(persist_path=None)
    await kb.connect()
    await kb.clear()
    await ingest_default_corpora(kb)
    yield KnowledgeEnricher(kb=kb)
    await kb.clear()
    await kb.close()


@pytest.mark.asyncio
async def test_rag_context_is_prepended_to_user_prompt(
    seeded_enricher, tmp_path,
):
    router = MagicMock()
    router.query_json = AsyncMock(return_value=_verdict_response())
    triager = LLMTriager(
        router=router,
        inter_call_delay_seconds=0.0,
        enricher=seeded_enricher,
    )
    finding = _finding()

    await triager.triage([finding], context=_context(tmp_path))

    # The router was called exactly once
    assert router.query_json.await_count == 1
    sent_messages = router.query_json.await_args.kwargs["messages"]
    user_prompt = sent_messages[1]["content"]
    # The "Reference context:" header is produced by EnrichedFinding
    # → its presence is the easiest signal that RAG context made it
    # into the prompt body.
    assert "Reference context:" in user_prompt
    # And the original agent-prompt body is still in place.
    assert "Vulnerability class: Intent Redirect" in user_prompt


@pytest.mark.asyncio
async def test_rag_mapping_persisted_into_evidence(
    seeded_enricher, tmp_path,
):
    router = MagicMock()
    router.query_json = AsyncMock(return_value=_verdict_response())
    triager = LLMTriager(
        router=router,
        inter_call_delay_seconds=0.0,
        enricher=seeded_enricher,
    )
    finding = _finding()

    await triager.triage([finding], context=_context(tmp_path))

    mapping = finding.evidence.get("_rag_mapping")
    assert isinstance(mapping, dict)
    # The finding's declared MASVS id is preserved.
    assert "MSTG-PLATFORM-1" in mapping
    # The passage-id list is also persisted for downstream rendering.
    passage_ids = finding.evidence.get("_rag_passage_ids")
    assert isinstance(passage_ids, list)
    assert passage_ids


@pytest.mark.asyncio
async def test_enricher_none_means_unchanged_prompt(tmp_path):
    router = MagicMock()
    router.query_json = AsyncMock(return_value=_verdict_response())
    triager = LLMTriager(
        router=router,
        inter_call_delay_seconds=0.0,
        enricher=None,
    )
    finding = _finding()

    await triager.triage([finding], context=_context(tmp_path))

    user_prompt = router.query_json.await_args.kwargs["messages"][1][
        "content"
    ]
    assert "Reference context:" not in user_prompt
    assert "_rag_mapping" not in finding.evidence


@pytest.mark.asyncio
async def test_raising_enricher_does_not_break_triage(tmp_path):
    enricher = MagicMock()
    enricher.enrich = AsyncMock(side_effect=RuntimeError("kb offline"))

    router = MagicMock()
    router.query_json = AsyncMock(return_value=_verdict_response())
    triager = LLMTriager(
        router=router,
        inter_call_delay_seconds=0.0,
        enricher=enricher,
    )
    finding = _finding()

    out = await triager.triage([finding], context=_context(tmp_path))

    assert len(out) == 1
    assert router.query_json.await_count == 1
    user_prompt = router.query_json.await_args.kwargs["messages"][1][
        "content"
    ]
    assert "Reference context:" not in user_prompt


@pytest.mark.asyncio
async def test_empty_passages_does_not_inject_context(tmp_path):
    enricher = MagicMock()
    enricher.enrich = AsyncMock(return_value=EnrichedFinding(
        finding=_finding(), passages=[], compliance_mapping={},
    ))

    router = MagicMock()
    router.query_json = AsyncMock(return_value=_verdict_response())
    triager = LLMTriager(
        router=router,
        inter_call_delay_seconds=0.0,
        enricher=enricher,
    )
    finding = _finding()

    await triager.triage([finding], context=_context(tmp_path))

    user_prompt = router.query_json.await_args.kwargs["messages"][1][
        "content"
    ]
    assert "Reference context:" not in user_prompt
    # And no mapping written either.
    assert "_rag_mapping" not in finding.evidence
