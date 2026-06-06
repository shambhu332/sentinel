"""Unit tests for the RAG enrichment layer.

The tests run against an in-memory ChromaDB collection
(``KnowledgeBase(persist_path=None)``) so the suite stays self-
contained and doesn't litter ``tmp_path`` with on-disk persisted
indexes.
"""
from __future__ import annotations

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import generate_session_id
from sentinel.rag.enricher import KnowledgeEnricher
from sentinel.rag.ingester import ingest_default_corpora, ingest_osv
from sentinel.rag.knowledge_base import KnowledgeBase, KnowledgeBaseError
from sentinel.rag.passage import EnrichedFinding, Passage
from sentinel.rag.retriever import KnowledgeRetriever


@pytest.fixture
async def kb():
    # ChromaDB's EphemeralClient keeps the named collection alive
    # across instances inside a single process, so we explicitly
    # clear before yielding to guarantee each test sees an empty
    # corpus.
    kb = KnowledgeBase(persist_path=None)
    await kb.connect()
    await kb.clear()
    yield kb
    await kb.clear()
    await kb.close()


@pytest.fixture
async def seeded_kb(kb):
    await ingest_default_corpora(kb)
    return kb


def _finding(*, vuln_class: str, owasp: str = "", masvs: str = "") -> Finding:
    return Finding(
        agent_id="P_010",
        vuln_class=vuln_class,
        severity=Severity.HIGH,
        confidence=0.85,
        evidence={"issue": "demonstration"},
        recommendation="see knowledge base",
        owasp=owasp or None,
        masvs=masvs or None,
        session_id=generate_session_id(),
    )


# ---------- KnowledgeBase lifecycle ----------


@pytest.mark.asyncio
async def test_require_collection_raises_before_connect():
    kb = KnowledgeBase(persist_path=None)
    with pytest.raises(KnowledgeBaseError):
        await kb.query(text="anything")


@pytest.mark.asyncio
async def test_connect_is_idempotent(kb):
    # Second connect must be a no-op.
    await kb.connect()
    assert await kb.count() == 0


@pytest.mark.asyncio
async def test_upsert_then_count(kb):
    await kb.upsert(
        ids=["X::1"],
        texts=["hello world"],
        metadatas=[{"source": "X", "control_id": "X-1", "title": "t"}],
    )
    assert await kb.count() == 1


@pytest.mark.asyncio
async def test_clear_resets_collection(kb):
    await kb.upsert(["X::1"], ["hi"], [{"source": "X"}])
    assert await kb.count() == 1
    await kb.clear()
    assert await kb.count() == 0


# ---------- ingester ----------


@pytest.mark.asyncio
async def test_ingest_default_corpora_loads_expected_minimum(kb):
    report = await ingest_default_corpora(kb)
    assert report.masvs >= 20
    assert report.owasp_mobile == 10
    assert report.cwe >= 20
    assert report.total == await kb.count()


@pytest.mark.asyncio
async def test_ingest_is_idempotent(kb):
    first = await ingest_default_corpora(kb)
    after_first = await kb.count()
    second = await ingest_default_corpora(kb)
    after_second = await kb.count()
    assert first.total == second.total
    assert after_first == after_second  # upsert, not duplicate


@pytest.mark.asyncio
async def test_ingest_osv_missing_dir_returns_zero(kb, tmp_path):
    missing = tmp_path / "does_not_exist"
    n = await ingest_osv(kb, missing)
    assert n == 0


@pytest.mark.asyncio
async def test_ingest_osv_reads_jsonl_files(kb, tmp_path):
    import json

    osv_dir = tmp_path / "osv"
    osv_dir.mkdir()
    (osv_dir / "vuln1.json").write_text(json.dumps({
        "id": "OSV-TEST-001",
        "summary": "Sample vulnerability",
        "details": "Long description...",
    }))
    n = await ingest_osv(kb, osv_dir)
    assert n == 1
    assert await kb.count() == 1


# ---------- retriever ----------


@pytest.mark.asyncio
async def test_retrieve_returns_empty_on_empty_corpus(kb):
    retriever = KnowledgeRetriever(kb)
    passages = await retriever.retrieve("anything")
    assert passages == []


@pytest.mark.asyncio
async def test_retrieve_for_finding_returns_passages(seeded_kb):
    retriever = KnowledgeRetriever(seeded_kb)
    f = _finding(
        vuln_class="Intent Redirect",
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MSTG-PLATFORM-1",
    )
    passages = await retriever.retrieve_for_finding(f, top_k=3)
    assert passages
    assert all(isinstance(p, Passage) for p in passages)
    assert all(p.score >= 0.0 for p in passages)


@pytest.mark.asyncio
async def test_source_filter_constrains_results(seeded_kb):
    retriever = KnowledgeRetriever(seeded_kb)
    passages = await retriever.retrieve(
        "session token in URL", top_k=5, source_filter="MASVS",
    )
    assert passages
    # Verify metadata source consistency by checking the source id
    # prefix — every MASVS passage's control_id starts with MSTG.
    assert all(p.source.startswith("MSTG-") for p in passages)


# ---------- enricher ----------


@pytest.mark.asyncio
async def test_enricher_attaches_passages(seeded_kb):
    enricher = KnowledgeEnricher(kb=seeded_kb, top_k=3)
    f = _finding(
        vuln_class="Cleartext WebSocket",
        owasp="M5: Insecure Communication",
        masvs="MSTG-NETWORK-1",
    )
    enriched = await enricher.enrich(f)
    assert isinstance(enriched, EnrichedFinding)
    assert enriched.passages
    # Mapping must include the finding's declared masvs id.
    assert "MSTG-NETWORK-1" in enriched.compliance_mapping


@pytest.mark.asyncio
async def test_enricher_handles_empty_corpus_gracefully(kb):
    enricher = KnowledgeEnricher(kb=kb)
    f = _finding(vuln_class="Anything")
    enriched = await enricher.enrich(f)
    assert enriched.passages == []
    assert enriched.compliance_mapping == {}


@pytest.mark.asyncio
async def test_enrich_many_walks_all(seeded_kb):
    enricher = KnowledgeEnricher(kb=seeded_kb, top_k=2)
    findings = [
        _finding(vuln_class="ECB Cipher Mode", masvs="MSTG-CRYPTO-2"),
        _finding(vuln_class="Session Token in URL", masvs="MSTG-AUTH-2"),
    ]
    results = await enricher.enrich_many(findings)
    assert len(results) == 2
    assert all(isinstance(r, EnrichedFinding) for r in results)


# ---------- Passage shaping ----------


def test_passage_to_prompt_block_renders_header_and_text():
    p = Passage(
        source="MSTG-AUTH-2",
        title="Server-side token invalidation",
        text="Refresh tokens must rotate on logout.",
        category="auth",
        score=0.9,
    )
    block = p.to_prompt_block()
    assert "MSTG-AUTH-2" in block
    assert "(auth)" in block
    assert "Refresh tokens" in block


def test_enriched_finding_prompt_context_caps_at_max():
    finding = _finding(vuln_class="x", masvs="MSTG-AUTH-2")
    passages = [
        Passage(source=f"X-{i}", title=f"t{i}", text=f"text {i}")
        for i in range(6)
    ]
    enriched = EnrichedFinding(finding=finding, passages=passages)
    ctx = enriched.prompt_context(max_passages=3)
    # Render must include only 3 source headers.
    assert ctx.count("[X-") == 3
