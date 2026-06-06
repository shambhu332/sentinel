"""Seeds the SENTINEL knowledge base from the bundled JSON corpora.

The three corpora — MASVS, OWASP Mobile Top 10, and the CWE subset —
ship in ``sentinel/rag/data/``. They are deliberately small (≈ 60
passages combined) so the corpus boots in < 5s on a developer laptop
and stays within the embedding budget of free LLM tiers.

External corpora (OSV vulnerability records) are wired in via
``ingest_osv``; the caller passes the directory produced by
``scripts/fetch_osv_db.py`` and the function tolerates the directory
being absent.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.rag.knowledge_base import KnowledgeBase, KnowledgeBaseError

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent / "data"


@dataclass
class IngestReport:
    """Summary of a knowledge-base ingest run."""

    masvs: int = 0
    owasp_mobile: int = 0
    cwe: int = 0
    osv: int = 0

    @property
    def total(self) -> int:
        return self.masvs + self.owasp_mobile + self.cwe + self.osv


async def ingest_default_corpora(kb: KnowledgeBase) -> IngestReport:
    """Push the three bundled corpora into ``kb``.

    The function is idempotent: every record is upserted by its
    canonical id (``MSTG-AUTH-2``, ``CWE-926``, ``M5``) so calling
    ``ingest_default_corpora`` repeatedly does not duplicate rows.
    """
    report = IngestReport()
    report.masvs = await _ingest_masvs(kb)
    report.owasp_mobile = await _ingest_owasp_mobile(kb)
    report.cwe = await _ingest_cwe(kb)
    logger.info(
        "Ingested %d MASVS + %d OWASP Mobile + %d CWE = %d passages",
        report.masvs, report.owasp_mobile, report.cwe, report.total,
    )
    return report


async def ingest_osv(kb: KnowledgeBase, osv_dir: Path) -> int:
    """Ingest an on-disk OSV vulnerability dump (optional).

    Returns the number of passages ingested. If ``osv_dir`` does not
    exist, returns 0 without raising — the caller can treat OSV
    enrichment as best-effort.
    """
    if not osv_dir.exists():
        return 0
    ids: list[str] = []
    texts: list[str] = []
    metas: list[dict[str, Any]] = []
    for jsonl in sorted(osv_dir.rglob("*.json")):
        try:
            data = json.loads(jsonl.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        vuln_id = data.get("id") or jsonl.stem
        summary = data.get("summary", "")
        details = (data.get("details") or "")[:1200]
        if not summary and not details:
            continue
        ids.append(f"OSV::{vuln_id}")
        texts.append(f"{summary}\n\n{details}".strip())
        metas.append({
            "source": "OSV",
            "control_id": vuln_id,
            "title": summary or vuln_id,
            "category": "supply_chain",
        })

    if not ids:
        return 0
    for batch_start in range(0, len(ids), 64):
        end = batch_start + 64
        await kb.upsert(
            ids=ids[batch_start:end],
            texts=texts[batch_start:end],
            metadatas=metas[batch_start:end],
        )
    return len(ids)


# ---------- corpora-specific helpers ----------


async def _ingest_masvs(kb: KnowledgeBase) -> int:
    payload = _read_json("masvs.json")
    controls = payload.get("controls") or []
    ids = [f"MASVS::{c['id']}" for c in controls]
    texts = [
        f"{c['title']}\n\n{c['text']}" for c in controls
    ]
    metas = [
        {
            "source": "MASVS",
            "control_id": c["id"],
            "title": c["title"],
            "category": c.get("category", ""),
        }
        for c in controls
    ]
    if not ids:
        return 0
    await kb.upsert(ids=ids, texts=texts, metadatas=metas)
    return len(ids)


async def _ingest_owasp_mobile(kb: KnowledgeBase) -> int:
    payload = _read_json("owasp_mobile.json")
    entries = payload.get("entries") or []
    ids = [f"OWASP_MOBILE::{e['id']}" for e in entries]
    texts = [f"{e['title']}\n\n{e['text']}" for e in entries]
    metas = [
        {
            "source": "OWASP_MOBILE",
            "control_id": e["id"],
            "title": e["title"],
            "category": "owasp",
        }
        for e in entries
    ]
    if not ids:
        return 0
    await kb.upsert(ids=ids, texts=texts, metadatas=metas)
    return len(ids)


async def _ingest_cwe(kb: KnowledgeBase) -> int:
    payload = _read_json("cwe_subset.json")
    entries = payload.get("entries") or []
    ids = [f"CWE::{e['id']}" for e in entries]
    texts = [f"{e['title']}\n\n{e['text']}" for e in entries]
    metas = [
        {
            "source": "CWE",
            "control_id": e["id"],
            "title": e["title"],
            "category": "weakness",
        }
        for e in entries
    ]
    if not ids:
        return 0
    await kb.upsert(ids=ids, texts=texts, metadatas=metas)
    return len(ids)


def _read_json(filename: str) -> dict[str, Any]:
    path = _DATA_DIR / filename
    if not path.exists():
        raise KnowledgeBaseError(f"missing bundled corpus: {path}")
    return json.loads(path.read_text())
