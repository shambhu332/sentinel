"""ADAPT_001 — Strategy Selector + LEARN_001 Feedback Agent.

The two halves of the self-learning loop:

  * `FeedbackAgent.record_probe_failure(agent_id, finding, context_tag)`
    is called at the end of Phase 4.5 by the dynamic-result aggregator
    whenever a SAST finding's `dynamic_target` probe FAILED to confirm
    the vulnerability (zero successful_internal_hits, zero
    spoofs_succeeded, zero distinct_row_counts, etc). The Feedback
    agent maps that failure to a `context_tag` describing the inferred
    reason ("custom_orm", "obfuscation_tier_2", "modified_billing_lib",
    "non_standard_provider_path") and persists it under the per-app
    learning profile.

  * `StrategySelector.strategies_for(agent_id, profile)` is called at
    the top of every dynamic agent's `analyze()` method. It returns
    the list of recorded `suggested_strategy` strings for that agent
    based on previously-recorded failure contexts.

  * `StrategySelector.applies_strategy(strategies, name)` is the
    cheap one-liner agents call:
        if applies_strategy(strats, "custom_orm_fuzzing"):
            probes = _ORM_PROBES + _STANDARD_PROBES
        else:
            probes = _STANDARD_PROBES

The mapping from context-tag → suggested-strategy lives in
`_FAILURE_STRATEGY_MAP`. Agents read strategies; the Feedback agent
writes them. Both halves are pure — no side effects beyond the
profile store.

Persistence backend:
  * Defaults to `sentinel.learning.profile_store.AppProfileStore`
    (file-backed JSON under data/learning/).
  * Optionally accepts a ChromaDB collection via
    `StrategySelector(chroma_collection=...)` for the embedding-based
    "similar apps" lookup the brief asks for. When chroma is missing,
    the selector still works against the local profile — chroma is
    enrichment, not a hard dependency.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sentinel.learning.profile_store import AppLearningProfile, AppProfileStore

logger = logging.getLogger(__name__)


# Maps the inferred reason a dynamic probe failed -> the strategy the
# agent should switch to next time. Hand-curated; PR-friendly.
_FAILURE_STRATEGY_MAP: dict[str, str] = {
    # D_063 ContentProvider SQLi failures
    "custom_orm":               "custom_orm_fuzzing",
    "selection_argument_bound": "raw_uri_fuzzing",
    "permission_protected":     "exported_provider_only",

    # D_072 JNI Shadow Executor failures
    "obfuscation_tier_2":       "extended_payload_set",
    "anti_debug_present":       "skip_oversize_probes",
    "symbol_stripped":          "module_export_scan",

    # D_082 IAP Spoofing failures
    "modified_billing_lib":     "fallback_listener_class_walk",
    "server_attestation":       "skip_iap_spoof",

    # D_083 Mobile SSRF failures
    "host_allowlist_present":   "scheme_confusion_payloads",
    "dns_pinning":              "ip_literal_probes",

    # D_084-D_086 WebView failures
    "csp_strict":               "dom_xss_only",
    "content_provider_locked":  "narrow_path_only",
    "intent_filter_strict":     "internal_only_payloads",
}


@dataclass(frozen=True)
class StrategyRecord:
    """One adaptive strategy for the next scan."""

    agent_id: str
    strategy: str
    source_context: str
    occurrences: int = 1


@dataclass
class StrategySelector:
    """Reads failure contexts -> chooses payload strategies."""

    chroma_collection: Any = None  # opt-in similar-apps embedding store

    def strategies_for(
        self, agent_id: str, profile: AppLearningProfile | None,
    ) -> list[StrategyRecord]:
        """Return strategies the named agent should apply for this scan."""
        if profile is None:
            return []
        records: list[StrategyRecord] = []
        for entry in profile.get_failure_contexts(agent_id):
            strategy = entry.get("suggested_strategy")
            if not strategy:
                # Fall back to the map if the recorder didn't pick one.
                strategy = _FAILURE_STRATEGY_MAP.get(
                    entry.get("context_tag", ""), "",
                )
            if not strategy:
                continue
            records.append(StrategyRecord(
                agent_id=agent_id,
                strategy=strategy,
                source_context=entry.get("context_tag", ""),
                occurrences=int(entry.get("occurrences", 1)),
            ))
        # Optional ChromaDB step: similar-app lookup. When the
        # collection is missing this entire branch is skipped.
        if self.chroma_collection is not None and profile.package:
            records.extend(self._chroma_neighbors(agent_id, profile))
        # Dedup by strategy name, keeping the highest-occurrence rec.
        best: dict[str, StrategyRecord] = {}
        for r in records:
            cur = best.get(r.strategy)
            if cur is None or r.occurrences > cur.occurrences:
                best[r.strategy] = r
        return sorted(
            best.values(), key=lambda x: x.occurrences, reverse=True,
        )

    def _chroma_neighbors(
        self, agent_id: str, profile: AppLearningProfile,
    ) -> list[StrategyRecord]:
        """Ask ChromaDB for failure contexts recorded for similar apps."""
        try:
            res = self.chroma_collection.query(
                query_texts=[profile.package],
                n_results=5,
                where={"agent_id": agent_id},
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("Chroma neighbor query failed: %s", e)
            return []
        out: list[StrategyRecord] = []
        for meta_list in res.get("metadatas", []) or []:
            for meta in meta_list or []:
                strategy = meta.get("suggested_strategy") or \
                    _FAILURE_STRATEGY_MAP.get(meta.get("context_tag", ""), "")
                if not strategy:
                    continue
                out.append(StrategyRecord(
                    agent_id=agent_id, strategy=strategy,
                    source_context=meta.get("context_tag", "neighbor"),
                    occurrences=1,
                ))
        return out


def applies_strategy(
    strategies: list[StrategyRecord], name: str,
) -> bool:
    """One-liner agents call to ask 'should I switch to <name>?'."""
    return any(s.strategy == name for s in strategies)


@dataclass
class FeedbackAgent:
    """Records dynamic-probe failures so future scans adapt."""

    store: AppProfileStore | None = None
    chroma_collection: Any = None

    def record_probe_failure(
        self,
        apk_sha256: str,
        agent_id: str,
        context_tag: str,
        context_note: str = "",
        scan_session: str = "",
        suggested_strategy: str | None = None,
    ) -> None:
        """Persist a single failure context for the named (apk, agent).

        Pass `suggested_strategy=None` to let the
        `_FAILURE_STRATEGY_MAP` decide; pass an explicit string to
        override (useful when an agent has more info than the map
        does — e.g. observing a specific ORM class name).
        """
        if self.store is None or not apk_sha256:
            return
        strategy = (
            suggested_strategy
            if suggested_strategy is not None
            else _FAILURE_STRATEGY_MAP.get(context_tag, "")
        )
        profile = self.store.load(apk_sha256)
        profile.record_failure_context(
            agent_id=agent_id,
            context_tag=context_tag,
            context_note=context_note,
            suggested_strategy=strategy,
            scan_session=scan_session,
        )
        self.store.save(profile)
        # Mirror into ChromaDB so OTHER apps can benefit from this
        # lesson (the "similar apps" branch of the selector).
        self._mirror_to_chroma(
            apk_sha256, agent_id, context_tag, strategy,
            context_note, profile.package,
        )

    def _mirror_to_chroma(
        self, apk_sha256: str, agent_id: str, context_tag: str,
        suggested_strategy: str, context_note: str, package: str,
    ) -> None:
        if self.chroma_collection is None:
            return
        try:
            doc = f"{package} {agent_id} {context_tag} {context_note}".strip()
            self.chroma_collection.add(
                documents=[doc],
                metadatas=[{
                    "apk_sha256": apk_sha256,
                    "agent_id": agent_id,
                    "context_tag": context_tag,
                    "suggested_strategy": suggested_strategy,
                    "package": package,
                }],
                ids=[f"{apk_sha256[:16]}-{agent_id}-{context_tag}"],
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("Chroma mirror failed: %s", e)


__all__ = [
    "FeedbackAgent",
    "StrategyRecord",
    "StrategySelector",
    "applies_strategy",
]
