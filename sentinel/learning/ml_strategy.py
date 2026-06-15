"""ML-trained strategy classifier — opt-in upgrade over the rule-based
``_FAILURE_STRATEGY_MAP``.

The original ``StrategySelector`` ships a hand-written dict mapping
``context_tag -> suggested_strategy``. That's fine when an agent author
already knows what to try next, but it doesn't generalise across:

  * apps with similar fingerprints (same obfuscator, same ORM, same
    auth stack) where one app's failures predict the next app's,
  * novel context tags an agent emits for the first time,
  * combinations of two or three tags whose joint meaning is more
    than the sum (e.g. ``custom_orm`` + ``obfuscation_tier_2`` →
    ``extended_payload_set`` with high confidence).

This module replaces the dict with a small scikit-learn classifier
(``GradientBoostingClassifier`` by default) trained on the observed
``(features) -> winning strategy`` outcomes accumulated in the
per-app ``AppLearningProfile``. Until a real corpus exists, training
falls back to the synthetic bootstrap rows in ``_BOOTSTRAP_DATA`` so
the classifier predicts something sensible from day one.

Public surface is small + drop-in compatible with the existing
selector:

  * ``MLStrategySelector.strategies_for(agent_id, profile)`` — same
    signature as ``StrategySelector``. Returns ``StrategyRecord``s.
  * ``train_from_profiles(profile_dir, model_path)`` — re-train the
    classifier from a directory of saved ``AppLearningProfile`` JSON
    blobs.
  * ``load_model() / save_model()`` — pickle the trained estimator
    so the inference path doesn't pay training cost every scan.

Degrades cleanly when scikit-learn isn't installed: imports succeed
but ``strategies_for`` falls back to the rule-based selector.
"""
from __future__ import annotations

import json
import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.learning.profile_store import AppLearningProfile
from sentinel.learning.strategy import (
    _FAILURE_STRATEGY_MAP,
    StrategyRecord,
    StrategySelector,
)

logger = logging.getLogger(__name__)


# Synthetic bootstrap rows — gives the classifier something to train
# on before any real-app outcomes have been recorded. Each row is the
# exact shape the ``_featurise`` function produces. The strategy
# labels match the rule-based map so day-one behaviour stays familiar.
_BOOTSTRAP_DATA: list[dict[str, Any]] = [
    # D_063 ContentProvider SQLi
    {"agent_id": "D_063", "context_tag": "custom_orm",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "custom_orm_fuzzing"},
    {"agent_id": "D_063", "context_tag": "selection_argument_bound",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "raw_uri_fuzzing"},
    {"agent_id": "D_063", "context_tag": "permission_protected",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "exported_provider_only"},

    # D_072 JNI Shadow
    {"agent_id": "D_072", "context_tag": "obfuscation_tier_2",
     "tag_count": 1, "has_obfuscation": 1, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "extended_payload_set"},
    {"agent_id": "D_072", "context_tag": "anti_debug_present",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 1,
     "previous_failures": 1, "strategy": "skip_oversize_probes"},
    {"agent_id": "D_072", "context_tag": "symbol_stripped",
     "tag_count": 1, "has_obfuscation": 1, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "module_export_scan"},

    # Combinatorial rows — the value-add over the rule-based map.
    # Two tags simultaneously → still pick the obfuscation strategy
    # because the anti-debug-only response would miss the obfuscated
    # symbol table.
    {"agent_id": "D_072", "context_tag": "obfuscation_tier_2",
     "tag_count": 2, "has_obfuscation": 1, "has_anti_debug": 1,
     "previous_failures": 2, "strategy": "extended_payload_set"},
    {"agent_id": "D_072", "context_tag": "anti_debug_present",
     "tag_count": 2, "has_obfuscation": 1, "has_anti_debug": 1,
     "previous_failures": 2, "strategy": "extended_payload_set"},

    # D_082 IAP / billing
    {"agent_id": "D_082", "context_tag": "modified_billing_lib",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "fallback_listener_class_walk"},
    {"agent_id": "D_082", "context_tag": "server_attestation",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "skip_iap_spoof"},

    # D_083 mobile SSRF
    {"agent_id": "D_083", "context_tag": "host_allowlist_present",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "scheme_confusion_payloads"},
    {"agent_id": "D_083", "context_tag": "dns_pinning",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "ip_literal_probes"},

    # D_084/D_085/D_086 WebView
    {"agent_id": "D_084", "context_tag": "csp_strict",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "dom_xss_only"},
    {"agent_id": "D_085", "context_tag": "content_provider_locked",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "narrow_path_only"},
    {"agent_id": "D_086", "context_tag": "intent_filter_strict",
     "tag_count": 1, "has_obfuscation": 0, "has_anti_debug": 0,
     "previous_failures": 1, "strategy": "internal_only_payloads"},
]


def _featurise(
    agent_id: str, context_tag: str, profile: AppLearningProfile | None,
) -> list[float]:
    """Reduce the input to a fixed-width numeric feature vector.

    The classifier expects ``[agent_idx, tag_idx, tag_count,
    has_obfuscation, has_anti_debug, previous_failures]``. agent_id
    and context_tag are interned into the small string dictionaries
    below; unknown values get a sentinel index. Keeping the encoder
    deterministic + tiny means the classifier doesn't need an
    OrdinalEncoder pickled alongside it.
    """
    if profile is None:
        ctx_list: list[dict[str, Any]] = []
    else:
        ctx_list = list(profile.failure_contexts.get(agent_id, []))

    tags_in_profile = {entry.get("context_tag", "") for entry in ctx_list}
    return [
        float(_AGENT_INDEX.get(agent_id, _SENTINEL_IDX)),
        float(_TAG_INDEX.get(context_tag, _SENTINEL_IDX)),
        float(len(tags_in_profile)),
        1.0 if any("obfusc" in t for t in tags_in_profile) else 0.0,
        1.0 if any("anti_debug" in t for t in tags_in_profile) else 0.0,
        float(sum(int(e.get("occurrences", 1)) for e in ctx_list)),
    ]


# Tiny string interning — keep the classifier feature space stable
# across retrains and across processes. Adding new agents/tags adds
# entries at the end so old saved models still decode correctly.
_AGENT_INDEX = {
    a: i for i, a in enumerate([
        "D_063", "D_072", "D_082", "D_083",
        "D_084", "D_085", "D_086",
    ])
}
_TAG_INDEX = {
    t: i for i, t in enumerate([
        "custom_orm", "selection_argument_bound", "permission_protected",
        "obfuscation_tier_2", "anti_debug_present", "symbol_stripped",
        "modified_billing_lib", "server_attestation",
        "host_allowlist_present", "dns_pinning",
        "csp_strict", "content_provider_locked", "intent_filter_strict",
    ])
}
_SENTINEL_IDX = 999


@dataclass
class MLStrategySelector:
    """Drop-in replacement for ``StrategySelector`` backed by scikit-learn."""

    model_path: Path | None = None
    fallback: StrategySelector = field(default_factory=StrategySelector)
    _classifier: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._classifier = self._load_or_bootstrap()

    def _load_or_bootstrap(self) -> Any:
        try:
            if self.model_path and self.model_path.exists():
                with self.model_path.open("rb") as fh:
                    return pickle.load(fh)
        except Exception:  # noqa: BLE001
            logger.exception("ML model load failed; bootstrapping fresh")
        return _train_classifier(_BOOTSTRAP_DATA)

    # ---------- public surface (mirrors StrategySelector) ----------

    def strategies_for(
        self, agent_id: str, profile: AppLearningProfile | None,
    ) -> list[StrategyRecord]:
        if profile is None:
            return []
        # Walk every recorded failure context for this agent. The
        # classifier predicts the *best* strategy per context; we
        # collect them, dedupe by predicted label, and order by
        # occurrence count just like the rule-based selector.
        if self._classifier is None:
            return self.fallback.strategies_for(agent_id, profile)

        out: dict[str, StrategyRecord] = {}
        for entry in profile.get_failure_contexts(agent_id):
            ctx_tag = entry.get("context_tag", "")
            try:
                feats = _featurise(agent_id, ctx_tag, profile)
                predicted = self._classifier.predict([feats])[0]
            except Exception:  # noqa: BLE001
                logger.debug("ML predict failed; falling back to map")
                predicted = _FAILURE_STRATEGY_MAP.get(ctx_tag, "")
            if not predicted:
                continue
            cur = out.get(predicted)
            occ = int(entry.get("occurrences", 1))
            if cur is None or occ > cur.occurrences:
                out[predicted] = StrategyRecord(
                    agent_id=agent_id, strategy=str(predicted),
                    source_context=ctx_tag, occurrences=occ,
                )
        return sorted(out.values(), key=lambda r: r.occurrences, reverse=True)

    # ---------- training ----------

    def save_model(self, path: Path | None = None) -> Path:
        path = path or self.model_path
        if path is None:
            raise ValueError("save_model requires a model_path")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            pickle.dump(self._classifier, fh)
        logger.info("ML model saved to %s", path)
        return path

    def retrain(self, rows: list[dict[str, Any]]) -> int:
        """Re-train from the union of bootstrap + new rows."""
        merged = _BOOTSTRAP_DATA + (rows or [])
        self._classifier = _train_classifier(merged)
        return len(merged)


def _train_classifier(rows: list[dict[str, Any]]) -> Any:
    """Train the GradientBoostingClassifier from a list of feature rows."""
    try:
        from sklearn.ensemble import GradientBoostingClassifier
    except ImportError:
        logger.info("scikit-learn unavailable; ML selector disabled")
        return None
    if not rows:
        return None
    X: list[list[float]] = []
    y: list[str] = []
    for r in rows:
        X.append([
            float(_AGENT_INDEX.get(r["agent_id"], _SENTINEL_IDX)),
            float(_TAG_INDEX.get(r["context_tag"], _SENTINEL_IDX)),
            float(r.get("tag_count", 1)),
            float(r.get("has_obfuscation", 0)),
            float(r.get("has_anti_debug", 0)),
            float(r.get("previous_failures", 1)),
        ])
        y.append(str(r["strategy"]))
    if len(set(y)) < 2:
        logger.info(
            "Training corpus has %d label(s); refusing to fit a single-class "
            "model — ML selector will defer to the rule-based map", len(set(y)),
        )
        return None
    clf = GradientBoostingClassifier(
        n_estimators=50, max_depth=3, random_state=0,
    )
    clf.fit(X, y)
    return clf


def train_from_profiles(
    profile_dir: Path, model_path: Path,
) -> int:
    """Re-train the classifier from every AppLearningProfile JSON on disk.

    Returns the row count used for training (bootstrap + observed).
    Callable from a cron/CI job; safe to call repeatedly.
    """
    if not profile_dir.exists():
        return 0
    rows: list[dict[str, Any]] = []
    for path in profile_dir.glob("*.json"):
        try:
            blob = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        contexts = blob.get("failure_contexts") or {}
        for agent_id, entries in contexts.items():
            tag_count = len({e.get("context_tag", "") for e in entries})
            for e in entries:
                strategy = e.get("suggested_strategy") or ""
                if not strategy:
                    continue
                rows.append({
                    "agent_id": agent_id,
                    "context_tag": e.get("context_tag", ""),
                    "tag_count": tag_count,
                    "has_obfuscation": int(any(
                        "obfusc" in (x.get("context_tag", "") or "")
                        for x in entries
                    )),
                    "has_anti_debug": int(any(
                        "anti_debug" in (x.get("context_tag", "") or "")
                        for x in entries
                    )),
                    "previous_failures": int(e.get("occurrences", 1)),
                    "strategy": strategy,
                })
    selector = MLStrategySelector(model_path=model_path)
    selector.retrain(rows)
    selector.save_model()
    return len(rows) + len(_BOOTSTRAP_DATA)


__all__ = [
    "MLStrategySelector",
    "train_from_profiles",
]
