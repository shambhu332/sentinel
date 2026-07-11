"""D_063 — ContentProvider SQLi injection (Dynamic Testing Target).

Static identification of exported ContentProviders whose `query()` /
`update()` / `delete()` implementations route attacker-controlled
`selection` or `projection` arguments into `rawQuery` /
`SQLiteQueryBuilder.appendWhere(...)` without parameterisation. For
every match we emit a Frida trigger payload the DAST orchestrator
fires through `ContentResolver.query()` from a controlled context.

The existing IPC_001 / ContentProviderIDORAgent already flag
unsynthesised SQLi-shaped patterns in `selection`. D_063's value-add
is the runtime confirmation half:

  1) Identify the provider's authority (from AndroidManifest)
  2) Enumerate URIs the provider claims to handle (UriMatcher entries)
  3) Build a `frida_payload` describing the URI + the payload bag
     to fire (sqli probes: `' OR 1=1--`, `1) UNION SELECT name FROM
     sqlite_master--`, etc.)
  4) The Frida trigger script (frida_agent/src/hooks/d063_provider_sqli.ts)
     fires each probe through ContentResolver, observes the cursor
     row count, and reports back. Bound by SafetyBudget defaults
     (max_actions_total=50, max_actions_per_sec=5).

We deliberately keep payloads in a small curated list — the goal is
proof-of-vulnerability, not exhaustive fuzzing. Comprehensive fuzz
is what D_054 / D_058 are for.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Pattern signals — these mark a provider class as a candidate.
_PROVIDER_MARKERS = (
    "extends ContentProvider",
    "extends android.content.ContentProvider",
)

# Selection / projection flowing into rawQuery / appendWhere unprotected.
_UNSAFE_SINKS_RE = re.compile(
    r"\b(rawQuery|execSQL|appendWhere|appendWhereStandalone)\s*\("
)
# Parameterised query helpers — presence in the same method downgrades.
_PARAM_HELPERS_RE = re.compile(
    r"\b(setSelectionArgs|setProjectionMap|bindString|bindLong)\b"
)
# String concatenation of the selection arg — the classic SQLi shape.
_SELECTION_CONCAT_RE = re.compile(
    r"\b(selection|where|condition)\s*\+\s*"
    r"|\+\s*(selection|where|condition)\b"
)

# Curated SQLi probe payloads — kept small on purpose.
_PROBE_PAYLOADS = [
    "' OR 1=1--",
    "1) UNION SELECT name FROM sqlite_master--",
    "x' AND 1=2 UNION SELECT 1--",
    "1; DROP TABLE users--",   # destructive — DAST harness rate-limits to 1
    "%' AND substr(sqlite_version(),1,1)>'2",
]

# Custom-ORM extension probes — activated by ADAPT_001 when the
# previous scan for this APK recorded a `custom_orm` failure context.
# Common ORM-wrapping shapes: ROOM @Query placeholders, Greenrobot
# wrappers, JOOQ-style positional binds. We never mutate state.
_CUSTOM_ORM_PROBES = [
    "1=1) AND name LIKE '%'--",       # ROOM-style positional
    ":selection OR 1=1--",            # named-parameter spillover
    "':1 OR 1=1--",                   # quoted positional
    "?1) OR 1=1--",                   # JOOQ-style
    "GROUP_CONCAT(name)--",           # column-expression bleed
]

_MAX_FILES = 1500


class ProviderSqliAgent(BaseAgent):
    """D_063: identify SQLi-able exported providers + emit DAST trigger."""

    AGENT_ID = "D_063"
    VULN_CLASS = "ContentProvider SQLi (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.decompiled_dir
            and ctx.decompiled_dir.exists()
            and ctx.manifest
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        if root is None:
            return []

        # Enumerate exported providers from the manifest
        providers = self._exported_providers(ctx.manifest or {})
        if not providers:
            return []

        # ADAPT_001: consult the per-app learning profile for any
        # recorded failure context strategies that apply to this agent.
        adaptive_strategies: list[str] = []
        if ctx.learning_profile is not None:
            try:
                from sentinel.learning import StrategySelector
                selector = StrategySelector()
                adaptive_strategies = [
                    r.strategy for r in selector.strategies_for(
                        self.AGENT_ID, ctx.learning_profile,
                    )
                ]
                if adaptive_strategies:
                    logger.info(
                        "[%s] Applying %d adaptive strategies: %s",
                        self.AGENT_ID, len(adaptive_strategies),
                        adaptive_strategies,
                    )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[%s] Strategy selector failed; using defaults",
                    self.AGENT_ID,
                )

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not any(marker in text for marker in _PROVIDER_MARKERS):
                continue
            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]

            # Match this Java class against a manifest provider entry.
            matched = next(
                (p for p in providers if p["name"].endswith(class_name)
                 or p["name"].split(".")[-1] == class_name),
                None,
            )
            if matched is None:
                continue

            # Look for unsafe sinks + selection concatenation
            sinks = [
                m.group(0) for m in _UNSAFE_SINKS_RE.finditer(text)
            ]
            has_unsafe_sink = bool(sinks)
            has_concat = bool(_SELECTION_CONCAT_RE.search(text))
            has_param_helper = bool(_PARAM_HELPERS_RE.search(text))

            if not has_unsafe_sink:
                continue
            if has_param_helper and not has_concat:
                continue  # safer — bind helpers in use, no concat seen

            # Build the Frida payload
            authority = matched.get("authority") or ""
            uri_hints = self._extract_uri_hints(text)
            payload = self._build_frida_payload(
                authority, uri_hints,
                adaptive_strategies=adaptive_strategies,
            )

            severity = Severity.HIGH if has_concat else Severity.MEDIUM
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.70,
                recommendation=(
                    f"Exported provider `{class_name}` "
                    f"(authority `{authority}`) routes the selection / "
                    "projection argument into a raw SQL sink without "
                    "parameter binding. The Frida DAST trigger will "
                    "fire 5 SQLi probe URIs against the authority and "
                    "look for distinct row counts as the exploitability "
                    "signal. Fix by switching to "
                    "SQLiteQueryBuilder.setSelectionArgs(...) and "
                    "rejecting any selection string that doesn't "
                    "match a strict allow-list."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "authority": authority,
                    "unsafe_sinks": list(set(sinks))[:5],
                    "has_selection_concat": has_concat,
                    "dynamic_target": True,
                    "frida_payload": payload,
                },
            ))
        return findings

    # ---------- manifest helpers ----------

    @staticmethod
    def _exported_providers(manifest: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in manifest.get("providers", []) or []:
            if not isinstance(p, dict):
                continue
            if p.get("exported") is True and not p.get("permission"):
                out.append(p)
        return out

    @staticmethod
    def _extract_uri_hints(text: str) -> list[str]:
        """Crude UriMatcher path-string extraction for probe URIs.

        Accepts the first argument as either a bare identifier
        (`AUTHORITY`) or a string literal (`"com.x.provider"`) — both
        are common idioms.
        """
        hits = re.findall(
            r'addURI\s*\(\s*(?:[A-Za-z0-9_.]+|"[^"]+")\s*,\s*"([^"]+)"',
            text,
        )
        # Cap and dedupe
        return list(dict.fromkeys(hits))[:8]

    @staticmethod
    def _build_frida_payload(
        authority: str, uri_hints: list[str],
        adaptive_strategies: list[str] | None = None,
    ) -> dict[str, Any]:
        # If no UriMatcher hints found, fall back to the bare authority root
        candidate_uris: list[str] = []
        if authority:
            for hint in uri_hints or [""]:
                base = f"content://{authority}"
                candidate_uris.append(
                    f"{base}/{hint}" if hint else base,
                )
        # ADAPT_001 hook: if the last scan of this APK recorded a
        # `custom_orm` failure context, extend the probe set with the
        # ROOM / Greenrobot / JOOQ-shaped payloads. Standard probes
        # still run — we widen rather than replace.
        strats = adaptive_strategies or []
        probes = list(_PROBE_PAYLOADS)
        if "custom_orm_fuzzing" in strats:
            probes = list(_CUSTOM_ORM_PROBES) + probes
        return {
            "authority": authority,
            "candidate_uris": candidate_uris,
            "probe_payloads": probes,
            "adaptive_strategies_applied": strats,
            "safety_budget": {
                "max_actions_total": 50,
                "max_actions_per_sec": 5,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                f"// D_063 — fire SQLi probes through ContentResolver\n"
                f"// authority = {authority}\n"
                f"// rpc.exports.proberprovidersqli(payload) is the entry\n",
        }


__all__ = ["ProviderSqliAgent"]
