"""Adaptive planner — chooses the next agent to run based on findings.

The planner is intentionally narrow:

* It owns no scanning logic.
* Each BaseAgent subclass becomes one ``AgentTool`` the LLM can call.
* On each tick it sees a compact summary of findings so far (NOT raw
  evidence — too noisy / private) and a list of remaining tools.
* It returns ``PlannerDecision`` indicating which tool to fire next,
  with what strategy hint (handed through to the agent via
  ``ctx.adaptive_strategies``), or that the scan should stop.

Two modes are supported:

  * **llm**: free-LLM-driven (`FreeProviderRouter`). The LLM gets a
    short structured prompt and a JSON schema to fill in. Decisions
    are *advisory* — the planner cross-checks the tool name against
    the registry and silently falls back to the next-priority tool
    on any malformed response.
  * **heuristic**: no LLM. The planner picks tools by static priority:
    high-impact agents first, then everything else in registry order.
    Used when no LLM is available or when ``ctx.is_private`` requests
    fully offline mode without Ollama.

Failure modes:
* If the LLM is down, fall back to heuristic mode.
* If a tool raises, log + continue with the next one.
* If the planner loop has run > ``max_steps``, stop (the procedural
  orchestrator runs everything anyway, so this just caps planner
  overhead).

The planner does NOT replace the orchestrator. It runs *in parallel*
to it — concretely, after Phase 2 has finished, the planner gets the
list of agents that haven't been fired and runs them in
LLM-recommended order with possible adaptive strategy hints. The
finding stream is identical; only the *order* and *adaptation* change.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentTool:
    """One agent the planner can call as a 'tool'."""

    agent_id: str
    name: str
    phase: str
    category: str
    severity_hint: str
    # The Python class the orchestrator instantiates. Kept off the tool
    # schema sent to the LLM (it would just bloat the prompt).
    cls: Any = field(repr=False, compare=False)


@dataclass
class PlannerDecision:
    next_tool: str | None        # None → stop
    strategy: str = ""           # propagated as adaptive_strategy hint
    reason: str = ""


# Priority order when no LLM is available — high-impact dynamic
# probes first, then runtime hooks, then SAST sweeps, then audit
# agents last. Used by both modes (LLM falls back to this if its
# response is malformed).
_PRIORITY_AGENT_PREFIXES = (
    "D_072",  # JNI shadow — RCE
    "D_063",  # provider SQLi
    "D_062",  # binder bomb
    "D_054",  # GraphQL fuzz
    "D_052",  # symbolic intent
    "D_046",  # race condition
    "API_001",  # API inventory
    "D_",      # rest of the dynamic batch
    "TAINT_001",
    "REFL_001",
    "C_",
    "N_",
    "P_",
    "A_",
)


def _priority_of(agent_id: str) -> int:
    for i, prefix in enumerate(_PRIORITY_AGENT_PREFIXES):
        if agent_id.startswith(prefix):
            return i
    return len(_PRIORITY_AGENT_PREFIXES)


class AdaptivePlanner:
    """Picks one agent to run at a time, optionally LLM-driven."""

    def __init__(
        self,
        tools: list[AgentTool],
        router: Any = None,
        max_steps: int = 200,
    ) -> None:
        self.tools = tools
        self.router = router      # FreeProviderRouter | None
        self.max_steps = max_steps
        self._executed: set[str] = set()
        self._step = 0

    @property
    def remaining(self) -> list[AgentTool]:
        return [t for t in self.tools if t.agent_id not in self._executed]

    def mark_done(self, agent_id: str) -> None:
        self._executed.add(agent_id)

    async def decide(self, findings_so_far: list[Finding]) -> PlannerDecision:
        """Pick the next agent to fire.

        Always falls back to the heuristic decision when the LLM call
        fails / returns garbage / is unavailable.
        """
        self._step += 1
        if self._step > self.max_steps:
            return PlannerDecision(next_tool=None,
                                   reason=f"max_steps={self.max_steps} hit")

        remaining = self.remaining
        if not remaining:
            return PlannerDecision(next_tool=None,
                                   reason="all agents executed")

        heuristic = self._heuristic_decision(findings_so_far, remaining)
        if self.router is None:
            return heuristic

        try:
            llm = await self._llm_decision(findings_so_far, remaining)
            if llm.next_tool and any(t.agent_id == llm.next_tool for t in remaining):
                return llm
            logger.debug(
                "Planner: LLM picked unknown tool %r; falling back to heuristic",
                llm.next_tool,
            )
        except Exception as e:  # noqa: BLE001
            logger.info("Planner: LLM decision failed (%s); using heuristic", e)
        return heuristic

    # ------------------- heuristic mode -------------------

    def _heuristic_decision(
        self, findings_so_far: list[Finding], remaining: list[AgentTool],
    ) -> PlannerDecision:
        # Pick the highest-priority remaining tool.
        best = min(remaining, key=lambda t: _priority_of(t.agent_id))
        # Light context-aware strategy: if any HIGH/CRITICAL has fired
        # already, hint the next agent to widen its probe set.
        any_high = any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings_so_far
        )
        strategy = "extended_payload_set" if any_high else ""
        return PlannerDecision(
            next_tool=best.agent_id,
            strategy=strategy,
            reason=(
                "highest-priority remaining agent"
                + (" (extended set: high-sev finding present)" if strategy else "")
            ),
        )

    # ------------------- llm mode -------------------

    async def _llm_decision(
        self, findings_so_far: list[Finding], remaining: list[AgentTool],
    ) -> PlannerDecision:
        # Summarise findings into <=20 lines to keep the prompt tight.
        summary_lines = []
        for f in findings_so_far[-30:]:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            summary_lines.append(
                f"- {f.agent_id} {sev} {f.vuln_class}"[:200]
            )
        # Tool inventory — id + phase + category is enough for the LLM.
        tool_lines = [
            f"- {t.agent_id}  ({t.category}, {t.phase})"
            for t in remaining[:60]
        ]
        prompt = (
            "You are the SENTINEL adaptive planner. Given the findings"
            " observed so far and the remaining mobile-security agents,"
            " choose ONE agent to run next.\n\n"
            f"Findings so far ({len(findings_so_far)}):\n"
            + "\n".join(summary_lines or ["(none yet)"])
            + "\n\nRemaining agents:\n"
            + "\n".join(tool_lines)
            + '\n\nRespond with strict JSON: '
              '{"next":"<agent_id>","strategy":"<optional hint>","why":"<short>"}'
        )
        # Free-tier router exposes a `.generate()` async method.
        raw = await self.router.generate(prompt, max_tokens=120, temperature=0.1)
        text = (raw or "").strip()
        # Strip ``` fencing if present.
        if text.startswith("```"):
            text = text.strip("`").lstrip("json").strip()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            raise ValueError(f"non-JSON planner response: {text[:120]!r}")
        return PlannerDecision(
            next_tool=str(obj.get("next") or "") or None,
            strategy=str(obj.get("strategy") or ""),
            reason=str(obj.get("why") or "llm"),
        )


def tools_from_classes(agent_classes: list[type]) -> list[AgentTool]:
    """Turn a list of BaseAgent subclasses into planner tools."""
    out: list[AgentTool] = []
    for cls in agent_classes:
        aid = getattr(cls, "AGENT_ID", "")
        if not aid:
            continue
        out.append(AgentTool(
            agent_id=aid,
            name=cls.__name__,
            phase=getattr(cls, "PHASE", "Phase 2"),
            category=cls.__module__.split(".")[-2] if "." in cls.__module__ else "other",
            severity_hint="varies",
            cls=cls,
        ))
    return out


__all__ = [
    "AdaptivePlanner", "AgentTool", "PlannerDecision",
    "tools_from_classes",
]
