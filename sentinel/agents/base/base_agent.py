"""BaseAgent — abstract contract every one of the 88 agents implements."""
from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

from sentinel.core.finding import Finding
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)

AGENT_ID_PATTERN = re.compile(r"^[A-Z]+_\d{3}$")


class AgentError(Exception):
    """Raised when an agent cannot complete its analysis."""


class BaseAgent(ABC):
    """Every SENTINEL agent subclasses this.

    Lifecycle:
        1. __init__ — agent instantiated with context + memory
        2. is_applicable() — returns False if agent should skip (wrong platform, etc)
        3. analyze() — does the real work, yields Findings
        4. Each finding is validated, published to memory, events emitted

    Agents that need the LLM call self._memory and self._router themselves.
    Scope enforcement is automatic: any finding whose package/domain is out-of-scope
    gets dropped before it reaches storage.
    """

    AGENT_ID: str = ""
    VULN_CLASS: str = ""
    PHASE: str = "Phase 2"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
    ) -> None:
        if not AGENT_ID_PATTERN.match(self.AGENT_ID):
            raise AgentError(f"Invalid AGENT_ID '{self.AGENT_ID}' — must match XXX_NNN")
        if not self.VULN_CLASS:
            raise AgentError(f"{self.AGENT_ID}: VULN_CLASS cannot be empty")

        self._context = context
        self._memory = memory
        self._config = config or {}
        self._log = logging.getLogger(f"agent.{self.AGENT_ID}")

    # ---------- Properties ----------

    @property
    def context(self) -> ScanContext:
        return self._context

    @property
    def memory(self) -> MemoryInterface:
        return self._memory

    # ---------- Abstract methods ----------

    @abstractmethod
    async def is_applicable(self) -> bool:
        """Return False if this agent should be skipped for this scan.

        Examples: iOS-only agents return False for Android APKs.
        Scope-based filtering is handled upstream; this is for technical fit.
        """

    @abstractmethod
    async def analyze(self) -> list[Finding]:
        """Run detection. Return zero or more Findings."""

    # ---------- Orchestration helpers ----------

    async def run(self) -> list[Finding]:
        """Entry point called by the orchestrator.

        Handles: applicability check, timeout, error isolation,
        scope filtering, event emission, memory storage.
        """
        await self._memory.publish_event(
            session_id=self._context.session_id,
            event_type="agent.started",
            payload={"agent_id": self.AGENT_ID},
        )

        try:
            if not await self.is_applicable():
                self._log.debug("%s not applicable, skipping", self.AGENT_ID)
                await self._memory.publish_event(
                    session_id=self._context.session_id,
                    event_type="agent.skipped",
                    payload={"agent_id": self.AGENT_ID, "reason": "not applicable"},
                )
                return []

            findings = await self.analyze()

        except asyncio.CancelledError:
            self._log.warning("%s cancelled", self.AGENT_ID)
            raise
        except Exception as e:  # noqa: BLE001
            self._log.exception("%s failed: %s", self.AGENT_ID, e)
            await self._memory.publish_event(
                session_id=self._context.session_id,
                event_type="agent.failed",
                payload={"agent_id": self.AGENT_ID, "error": str(e)[:500]},
            )
            return []

        # Filter findings by scope
        scoped = [f for f in findings if self._within_scope(f)]
        dropped = len(findings) - len(scoped)
        if dropped > 0:
            self._log.info("%s: dropped %d out-of-scope findings", self.AGENT_ID, dropped)

        # Save findings + emit events
        for f in scoped:
            await self._memory.save_finding(f)
            await self._memory.publish_event(
                session_id=self._context.session_id,
                event_type="finding.emitted",
                payload={
                    "agent_id": f.agent_id, "finding_id": f.finding_id,
                    "severity": f.severity.value, "vuln_class": f.vuln_class,
                },
            )

        await self._memory.publish_event(
            session_id=self._context.session_id,
            event_type="agent.completed",
            payload={"agent_id": self.AGENT_ID, "findings_count": len(scoped)},
        )
        return scoped

    # ---------- Utilities ----------

    def _within_scope(self, finding: Finding) -> bool:
        """Check if a finding's target is in bug bounty scope."""
        scope = self._context.scope
        if scope.is_unrestricted():
            return True

        evidence = finding.evidence or {}
        package = evidence.get("package")
        if package and not scope.package_in_scope(str(package)):
            return False
        return True

    def _make_finding(self, **kwargs: Any) -> Finding:
        """Build a Finding with session_id and agent_id auto-filled."""
        kwargs.setdefault("session_id", self._context.session_id)
        kwargs.setdefault("agent_id", self.AGENT_ID)
        return Finding(**kwargs)
