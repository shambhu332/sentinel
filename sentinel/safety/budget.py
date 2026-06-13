"""SafetyBudget — rate / total / wall-clock / crash limits for fuzzers.

Standard usage from inside an aggressive agent::

    budget = SafetyBudget(SafetyConfig(
        max_actions_total=200, max_actions_per_sec=10.0,
        wall_clock_budget_s=60.0, max_consecutive_crashes=5,
    ))
    for payload in payloads:
        if not await budget.acquire():
            logger.warning("Safety budget exhausted; stopping fuzz loop")
            break
        try:
            await fire(payload)
            budget.record_success()
        except Exception:
            budget.record_failure()

The token bucket is monotonic-clock-driven and lock-free for single-task
agents. Tested up to ~5000 actions/scan.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SafetyConfig:
    """Tunable limits per agent. Defaults are reasonable for device fuzzing."""

    max_actions_total: int = 200
    max_actions_per_sec: float = 10.0
    wall_clock_budget_s: float = 60.0
    max_consecutive_crashes: int = 5


class SafetyBreakerTripped(RuntimeError):
    """Raised when an action is forced through a tripped breaker."""


@dataclass
class SafetyBudget:
    """Stateful budget threaded through an aggressive agent's loop."""

    config: SafetyConfig = field(default_factory=SafetyConfig)
    _actions_fired: int = 0
    _consecutive_crashes: int = 0
    _started_at: float = field(default_factory=time.monotonic)
    _tokens: float = 0.0
    _last_refill: float = field(default_factory=time.monotonic)
    _tripped: bool = False
    _trip_reason: str = ""

    # ---------- public surface ----------

    async def acquire(self) -> bool:
        """Block until a token is available; return False if any limit fires."""
        if self._tripped:
            return False
        if self._actions_fired >= self.config.max_actions_total:
            self._trip("max_actions_total exceeded")
            return False
        if (time.monotonic() - self._started_at) >= self.config.wall_clock_budget_s:
            self._trip("wall_clock_budget exceeded")
            return False
        # Token bucket: refill, then wait if empty.
        await self._await_token()
        self._actions_fired += 1
        return True

    def record_success(self) -> None:
        self._consecutive_crashes = 0

    def record_failure(self) -> None:
        self._consecutive_crashes += 1
        if self._consecutive_crashes >= self.config.max_consecutive_crashes:
            self._trip(
                f"max_consecutive_crashes ({self.config.max_consecutive_crashes}) tripped",
            )

    def stats(self) -> dict[str, float | int | bool | str]:
        return {
            "actions_fired": self._actions_fired,
            "consecutive_crashes": self._consecutive_crashes,
            "wall_clock_used_s": round(time.monotonic() - self._started_at, 3),
            "tripped": self._tripped,
            "trip_reason": self._trip_reason,
        }

    @property
    def tripped(self) -> bool:
        return self._tripped

    # ---------- helpers ----------

    async def _await_token(self) -> None:
        rate = self.config.max_actions_per_sec
        if rate <= 0:
            return  # rate disabled
        capacity = max(rate, 1.0)
        while True:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now
            self._tokens = min(capacity, self._tokens + elapsed * rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # Sleep just long enough for the next token to appear.
            needed = 1.0 - self._tokens
            await asyncio.sleep(needed / rate)

    def _trip(self, reason: str) -> None:
        if self._tripped:
            return
        self._tripped = True
        self._trip_reason = reason
        logger.warning("[safety] breaker tripped: %s", reason)


__all__ = ["SafetyBreakerTripped", "SafetyBudget", "SafetyConfig"]
