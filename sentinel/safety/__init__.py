"""Safety primitives — rate limiting + crash budgets for aggressive agents.

DAST agents that fuzz (D_042 deep-link bomb, D_054 GraphQL fuzzer,
D_058 WebSocket injector) can brick a test device when run unbounded.
This package exposes a single `SafetyBudget` object every aggressive
agent threads through its action loop.

The budget enforces three independent limits:

  * **Rate**             — max actions/second (token bucket)
  * **Total**            — hard cap on number of actions per scan
  * **Wall-clock**       — overall seconds-spent budget
  * **Consecutive crashes** — N back-to-back exceptions trips the
                              breaker and refuses further actions

Failures degrade gracefully — `await budget.acquire()` returns False
when any limit fires; callers check the boolean and stop the loop.
"""
from sentinel.safety.budget import (
    SafetyBreakerTripped,
    SafetyBudget,
    SafetyConfig,
)

__all__ = ["SafetyBreakerTripped", "SafetyBudget", "SafetyConfig"]
