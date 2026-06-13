"""Adversarial agent swarm — Red/Blue (+ optional Purple) LLM chain."""
from sentinel.swarm.orchestrator import (
    BlueAgentOutput,
    PurpleAgentOutput,
    RedAgentOutput,
    SwarmOrchestrator,
    SwarmResult,
)
from sentinel.swarm.sanitize import sanitize_evidence

__all__ = [
    "BlueAgentOutput",
    "PurpleAgentOutput",
    "RedAgentOutput",
    "SwarmOrchestrator",
    "SwarmResult",
    "sanitize_evidence",
]
