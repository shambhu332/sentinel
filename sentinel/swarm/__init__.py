"""Adversarial agent swarm — Red/Blue LLM chain per finding."""
from sentinel.swarm.orchestrator import (
    BlueAgentOutput,
    RedAgentOutput,
    SwarmOrchestrator,
    SwarmResult,
)
from sentinel.swarm.sanitize import sanitize_evidence

__all__ = [
    "BlueAgentOutput",
    "RedAgentOutput",
    "SwarmOrchestrator",
    "SwarmResult",
    "sanitize_evidence",
]
