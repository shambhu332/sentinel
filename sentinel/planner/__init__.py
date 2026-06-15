"""SENTINEL adaptive planner — LLM-driven agent orchestration.

The planner wraps the existing procedural orchestrator with a small
tool-calling loop. After each agent runs, the planner sees the
findings so far and decides which agent to schedule next (or to stop
early). This is the open-source twin of djini.ai's 'agentic SAST/DAST'
claim — the difference being that ours is grounded in an explicit
agent registry and is fully inspectable.

The planner is OFF by default. Procedural scans still run unchanged.
Opt in with ``--planner`` on the CLI or ``planner=True`` on the API.
"""
from sentinel.planner.planner import AdaptivePlanner, AgentTool, PlannerDecision

__all__ = ["AdaptivePlanner", "AgentTool", "PlannerDecision"]
