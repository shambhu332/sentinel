"""Agent registry endpoints — derived live from the Python class registry.

Originally this endpoint shipped a hand-curated `_REGISTRY` literal
that drifted out of sync as new agents landed (the audit flagged
D_073/D_074/D_078/D_081 + the D_08x batch as missing). We now derive
the registry by introspecting every loaded BaseAgent subclass at
import time so the endpoint is always up to date.

For backward compatibility the response model is unchanged; missing
metadata (severity / description) falls back to sensible defaults
when the agent class doesn't expose them.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.agents.base.base_agent import BaseAgent

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agents", tags=["agents"])


class AgentInfo(BaseModel):
    id: str
    name: str
    category: str
    phase: str
    severity: str
    description: str


def _category_for(cls: type[BaseAgent]) -> str:
    """Best-effort category from the module path the class lives in."""
    mod = cls.__module__
    if ".dynamic" in mod:
        return "Dynamic"
    if ".auth" in mod or ".auth_storage" in mod:
        return "Authentication"
    if ".crypto" in mod or ".data_storage" in mod or ".shared_prefs" in mod:
        return "Crypto/Storage"
    if ".network" in mod:
        return "Network"
    if ".business" in mod or ".logic" in mod:
        return "Business Logic"
    if ".privacy" in mod:
        return "Privacy"
    if ".platform" in mod or ".deep_links" in mod:
        return "Android Platform"
    if ".supply_chain" in mod:
        return "Supply Chain"
    if ".webview" in mod:
        return "WebView"
    if ".native" in mod or ".reflection" in mod:
        return "Native / Reflection"
    if ".meta" in mod:
        return "Meta"
    if ".reporting" in mod:
        return "Reporting"
    if ".correlation" in mod:
        return "Correlation"
    if ".firebase" in mod:
        return "Firebase"
    if ".resilience" in mod:
        return "Resilience"
    if ".crossplatform" in mod:
        return "Cross-Platform"
    if ".ui" in mod:
        return "UI / Gesture"
    return "Other"


def _description_for(cls: type[BaseAgent]) -> str:
    """Pull a short description from the class docstring."""
    doc = (cls.__doc__ or "").strip()
    if not doc:
        return cls.__name__
    # First non-blank line, capped.
    first = next((ln.strip() for ln in doc.splitlines() if ln.strip()), "")
    return first[:280] or cls.__name__


def _discover_subclasses() -> list[type[BaseAgent]]:
    """Walk every sentinel.agents.* package so subclasses register."""
    try:
        agents_pkg = importlib.import_module("sentinel.agents")
    except ImportError:
        return []
    for _finder, name, _ispkg in pkgutil.walk_packages(
        agents_pkg.__path__, prefix="sentinel.agents.",
    ):
        try:
            importlib.import_module(name)
        except Exception as e:  # noqa: BLE001
            logger.debug("Could not import %s for registry: %s", name, e)
    # Walk every subclass of BaseAgent recursively.
    seen: dict[str, type[BaseAgent]] = {}
    stack: list[type[BaseAgent]] = list(BaseAgent.__subclasses__())
    while stack:
        cls = stack.pop()
        aid = getattr(cls, "AGENT_ID", "")
        if aid and aid not in seen:
            seen[aid] = cls
        stack.extend(cls.__subclasses__())
    return list(seen.values())


def _build_registry() -> list[AgentInfo]:
    out: list[AgentInfo] = []
    for cls in _discover_subclasses():
        aid = getattr(cls, "AGENT_ID", "")
        if not aid:
            continue
        try:
            out.append(AgentInfo(
                id=aid,
                name=getattr(cls, "VULN_CLASS", "") or cls.__name__,
                category=_category_for(cls),
                phase=getattr(cls, "PHASE", "Phase 2"),
                severity="varies",  # severity is per-finding, not per-agent
                description=_description_for(cls),
            ))
        except Exception:  # noqa: BLE001
            logger.exception("registry build skip: %s", cls)
    out.sort(key=lambda x: x.id)
    return out


# Built once at import time. Cheap — only does walk_packages + getattr.
_REGISTRY: list[AgentInfo] = _build_registry()


@router.get("", response_model=list[AgentInfo])
def list_agents(category: str | None = None) -> list[AgentInfo]:
    """List all agents. Optional ?category= filter."""
    if category:
        return [a for a in _REGISTRY if a.category.lower() == category.lower()]
    return _REGISTRY


@router.get("/{agent_id}", response_model=AgentInfo)
def get_agent(agent_id: str) -> AgentInfo:
    """Fetch a single agent by ID (e.g., D_063)."""
    for a in _REGISTRY:
        if a.id == agent_id.upper():
            return a
    raise HTTPException(status_code=404, detail=f"agent {agent_id} not found")


def reload_registry() -> int:
    """Force a registry rebuild (used by tests)."""
    global _REGISTRY
    _REGISTRY = _build_registry()
    return len(_REGISTRY)
