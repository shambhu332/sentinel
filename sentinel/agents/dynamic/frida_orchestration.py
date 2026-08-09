"""Frida script load ordering and orchestration.

Scripts must be loaded in a specific order to avoid race conditions:
  1. Bypass layer  — disables SSL pinning / root detection / anti-Frida
                     BEFORE any monitored network calls are made.
  2. Monitor layer — passive observers that collect events.
  3. Deep-dive layer — heavy tracers that generate high-volume data;
                       loaded last so bypass hooks are already in place.

Loading bypass scripts after monitors means early network calls complete
before pinning is bypassed — you miss them. Loading deep-dive tracers
before monitors means some events are swallowed before the listener is
registered. The ordering here matches the DragonJAR recommendation.

Usage::

    from sentinel.agents.dynamic.frida_orchestration import (
        FRIDA_LOAD_ORDER, FridaOrchestrator,
    )
    orch = FridaOrchestrator(session, frida_agent_dir)
    await orch.load_all()
    await orch.load_phase("bypass")

Script paths are relative to the ``frida_agent/`` directory at the
repository root. Agents that need a specific subset call
:meth:`FridaOrchestrator.load_phase` with the phase name.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Canonical load order ──────────────────────────────────────────────────────
#
# Each phase is a list of script filenames. Within a phase the scripts are
# loaded sequentially (order matters for interdependencies). Phases
# themselves are loaded sequentially too, not concurrently — the bypass
# hooks must be active before monitors start listening.

FRIDA_LOAD_ORDER: dict[str, list[str]] = {
    "bypass": [
        "ssl-pinning-bypass.js",
        "root-detection-bypass.js",
        "anti-frida-bypass.js",
        "flag-secure-bypass.js",
        "rasp-bypass.js",
        "network-security-bypass.js",
    ],
    "monitor": [
        "intent-logger.js",
        "ipc-abuse-helper.js",
        "network-interceptor-enhanced.js",
        "android-file-access-monitor.js",
        "webview-monitor.js",
        "keystore-inspector.js",
        "jwt-token-monitor.js",
        "shared-prefs-dumper.js",
    ],
    "deep_dive": [
        "jni-tracer.js",
        "native-hook.js",
        "method-tracer.js",
        "biometric-bypass.js",
        "native-heap-tracer.js",
        "flutter-channel-hook.js",
        "comprehensive-tracer.js",
    ],
}

# Flat ordered list for convenience (bypass → monitor → deep_dive).
FRIDA_LOAD_ORDER_FLAT: list[str] = [
    script
    for phase in ("bypass", "monitor", "deep_dive")
    for script in FRIDA_LOAD_ORDER[phase]
]


@dataclass
class LoadResult:
    """Outcome of loading one Frida script."""
    script_name: str
    success: bool
    error: str = ""
    script_handle: Any = field(default=None, repr=False)


class FridaOrchestrator:
    """Loads Frida scripts into an active session in the correct order.

    Parameters
    ----------
    session:
        A ``frida.core.Session`` (or MCP Frida session wrapper) with a
        ``create_script(source: str)`` / ``load()`` interface.
    frida_agent_dir:
        Path to the ``frida_agent/`` directory. Defaults to the sibling
        of this file's repository root.
    message_handler:
        Optional callable ``(message: dict, data: bytes | None) -> None``
        attached to every loaded script for ``send()`` events.
    """

    def __init__(
        self,
        session: Any,
        frida_agent_dir: Path | None = None,
        message_handler: Any | None = None,
    ) -> None:
        self.session = session
        self.frida_agent_dir = (
            frida_agent_dir
            or Path(__file__).parents[3] / "frida_agent"
        )
        self.message_handler = message_handler or _default_message_handler
        self._loaded: list[LoadResult] = []

    # ---------- Public API ----------

    async def load_all(self) -> list[LoadResult]:
        """Load every script in bypass → monitor → deep_dive order."""
        for phase in ("bypass", "monitor", "deep_dive"):
            await self.load_phase(phase)
        return list(self._loaded)

    async def load_phase(self, phase: str) -> list[LoadResult]:
        """Load all scripts in one phase. Phase must be bypass/monitor/deep_dive."""
        scripts = FRIDA_LOAD_ORDER.get(phase)
        if scripts is None:
            raise ValueError(
                f"Unknown phase '{phase}'. "
                f"Valid: {list(FRIDA_LOAD_ORDER)}"
            )
        results: list[LoadResult] = []
        for script_name in scripts:
            result = await self._load_one(script_name, phase)
            results.append(result)
            self._loaded.append(result)
            if not result.success:
                logger.warning(
                    "[FridaOrch] %s failed (%s) — continuing",
                    script_name, result.error,
                )
        return results

    async def load_scripts(self, script_names: list[str]) -> list[LoadResult]:
        """Load an explicit list of scripts by filename (order preserved)."""
        results: list[LoadResult] = []
        for name in script_names:
            phase = self._phase_for(name)
            result = await self._load_one(name, phase)
            results.append(result)
            self._loaded.append(result)
        return results

    @property
    def loaded(self) -> list[LoadResult]:
        return list(self._loaded)

    @property
    def failed(self) -> list[LoadResult]:
        return [r for r in self._loaded if not r.success]

    # ---------- Internals ----------

    async def _load_one(self, script_name: str, phase: str) -> LoadResult:
        path = self.frida_agent_dir / script_name
        if not path.exists():
            return LoadResult(
                script_name=script_name,
                success=False,
                error=f"script not found: {path}",
            )
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as e:
            return LoadResult(
                script_name=script_name,
                success=False,
                error=f"read error: {e}",
            )

        try:
            handle = await asyncio.get_event_loop().run_in_executor(
                None, self._create_and_load, source, script_name,
            )
            logger.info(
                "[FridaOrch] loaded %s (%s phase)", script_name, phase,
            )
            return LoadResult(
                script_name=script_name,
                success=True,
                script_handle=handle,
            )
        except Exception as e:  # noqa: BLE001
            return LoadResult(
                script_name=script_name,
                success=False,
                error=str(e)[:300],
            )

    def _create_and_load(self, source: str, name: str) -> Any:
        script = self.session.create_script(source, name=name)
        script.on("message", self.message_handler)
        script.load()
        return script

    @staticmethod
    def _phase_for(script_name: str) -> str:
        for phase, scripts in FRIDA_LOAD_ORDER.items():
            if script_name in scripts:
                return phase
        return "unknown"


def _default_message_handler(message: dict, data: Any) -> None:
    tag = (message.get("payload") or {}).get("tag", "")
    logger.debug("[Frida:%s] %s", tag, message)


__all__ = [
    "FRIDA_LOAD_ORDER",
    "FRIDA_LOAD_ORDER_FLAT",
    "FridaOrchestrator",
    "LoadResult",
]
