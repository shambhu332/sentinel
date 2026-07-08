"""Base class for all DAST runtime agents."""
from __future__ import annotations

import asyncio
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.scan_context import ScanContext
from sentinel.core.finding import Finding, Severity


@dataclass
class RuntimeEvent:
    """A single event captured at runtime via Frida."""
    agent_id: str
    event_type: str  # "method_call", "finding", "hook_error", "taint_source", "taint_sink"
    timestamp: float
    data: dict[str, Any] = field(default_factory=dict)
    thread_id: str = "unknown"


class BaseDASTAgent(BaseAgent):
    """
    Base class for DAST agents that instrument a running Android app via Frida.

    Subclasses implement:
      get_frida_script() -> str   — the combined Frida JS to load
      analyze_events(events, ctx) -> list[Finding]  — interpret collected events
    """

    AGENT_ID: str = "D_000"
    VULN_CLASS: str = "DAST"
    _DESCRIPTION: str = "Base DAST agent"

    def __init__(
        self,
        context: ScanContext,
        memory: Any,
        config: Any = None,
        *,
        device_serial: str | None = None,
        dast_duration: int = 60,
    ) -> None:
        super().__init__(context=context, memory=memory, config=config)
        self.device_serial = device_serial
        self.dast_duration = dast_duration
        self._events: list[RuntimeEvent] = []

    # ------------------------------------------------------------------
    # Subclass contract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_frida_script(self) -> str:
        """Return the Frida JavaScript to inject into the target process."""

    @abstractmethod
    async def analyze_events(
        self,
        events: list[RuntimeEvent],
        ctx: ScanContext,
    ) -> list[Finding]:
        """Interpret collected runtime events and return findings."""

    # ------------------------------------------------------------------
    # BaseAgent contract
    # ------------------------------------------------------------------

    async def is_applicable(self) -> bool:
        """DAST agents require a connected device or emulator."""
        try:
            import frida  # type: ignore[import]
            if self.device_serial:
                frida.get_device(self.device_serial)
            else:
                frida.get_usb_device(timeout=2)
            return True
        except Exception:
            return False

    async def analyze(self) -> list[Finding]:
        """Run Frida instrumentation and return findings."""
        ctx = self.context
        try:
            import frida  # type: ignore[import]
        except (ImportError, TypeError):
            return [self._no_device_finding(ctx, "frida not installed")]

        package_name = self._extract_package(ctx)
        if not package_name:
            return [self._no_device_finding(ctx, "could not determine package name")]

        try:
            device = (
                frida.get_device(self.device_serial)
                if self.device_serial
                else frida.get_usb_device(timeout=5)
            )
            pid = device.spawn([package_name])
            session = device.attach(pid)
            script = session.create_script(self.get_frida_script())
            script.on("message", self._on_message)
            script.load()
            device.resume(pid)

            await asyncio.sleep(self.dast_duration)

            findings = await self.analyze_events(self._events, ctx)
            session.detach()
            return findings

        except Exception as exc:  # noqa: BLE001
            return [self._no_device_finding(ctx, str(exc)[:200])]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _on_message(self, message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "send":
            payload = message["payload"]
            self._events.append(RuntimeEvent(
                agent_id=payload.get("agent_id", self.AGENT_ID),
                event_type=payload.get("event_type", "unknown"),
                timestamp=float(payload.get("timestamp", 0)) / 1000.0,
                data=payload,
                thread_id=str(payload.get("thread_id", "unknown")),
            ))

    def _extract_package(self, ctx: ScanContext) -> str | None:
        manifest = ctx.workspace / "apktool" / "AndroidManifest.xml"
        if manifest.exists():
            try:
                import xml.etree.ElementTree as ET
                root = ET.parse(manifest).getroot()
                return root.get("package")
            except Exception:
                pass
        # Fallback: read from scan context metadata or manifest dict
        if ctx.manifest:
            pkg = ctx.manifest.get("package")
            if pkg:
                return pkg
        return getattr(ctx, "package_name", None)

    def _no_device_finding(self, ctx: ScanContext, reason: str) -> Finding:
        return Finding(
            agent_id=self.AGENT_ID,
            session_id=ctx.session_id,
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.0,
            severity_rationale=f"DAST skipped: {reason}",
            evidence={"reason": reason},
            recommendation=(
                "Connect an Android device or emulator and ensure "
                "Frida server is running."
            ),
            compliance_tags=[],
            finding_category="Static_Tool",
        )
