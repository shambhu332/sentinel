"""Dynamic-target dispatcher — fires the rpc.exports surface for every
hybrid SAST→DAST finding whose evidence carries `dynamic_target: True`.

Without this dispatcher, the hybrid agents shipped findings the Frida
hooks could service but nothing actually invoked them — the audit
called this out as a critical gap. The dispatcher runs at Phase 4.5,
right after the existing Frida hook injection, so every TS hook is
already registered in `script.exports`.

Mapping from AGENT_ID -> rpc.exports method name. Kept in sync with
each Frida hook's `rpc.exports = { <name>: ... }` declaration. New
hybrid agents add one entry here when they ship.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from sentinel.core.finding import Finding
from sentinel.tools.frida_runner import FridaRunner

logger = logging.getLogger(__name__)


# AGENT_ID -> rpc.exports method name (must match the TS hook).
_AGENT_TO_RPC: dict[str, str] = {
    "D_042": "deeplinkbomb",
    "D_043": "hiddenapiprobe",
    "D_044": "biometricreplay",
    "D_045": "sqliteprober",
    "D_046": "triggerrace",
    "D_047": "memorydump",
    "D_048": "webviewxss",
    "D_049": "notificationsnoop",
    "D_050": "pinningstress",
    "D_051": "serviceprobe",
    "D_052": "symbolicintent",
    "D_053": "sidechannel",
    "D_054": "graphqlfuzzer",
    "D_055": "nativeheap",
    "D_056": "biometrictiming",
    "D_057": "statepoisoner",
    "D_058": "websocketinjector",
    "D_059": "clipboardhijack",
    "D_060": "sensorspoofing",
    "D_061": "keyextractor",
    "D_062": "binderbomb",
    "D_063": "proberprovidersqli",
    "D_064": "jobhijacker",
    "D_065": "proberfileprovider",
    "D_066": "a11yabuser",
    "D_067": "splitapkfuzzer",
    "D_068": "wearablebridge",
    "D_070": "pipspy",
    "D_071": "twabreaker",
    "D_072": "jnishadow",
    "D_073": "pendingintentesc",
    "D_074": "schemeconfuser",
    "D_078": "biometricunwrapper",
    "D_082": "iapspoofing",
    "D_083": "mobilessrf",
    "D_084": "webviewxssuniversal",
    "D_085": "providerlfi",
    "D_086": "intentxss",
}


async def dispatch_dynamic_targets(
    findings: list[Finding],
    frida: FridaRunner,
    max_concurrent: int = 2,
    per_call_timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Fire each dynamic_target finding's frida_payload via Frida RPC.

    Returns a structured summary the orchestrator records under
    `phase4_5_dispatch` so the report layer can show per-agent
    dispatch results.

    Concurrency is intentionally low (max 2). Aggressive hooks like
    D_062 binder bomb and D_072 jni shadow must not run in parallel
    — they share kernel resources and a runaway pair could brick
    the test device.
    """
    targets = [
        f for f in findings
        if (f.evidence or {}).get("dynamic_target") is True
        and isinstance((f.evidence or {}).get("frida_payload"), dict)
        and f.agent_id in _AGENT_TO_RPC
    ]
    if not targets:
        return {"dispatched": 0, "results": [], "skipped": 0}

    semaphore = asyncio.Semaphore(max(1, max_concurrent))

    async def _fire(finding: Finding) -> dict[str, Any]:
        async with semaphore:
            method = _AGENT_TO_RPC[finding.agent_id]
            payload = (finding.evidence or {})["frida_payload"]
            logger.info(
                "[dispatch] %s -> %s", finding.agent_id, method,
            )
            try:
                result = await frida.dispatch_rpc(
                    method, payload, timeout_s=per_call_timeout_s,
                )
            except Exception as e:  # noqa: BLE001
                logger.exception(
                    "[dispatch] %s crashed", finding.agent_id,
                )
                return {
                    "agent_id": finding.agent_id,
                    "finding_id": finding.finding_id,
                    "method": method,
                    "ok": False,
                    "error": str(e)[:300],
                }
            return {
                "agent_id": finding.agent_id,
                "finding_id": finding.finding_id,
                "method": method,
                "ok": result.success,
                "error": result.error,
                "data": result.data if result.success else None,
            }

    results = await asyncio.gather(
        *(_fire(t) for t in targets), return_exceptions=False,
    )
    successful = sum(1 for r in results if r.get("ok"))
    return {
        "dispatched": len(results),
        "succeeded": successful,
        "failed": len(results) - successful,
        "results": results,
    }


__all__ = ["dispatch_dynamic_targets"]
