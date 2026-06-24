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
from pathlib import Path
from typing import Any

from sentinel.core.finding import Finding
from sentinel.tools.frida_runner import FridaRunner

logger = logging.getLogger(__name__)

# Agents we automatically wrap with before/after device screenshots.
# Add IDs as more hybrid agents become screenshot-worthy. Kept narrow
# on purpose — screencap adds ~250-400ms per call and is only useful
# for agents whose probe produces a visible UI/state change.
_SCREENSHOT_AGENTS: frozenset[str] = frozenset(
    {"D_073", "D_074", "D_078", "D_084"},
)


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
    *,
    session_id: str | None = None,
    workspace: Path | None = None,
    credential_manager: Any | None = None,
    rationale_router: Any | None = None,
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

    # Lazy import so the dispatcher stays importable when adb is missing
    # (e.g. CI-only static scans). Only constructed if at least one
    # screenshot-worthy agent is in the dispatch set.
    adb = None
    if session_id and workspace and any(
        f.agent_id in _SCREENSHOT_AGENTS for f in targets
    ):
        try:
            from sentinel.tools.adb_runner import AdbRunner
            adb = AdbRunner()
        except Exception as exc:  # noqa: BLE001
            logger.debug("[dispatch] AdbRunner unavailable: %s", exc)
            adb = None

    async def _capture(finding: Finding, label: str, step_index: int,
                       caption: str) -> dict | None:
        if adb is None or finding.agent_id not in _SCREENSHOT_AGENTS:
            return None
        shot = await adb.capture_screenshot(
            session_id=session_id,  # type: ignore[arg-type]
            filename=f"{finding.agent_id.lower()}_{label}",
            workspace=workspace,  # type: ignore[arg-type]
            caption=caption,
            step_index=step_index,
        )
        # Attach to the originating finding so the UI renders it under
        # the matching repro step. .screenshots tolerates both dict
        # and string entries per the Pydantic validator.
        finding.screenshots = list(finding.screenshots or []) + [shot]
        return shot

    async def _attempt_login(finding: Finding) -> Any | None:
        """Try auto-login for screenshot-worthy agents.

        Returns the AuthResult (truthy) when an attempt was made — even
        on auth_gated outcomes. Returns None when there's no credential
        manager wired or the agent isn't in the screenshot allow-list.
        """
        if credential_manager is None:
            return None
        if finding.agent_id not in _SCREENSHOT_AGENTS:
            return None
        package = (finding.evidence or {}).get("package") or (
            (finding.evidence or {}).get("frida_payload") or {}
        ).get("package", "")
        if not package:
            return None
        try:
            result = await credential_manager.auto_login(
                package, frida=frida,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[dispatch] auto_login crashed for %s: %s",
                finding.agent_id, exc,
            )
            return None
        finding.test_credentials_used = True
        return result

    async def _mark_auth_gated(
        finding: Finding, login_result: Any,
    ) -> dict[str, Any]:
        """Set the Djini-style auth-gated fields on the finding."""
        reason = getattr(login_result, "reason", "") or "auto-login blocked"
        finding.verification_state = "auth_gated"
        finding.verification_status = (
            f"Unverified due to auth gating — {reason[:96]}"
        )
        blocked = await _capture(
            finding, "auth_blocked", step_index=0,
            caption=(
                f"Login gate blocked {finding.agent_id} runtime probe"
            ),
        )
        if blocked and blocked.get("path"):
            finding.blocking_state_screenshot = blocked["path"]
        # LLM rationale — graceful fallback if router not wired.
        try:
            from sentinel.llm.severity_rationale import (
                RationaleInput, generate_auth_gated_rationale,
            )
            rationale = await generate_auth_gated_rationale(
                RationaleInput(
                    vuln_class=finding.vuln_class,
                    static_evidence=finding.evidence or {},
                    observed_runtime_behavior=(
                        finding.observed_result
                        or "Probe blocked before reaching vulnerable surface"
                    ),
                    blocking_reason=reason,
                ),
                router=rationale_router,
            )
            finding.severity_rationale = rationale
        except Exception as exc:  # noqa: BLE001
            logger.debug("[dispatch] rationale generation failed: %s", exc)
        return {
            "agent_id": finding.agent_id,
            "finding_id": finding.finding_id,
            "method": _AGENT_TO_RPC[finding.agent_id],
            "ok": False,
            "auth_gated": True,
            "error": reason,
            "screenshots": [blocked] if blocked else [],
        }

    async def _fire(finding: Finding) -> dict[str, Any]:
        async with semaphore:
            method = _AGENT_TO_RPC[finding.agent_id]
            payload = (finding.evidence or {})["frida_payload"]
            logger.info(
                "[dispatch] %s -> %s", finding.agent_id, method,
            )

            login = await _attempt_login(finding)
            if login is not None and not getattr(login, "succeeded", False):
                # Auth-gated: don't dispatch the RPC — the probe can't
                # reach the vulnerable surface. Route to AI-Powered bucket
                # via verification_state and let the rationale generator
                # explain the residual risk.
                return await _mark_auth_gated(finding, login)

            before = await _capture(
                finding, "before", step_index=0,
                caption=f"State before {finding.agent_id} runtime probe",
            )

            try:
                result = await frida.dispatch_rpc(
                    method, payload, timeout_s=per_call_timeout_s,
                )
            except Exception as e:  # noqa: BLE001
                logger.exception(
                    "[dispatch] %s crashed", finding.agent_id,
                )
                # Capture the blocking state so reviewers see what the
                # device looked like at the moment of failure.
                blocked = await _capture(
                    finding, "blocked", step_index=1,
                    caption=f"Device state when {finding.agent_id} crashed",
                )
                reason = str(e)[:200] or "dispatch crashed"
                finding.verification_status = (
                    f"Unverified at runtime — {reason}"
                )
                finding.verification_state = "runtime_failed"
                if blocked and blocked.get("path"):
                    finding.blocking_state_screenshot = blocked["path"]
                return {
                    "agent_id": finding.agent_id,
                    "finding_id": finding.finding_id,
                    "method": method,
                    "ok": False,
                    "error": str(e)[:300],
                    "screenshots": [s for s in (before, blocked) if s],
                }

            if not result.success:
                # RPC returned cleanly but reported failure — document
                # the reason on the finding itself, not just in
                # dispatcher telemetry, so the bucket classifier and UI
                # can route it as "Unverified".
                blocked = await _capture(
                    finding, "blocked", step_index=1,
                    caption=f"Device state when {finding.agent_id} blocked",
                )
                reason = result.error or "probe returned failure"
                finding.verification_status = (
                    f"Unverified at runtime — {reason[:200]}"
                )
                finding.verification_state = "runtime_failed"
                if blocked and blocked.get("path"):
                    finding.blocking_state_screenshot = blocked["path"]
                return {
                    "agent_id": finding.agent_id,
                    "finding_id": finding.finding_id,
                    "method": method,
                    "ok": False,
                    "error": result.error,
                    "data": None,
                    "screenshots": [s for s in (before, blocked) if s],
                }

            after = await _capture(
                finding, "after", step_index=1,
                caption=f"State after {finding.agent_id} runtime probe",
            )
            # Mark the discrete state so the bucket classifier routes
            # this into AI-Powered AppSec without grepping the
            # free-form verification_status string.
            finding.verification_state = "verified"
            return {
                "agent_id": finding.agent_id,
                "finding_id": finding.finding_id,
                "method": method,
                "ok": True,
                "error": None,
                "data": result.data,
                "screenshots": [s for s in (before, after) if s],
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
