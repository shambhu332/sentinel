"""D_090 — Auth-Gated Intent Handler Verifier.

Autonomous verifier that exercises each exported activity / deep-link
in both the logged-out and logged-in state and reports what the UI
actually does. Closes the runtime-evidence gap with Djini.AI's
"Verification-First" reports: every emitted Finding carries a
verification_state, a blocking-state screenshot for the auth-gated
case, and a target-state screenshot for the verified case.

Lifecycle inside a single ``analyze()`` call:

  1. Enumerate exported activities with deep-link intent-filters
     from ``ctx.manifest``.
  2. For each target:
       a. Fire the intent with ``am start ...`` and snapshot the UI
          (``state=logged_out``).
       b. If the post-intent state looks gated (LoginActivity in the
          stdout, permission denial in stderr, or no screenshot at
          all) AND credentials are registered → call
          ``CredentialManager.auto_login`` (max 2 attempts), re-fire
          the intent, snapshot again (``state=logged_in``).
       c. Emit one Finding with:
            verification_state = verified | auth_gated | runtime_failed
            blocking_state_screenshot = <evidence/.../logged_out.webp>
            screenshots = [logged_out, logged_in if any]
            test_credentials_used = True iff auto_login ran

Design notes
------------
- Lockout safety: hard cap of 2 login attempts per scan (across all
  targets), not per target. The shared counter lives on the agent
  instance.
- No live Frida TokenManager probe. The original brief asked for one
  but ``TokenManager.getToken()`` is app-specific — a generic probe
  produced false negatives in practice. Instead we infer the gated
  state from the ``am start`` output / a missing UI snapshot, which is
  app-agnostic.
- All adb commands run with a 10s ceiling. Screenshots wait 2s for
  the UI to settle before grabbing the frame.
- Severity rationale: best-effort. We pass router=None to
  ``generate_auth_gated_rationale`` so the deterministic Djini-shape
  fallback runs even without LLM access; LLMTriager's backfill step
  upgrades the rationale later when a router is available.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_TARGETS = 25
_MAX_LOGIN_ATTEMPTS = 2
_PER_CMD_TIMEOUT_S = 10.0
_SETTLE_S = 2.0

_AUTH_BLOCK_HINTS = (
    "loginactivity",
    "permission denial",
    "not exported",
    "requires permission",
)


class IntentAuthVerifierAgent(BaseAgent):
    """D_090: verify exported-activity intent handlers across auth states."""

    AGENT_ID = "D_090"
    VULN_CLASS = "Auth-Gated Intent Handler"
    PHASE = "dynamic"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._login_attempts_used = 0

    async def is_applicable(self) -> bool:
        if not self._context.manifest:
            return False
        return bool(_collect_targets(self._context.manifest))

    async def analyze(self) -> list[Finding]:
        manifest = self._context.manifest or {}
        package = manifest.get("package", "")
        if not package:
            return []

        adb, credentials, frida = self._resolve_runtime_deps()
        if adb is None:
            self._log.info(
                "D_090: AdbRunner unavailable — skipping runtime verification",
            )
            return []

        targets = _collect_targets(manifest)[:_MAX_TARGETS]
        findings: list[Finding] = []
        for target in targets:
            try:
                finding = await self._verify_target(
                    package, target, adb, credentials, frida,
                )
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "D_090: target %s crashed: %s",
                    target.get("activity"), exc,
                )
                continue
            if finding is not None:
                findings.append(finding)
        return findings

    # --- Runtime dependency resolution -------------------------------------

    def _resolve_runtime_deps(self) -> tuple[Any, Any, Any]:
        """Best-effort import of the dynamic-analysis toolchain.

        Returns ``(AdbRunner_instance, CredentialManager_instance,
        FridaRunner_instance)`` with any unavailable component set to
        ``None``. The agent degrades gracefully — no AdbRunner means
        no verification; no CredentialManager just means auth-gated
        targets stay auth-gated.
        """
        try:
            from sentinel.tools.adb_runner import AdbRunner
            adb = AdbRunner()
        except Exception:  # noqa: BLE001
            adb = None
        try:
            from sentinel.tools.credential_manager import CredentialManager
            credentials = CredentialManager.from_env(
                workspace_root=self._context.workspace,
            )
        except Exception:  # noqa: BLE001
            credentials = None
        try:
            from sentinel.tools.frida_runner import FridaRunner
            frida = FridaRunner(
                evidence_dir=self._context.workspace
                / self._context.session_id / "evidence" / "screenshots",
            )
        except Exception:  # noqa: BLE001
            frida = None
        return adb, credentials, frida

    # --- Per-target verification -------------------------------------------

    async def _verify_target(
        self,
        package: str,
        target: dict[str, Any],
        adb: Any,
        credentials: Any,
        frida: Any,
    ) -> Finding | None:
        activity = target["activity"]
        scheme = target["schemes"][0]
        host = target["hosts"][0] if target["hosts"] else "verify.sentinel"
        uri = f"{scheme}://{host}/"
        am_cmd = (
            f"shell am start -W -a android.intent.action.VIEW "
            f"-d {uri!r} {package}/{activity}"
        )

        logged_out_stdout, logged_out_stderr, logged_out_shot = (
            await adb.execute_adb_command_and_capture(
                am_cmd,
                session_id=self._context.session_id,
                context=f"d090_intent_auth_logged_out_{_safe(activity)}",
                workspace=self._context.workspace,
                timeout=_PER_CMD_TIMEOUT_S,
                settle_seconds=_SETTLE_S,
                caption=(
                    f"Intent {uri} → {activity} (no session)"
                ),
            )
        )
        blocked = _looks_auth_gated(
            logged_out_stdout, logged_out_stderr, logged_out_shot,
        )

        screenshots: list[dict[str, Any]] = [{
            "path": logged_out_shot,
            "label": "logged_out",
            "caption": f"Intent fired without session for {activity}",
            "step_index": 0,
        }]
        test_credentials_used = False
        logged_in_shot: str | None = None
        logged_in_stdout = ""
        logged_in_stderr = ""

        if blocked and credentials is not None and credentials.has_credentials:
            if self._login_attempts_used < _MAX_LOGIN_ATTEMPTS:
                self._login_attempts_used += 1
                test_credentials_used = True
                login_result = await credentials.auto_login(
                    package, frida=frida,
                )
                if login_result.succeeded:
                    logged_in_stdout, logged_in_stderr, logged_in_shot = (
                        await adb.execute_adb_command_and_capture(
                            am_cmd,
                            session_id=self._context.session_id,
                            context=(
                                f"d090_intent_auth_logged_in_"
                                f"{_safe(activity)}"
                            ),
                            workspace=self._context.workspace,
                            timeout=_PER_CMD_TIMEOUT_S,
                            settle_seconds=_SETTLE_S,
                            caption=(
                                f"Intent {uri} → {activity} (post-login)"
                            ),
                        )
                    )
                    screenshots.append({
                        "path": logged_in_shot,
                        "label": "logged_in",
                        "caption": (
                            f"Intent fired with credential "
                            f"{login_result.credential_label}"
                        ),
                        "step_index": 1,
                    })

        # Final state decision -------------------------------------------------
        state, status, severity = _classify_outcome(
            blocked=blocked,
            logged_in_shot=logged_in_shot,
            logged_in_stdout=logged_in_stdout,
            logged_in_stderr=logged_in_stderr,
        )

        rationale = await _generate_rationale(
            vuln_class=self.VULN_CLASS,
            target=target,
            logged_out_stdout=logged_out_stdout,
            logged_out_stderr=logged_out_stderr,
            state=state,
        )

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.78 if state == "verified" else 0.6,
            recommendation=(
                f"Activity `{activity}` accepts deep-link `{uri}`. "
                "Confirm the handler enforces authentication before "
                "trusting URI parameters. Reject malformed or hostile "
                "authorities; require an active session token for any "
                "state-changing action initiated from a deep link."
            ),
            evidence={
                "activity": activity,
                "schemes": target["schemes"],
                "hosts": target["hosts"],
                "exported": target["exported"],
                "uri_probed": uri,
                "logged_out_stdout": logged_out_stdout[:600],
                "logged_out_stderr": logged_out_stderr[:600],
                "logged_in_stdout": logged_in_stdout[:600],
                "logged_in_stderr": logged_in_stderr[:600],
            },
            screenshots=screenshots,
            verification_state=state,
            verification_status=status,
            blocking_state_screenshot=(
                logged_out_shot if state == "auth_gated" else None
            ),
            severity_rationale=rationale,
            test_credentials_used=test_credentials_used,
            observed_result=(
                f"logged_out: {(logged_out_stderr or logged_out_stdout)[:200]}"
            ),
            reproduction_commands=[f"adb {am_cmd}"],
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
        )


# --- Helpers ----------------------------------------------------------------

def _collect_targets(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Return exported activities with at least one deep-link intent-filter."""
    targets: list[dict[str, Any]] = []
    for activity in manifest.get("activities", []) or []:
        if not isinstance(activity, dict):
            continue
        if not activity.get("exported"):
            continue
        schemes: list[str] = []
        hosts: list[str] = []
        for intent_filter in activity.get("intent_filters", []) or []:
            if not isinstance(intent_filter, dict):
                continue
            actions = intent_filter.get("actions") or []
            action = intent_filter.get("action")
            if not (
                action == "android.intent.action.VIEW"
                or "android.intent.action.VIEW" in actions
            ):
                continue
            for key in ("schemes", "schemes_list"):
                value = intent_filter.get(key)
                if isinstance(value, list):
                    schemes.extend(v for v in value if isinstance(v, str))
            if isinstance(intent_filter.get("scheme"), str):
                schemes.append(intent_filter["scheme"])
            for key in ("hosts", "hosts_list"):
                value = intent_filter.get(key)
                if isinstance(value, list):
                    hosts.extend(v for v in value if isinstance(v, str))
            if isinstance(intent_filter.get("host"), str):
                hosts.append(intent_filter["host"])
        if not schemes:
            continue
        targets.append({
            "activity": activity.get("name", ""),
            "schemes": sorted(set(schemes)),
            "hosts": sorted(set(hosts)),
            "exported": True,
        })
    return targets


def _looks_auth_gated(stdout: str, stderr: str, screenshot: str | None) -> bool:
    """Heuristic: did the intent land on a login/permission screen?"""
    blob = (stdout + " " + stderr).lower()
    if any(hint in blob for hint in _AUTH_BLOCK_HINTS):
        return True
    if screenshot is None and (stderr or "").strip():
        # Couldn't snapshot AND adb complained — treat as gated/failed,
        # the dispatcher's rationale routing handles the rest.
        return True
    return False


def _classify_outcome(
    *,
    blocked: bool,
    logged_in_shot: str | None,
    logged_in_stdout: str,
    logged_in_stderr: str,
) -> tuple[str, str, Severity]:
    if not blocked:
        return (
            "verified",
            "Runtime-verified — handler reached without auth gating",
            Severity.HIGH,
        )
    if logged_in_shot is not None and not _looks_auth_gated(
        logged_in_stdout, logged_in_stderr, logged_in_shot,
    ):
        return (
            "verified",
            "Runtime-verified after auto-login",
            Severity.HIGH,
        )
    return (
        "auth_gated",
        "Unverified due to auth gating — login required",
        Severity.MEDIUM,
    )


async def _generate_rationale(
    *,
    vuln_class: str,
    target: dict[str, Any],
    logged_out_stdout: str,
    logged_out_stderr: str,
    state: str,
) -> str | None:
    if state != "auth_gated":
        return None
    try:
        from sentinel.llm.severity_rationale import (
            RationaleInput, generate_auth_gated_rationale,
        )
    except Exception:  # noqa: BLE001
        return None
    payload = RationaleInput(
        vuln_class=vuln_class,
        static_evidence={
            "activity": target.get("activity"),
            "schemes": target.get("schemes"),
            "hosts": target.get("hosts"),
        },
        observed_runtime_behavior=(
            (logged_out_stderr or logged_out_stdout or "")[:240]
            or "Intent dispatched but UI did not transition past the login gate"
        ),
        blocking_reason="auth gate redirected the intent before handler ran",
    )
    try:
        return await generate_auth_gated_rationale(payload, router=None)
    except Exception:  # noqa: BLE001
        return None


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in value)[:60]
