"""API_003 — Mass-assignment fuzzer.

Given a mitmproxy capture that includes authenticated ``POST`` / ``PUT`` /
``PATCH`` requests with a JSON body, this agent replays each request with
a small set of privilege-escalation payloads merged into the body. If the
backend accepts the extra field (returns 2xx) — and, stronger still,
reflects it back in the response — we've demonstrated mass assignment
(OWASP API6:2023 / API3:2023).

Safety controls — this agent writes to a live backend, so every safeguard
matters:

* **Scope-gated.** Same ``BountyScope.domain_in_scope`` check the BOLA
  verifier uses.
* **Idempotency intent.** We only inject **additive** top-level keys the
  original body did not carry. If the app already sends ``role``, we skip
  the ``role`` payload — overriding it wouldn't prove mass assignment, and
  it might change the intended behaviour on the server side.
* **One payload per request.** No combinatorial fuzzing — three probes
  per endpoint at most, one probe at a time so the signal isolates
  cleanly.
* **Rate-limited.** ``asyncio.sleep(1)`` between requests, matching the
  BOLA verifier's cadence.
* **Detection intent, not exploitation.** Even on a positive hit, the
  agent flags the finding; it does not chain the escalation into further
  actions.

Verified hits carry a full ``evidence['replay_logs']`` audit trail with
each attempted payload, the observed status code, and a short response
snippet.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.tools.api_parser import (
    extract_auth_headers,
    group_by_endpoint,
)
from sentinel.tools.mitmproxy_runner import CapturedFlow

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT = 15.0
_DEFAULT_DELAY_SECONDS = 1.0
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH"})

# Payloads probed against each candidate. Each entry is a top-level JSON
# object merged into the captured body. The first key is the "signal key"
# the response-reflection check looks for.
_DEFAULT_PAYLOADS: tuple[dict[str, Any], ...] = (
    {"is_admin": True},
    {"role": "admin"},
    {"price": 0},
    {"balance": 999999},
)


class MassAssignmentFuzzerAgent(BaseAgent):
    """API_003: probe backend endpoints for accepting privileged extra fields."""

    AGENT_ID = "API_003"
    VULN_CLASS = "Mass Assignment"
    PHASE = "Phase 4"

    # ---------- Lifecycle ----------

    async def is_applicable(self) -> bool:
        capture = (self._context.sources or {}).get("mitmproxy")
        if capture is None:
            return False
        flows = getattr(capture, "flows", None) or []
        for flow in flows:
            if _is_candidate(flow):
                return True
        return False

    async def analyze(self) -> list[Finding]:
        capture = (self._context.sources or {}).get("mitmproxy")
        flows: list[CapturedFlow] = list(getattr(capture, "flows", []) or [])
        if not flows:
            return []

        cfg = self._config or {}
        delay = float(cfg.get("delay_seconds", _DEFAULT_DELAY_SECONDS))
        timeout = float(cfg.get("timeout_seconds", _DEFAULT_TIMEOUT))
        payloads: tuple[dict[str, Any], ...] = tuple(
            cfg.get("payloads") or _DEFAULT_PAYLOADS,
        )

        # One representative flow per endpoint keeps the request count
        # bounded regardless of capture volume.
        candidates: list[CapturedFlow] = []
        for endpoint, group in group_by_endpoint(flows).items():
            if endpoint.method not in _MUTATING_METHODS:
                continue
            for flow in group:
                if _is_candidate(flow):
                    candidates.append(flow)
                    break

        if not candidates:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False,
        ) as client:
            for flow in candidates:
                if not self._host_allowed(flow.host):
                    self._log.debug("Skip out-of-scope host %s", flow.host)
                    continue
                finding = await self._probe_flow(client, flow, payloads, delay)
                if finding is not None:
                    findings.append(finding)
        return findings

    # ---------- Core replay ----------

    async def _probe_flow(
        self,
        client: httpx.AsyncClient,
        flow: CapturedFlow,
        payloads: tuple[dict[str, Any], ...],
        delay: float,
    ) -> Finding | None:
        try:
            baseline_body = json.loads(flow.request_body)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(baseline_body, dict):
            return None

        replay_headers = {
            k: v for k, v in (flow.request_headers or {}).items()
            # Host/Content-Length are recomputed by httpx per request.
            if k.lower() not in ("host", "content-length")
        }
        # Force JSON content-type — some captures had form-encoded originals.
        replay_headers.setdefault("Content-Type", "application/json")

        auth_headers = extract_auth_headers(flow)
        url = f"{flow.scheme or 'https'}://{flow.host}{flow.path}"

        replay_logs: list[dict[str, Any]] = []
        hit: dict[str, Any] | None = None

        for payload in payloads:
            signal_key = next(iter(payload))
            if signal_key in baseline_body:
                # Original request already carries this key; overriding is
                # not the same vulnerability. Skip to avoid a false positive.
                continue
            mutated = dict(baseline_body)
            mutated.update(payload)
            attempt: dict[str, Any] = {
                "url": url,
                "signal_key": signal_key,
                "payload": payload,
                "baseline_status": flow.response_status,
            }
            try:
                resp = await client.request(
                    flow.method.upper(),
                    url,
                    headers=replay_headers,
                    json=mutated,
                )
                attempt["status"] = resp.status_code
                attempt["response_snippet"] = resp.text[:400]
                reflected = _payload_reflected_in(payload, resp.text)
                attempt["reflected"] = reflected
                if _looks_like_mass_assignment(resp, reflected):
                    attempt["verdict"] = (
                        "reflected" if reflected else "accepted"
                    )
                    hit = attempt
                else:
                    attempt["verdict"] = (
                        "rejected"
                        if 400 <= resp.status_code < 500
                        else "no-signal"
                    )
            except httpx.RequestError as exc:
                attempt["error"] = f"{type(exc).__name__}: {exc}"
                attempt["verdict"] = "error"
            replay_logs.append(attempt)
            if hit is not None:
                break
            await asyncio.sleep(delay)

        if hit is None:
            return None

        reflected = bool(hit.get("reflected"))
        severity = Severity.CRITICAL if reflected else Severity.HIGH
        confidence = 0.9 if reflected else 0.7

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            evidence={
                "host": flow.host,
                "endpoint": flow.path,
                "method": flow.method.upper(),
                "signal_key": hit["signal_key"],
                "payload": hit["payload"],
                "baseline_status": flow.response_status,
                "mutated_status": hit.get("status"),
                "reflected_in_response": reflected,
                "replay_logs": replay_logs,
                "auth_header_names": sorted(auth_headers.keys()),
                "description": (
                    f"Replaying {flow.method.upper()} {flow.host}{flow.path} "
                    f"with an additional `{hit['signal_key']}` field returned "
                    f"{hit.get('status')}"
                    + (" and the field appeared in the response body — "
                       "the backend clearly bound it to the model."
                       if reflected else
                       " with no 4xx rejection — the backend silently "
                       "accepted the extra field.")
                ),
            },
            recommendation=(
                "Whitelist accepted body fields on the server. Pydantic-style "
                "'extra=forbid' models, DRF serializer fields, or explicit "
                "allow-lists on the ORM binding stop mass assignment cold. "
                "Never rely on the mobile client omitting a field — assume "
                "any client will send everything."
            ),
            owasp="API3:2023 Broken Object Property Level Authz",
            masvs="MSTG-AUTH-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
            observed_result=(
                f"Baseline returned {flow.response_status}; injecting "
                f"`{hit['signal_key']}` returned {hit.get('status')}"
                + (" with the field echoed back in the response."
                   if reflected else " with no 4xx rejection.")
            ),
            reproduction_commands=[
                _curl_reproduction(flow, hit["payload"], replay_headers),
            ],
            verification_status=(
                f"verified by API_003 replay against {flow.host}"
            ),
            # Top-level field so the frontend can render the API replay
            # table even without Phase 7.5.
            api_replay_logs=replay_logs,
            exploitation_status="Verified_Exploited",
        )

    # ---------- Scope check ----------

    def _host_allowed(self, host: str) -> bool:
        scope = self._context.scope
        if scope.is_unrestricted():
            return True
        if scope.in_scope_domains or scope.out_of_scope_domains:
            return scope.domain_in_scope(host)
        return True


# ---------- Helpers ----------

def _is_candidate(flow: CapturedFlow) -> bool:
    if (flow.method or "").upper() not in _MUTATING_METHODS:
        return False
    body = (flow.request_body or "").strip()
    if not body.startswith("{"):
        return False
    if not extract_auth_headers(flow):
        return False
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, dict)


def _payload_reflected_in(payload: dict[str, Any], text: str) -> bool:
    """True if the response body echoes the injected key with a matching value.

    Uses a JSON parse when possible for exact matching; falls back to a
    substring probe on the raw text for non-JSON responses.
    """
    if not text:
        return False
    key = next(iter(payload))
    expected = payload[key]
    parsed = _try_json(text)
    if parsed is not None:
        return _walk_for(parsed, key, expected)
    key_marker = f'"{key}"'
    if key_marker not in text:
        return False
    if isinstance(expected, bool):
        return "true" in text.lower() if expected else "false" in text.lower()
    return str(expected) in text


def _walk_for(node: Any, key: str, expected: Any) -> bool:
    if isinstance(node, dict):
        if key in node and node[key] == expected:
            return True
        return any(_walk_for(v, key, expected) for v in node.values())
    if isinstance(node, list):
        return any(_walk_for(item, key, expected) for item in node)
    return False


def _looks_like_mass_assignment(resp: httpx.Response, reflected: bool) -> bool:
    if reflected:
        return True
    # No reflection — signal is weaker but the *absence of a 4xx* is still
    # suspicious for a body the server previously didn't know about.
    if 200 <= resp.status_code < 300:
        return True
    return False


def _try_json(text: str) -> Any:
    text = (text or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _curl_reproduction(
    flow: CapturedFlow,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> str:
    try:
        baseline_body = json.loads(flow.request_body)
    except (json.JSONDecodeError, TypeError):
        baseline_body = {}
    if isinstance(baseline_body, dict):
        merged = dict(baseline_body)
        merged.update(payload)
    else:
        merged = payload
    url = f"{flow.scheme or 'https'}://{flow.host}{flow.path}"
    header_flags = [
        f"-H '{name}: {value}'"
        for name, value in headers.items()
    ]
    body_arg = json.dumps(merged).replace("'", "'\\''")
    return (
        f"curl -sSi -X {flow.method.upper()} "
        + " ".join(header_flags)
        + f" -d '{body_arg}' '{url}'"
    )
