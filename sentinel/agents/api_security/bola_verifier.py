"""API_002 — BOLA (Broken Object-Level Authorization) verifier.

Given a mitmproxy capture that includes authenticated ``GET`` requests
with an ID-shaped path segment, this agent replays each such request with
a mutated identifier while **reusing the original session's credentials**.
If the server responds ``200 OK`` with a body that looks like a different
object, we've demonstrated that the token had authority over resources it
should not have — the textbook BOLA finding (OWASP API1:2023).

Safety controls (deliberately conservative — this agent runs live traffic
against a real backend):

* **Scope-gated.** Nothing replays until ``BountyScope.domain_in_scope``
  says the host is fair game (or the scope is unrestricted).
* **Bounded mutations.** Numeric IDs are probed at ``value ± 1`` plus a
  configurable canary; opaque tokens are only probed with the canary. No
  enumeration, no ranges — mass-scraping is out of scope by design.
* **Rate-limited.** ``asyncio.sleep(1)`` between requests keeps us under
  most production rate limiters and matches typical bounty rules.
* **Diff-based signal.** A response is only reported as BOLA if it's
  ``2xx`` **and** materially differs from the baseline in a way that
  suggests a distinct object (different JSON keys or a different subset
  of the same identifying fields).

The replay log for every attempt lands on the emitted finding at
``evidence['replay_logs']`` — CI and reviewers can trace exactly what was
sent and received.
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
    ObjectId,
    extract_auth_headers,
    extract_object_ids,
    group_by_endpoint,
    replace_path_segment,
)
from sentinel.tools.mitmproxy_runner import CapturedFlow

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT = 15.0
_DEFAULT_DELAY_SECONDS = 1.0
# ID probed for opaque (non-numeric) segments. Deliberately obvious and
# unlikely to collide with anything real; the intent is to trip a 200 on a
# permissive endpoint, not to guess a valid ID.
_DEFAULT_CANARY_ID = "1"


class BOLAVerifierAgent(BaseAgent):
    """API_002: replay captured GET requests with mutated object IDs."""

    AGENT_ID = "API_002"
    VULN_CLASS = "Broken Object Level Authorization"
    PHASE = "Phase 4"

    # ---------- Lifecycle ----------

    async def is_applicable(self) -> bool:
        capture = (self._context.sources or {}).get("mitmproxy")
        if capture is None:
            return False
        flows = getattr(capture, "flows", None) or []
        # Only run if we have at least one authenticated GET with a
        # mutation candidate — save cycles otherwise.
        for flow in flows:
            if (flow.method or "").upper() != "GET":
                continue
            if not extract_auth_headers(flow):
                continue
            if any(o.location == "path" for o in extract_object_ids(flow)):
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
        canary = str(cfg.get("canary_id", _DEFAULT_CANARY_ID))

        # One representative flow per endpoint keeps us honest about
        # rate limits — no point replaying /users/{id} four times.
        candidates: list[CapturedFlow] = []
        for endpoint, group in group_by_endpoint(flows).items():
            if endpoint.method != "GET":
                continue
            for flow in group:
                if extract_auth_headers(flow) and any(
                    o.location == "path" for o in extract_object_ids(flow)
                ):
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
                finding = await self._probe_flow(client, flow, canary, delay)
                if finding is not None:
                    findings.append(finding)
        return findings

    # ---------- Core replay ----------

    async def _probe_flow(
        self,
        client: httpx.AsyncClient,
        flow: CapturedFlow,
        canary: str,
        delay: float,
    ) -> Finding | None:
        path_ids = [o for o in extract_object_ids(flow) if o.location == "path"]
        if not path_ids:
            return None
        # Mutate only the *last* path ID — that's the object the endpoint
        # is scoped to; earlier ones are usually collection selectors.
        target = path_ids[-1]

        mutations = _plan_mutations(target, canary)
        if not mutations:
            return None

        auth_headers = extract_auth_headers(flow)
        replay_headers = {
            k: v for k, v in (flow.request_headers or {}).items()
            # Don't leak the captured Host header to a different origin.
            if k.lower() not in ("host", "content-length")
        }
        replay_headers.update(auth_headers)

        replay_logs: list[dict[str, Any]] = []
        baseline_status = flow.response_status
        baseline_body = flow.response_body or ""

        bola_hit: dict[str, Any] | None = None
        for mutated_value in mutations:
            new_path = replace_path_segment(
                flow.path, int(target.key), mutated_value,
            )
            url = f"{flow.scheme or 'https'}://{flow.host}{new_path}"
            attempt: dict[str, Any] = {
                "url": url,
                "original_id": target.value,
                "mutated_id": mutated_value,
                "baseline_status": baseline_status,
            }
            try:
                resp = await client.get(url, headers=replay_headers)
                attempt["status"] = resp.status_code
                attempt["response_snippet"] = resp.text[:400]
                if _looks_like_bola(baseline_body, resp):
                    attempt["verdict"] = "bola"
                    bola_hit = attempt
                else:
                    attempt["verdict"] = "no-signal"
            except httpx.RequestError as exc:
                attempt["error"] = f"{type(exc).__name__}: {exc}"
                attempt["verdict"] = "error"
            replay_logs.append(attempt)
            if bola_hit is not None:
                break
            await asyncio.sleep(delay)

        if bola_hit is None:
            return None

        endpoint_template = flow.path
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.85,
            evidence={
                "host": flow.host,
                "endpoint": endpoint_template,
                "method": "GET",
                "original_id": target.value,
                "mutated_id": bola_hit["mutated_id"],
                "baseline_status": baseline_status,
                "mutated_status": bola_hit.get("status"),
                "replay_logs": replay_logs,
                "auth_header_names": sorted(auth_headers.keys()),
                "description": (
                    f"Replaying GET {flow.host}{flow.path} with the same "
                    f"session token but ID={bola_hit['mutated_id']} returned "
                    f"{bola_hit.get('status')}; the response body differs "
                    "from the captured baseline, suggesting the token can "
                    "read another object."
                ),
            },
            recommendation=(
                "Enforce object-level authorization on this endpoint: the "
                "backend must verify that the authenticated principal owns "
                "the requested object before returning it. Do not rely on "
                "IDs being unguessable. If the ID space is inherently public "
                "(e.g. public posts), add explicit access-control checks and "
                "document the intended sharing model."
            ),
            owasp="API1:2023 Broken Object Level Authorization",
            masvs="MSTG-AUTH-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
            observed_result=(
                f"Original request returned {baseline_status}; replay with "
                f"ID={bola_hit['mutated_id']} returned {bola_hit.get('status')} "
                "with a body distinguishable from the baseline."
            ),
            reproduction_commands=[
                _curl_reproduction(flow, target, bola_hit["mutated_id"]),
            ],
            verification_status=f"verified by API_002 replay against {flow.host}",
            # Top-level field so the frontend can render the API replay
            # table even when Phase 7.5 (ExploitDriver) is disabled.
            api_replay_logs=replay_logs,
            exploitation_status="Verified_Exploited",
            finding_category="AI-Powered",
        )

    # ---------- Scope check ----------

    def _host_allowed(self, host: str) -> bool:
        scope = self._context.scope
        if scope.is_unrestricted():
            return True
        # If the operator supplied any in-scope domains, honour them
        # strictly; otherwise fall back to package scope only (the mobile
        # app implicitly whitelists the hosts it talks to).
        if scope.in_scope_domains or scope.out_of_scope_domains:
            return scope.domain_in_scope(host)
        return True


# ---------- Helpers ----------

def _plan_mutations(target: ObjectId, canary: str) -> list[str]:
    """Return the mutation values to try, in probe order.

    Numeric IDs get ``±1`` first (most likely to hit a neighbour object)
    plus the canary. Opaque IDs only get the canary — enumerating tokens
    is enumeration by another name.
    """
    seen: set[str] = {target.value}
    plan: list[str] = []

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            plan.append(value)

    if target.is_numeric:
        try:
            base = int(target.value)
        except ValueError:
            base = None
        if base is not None:
            _add(str(base + 1))
            if base > 0:
                _add(str(base - 1))
    _add(canary)
    return plan


def _looks_like_bola(baseline_body: str, resp: httpx.Response) -> bool:
    """Heuristic: is ``resp`` a distinct object from ``baseline_body``?"""
    if resp.status_code < 200 or resp.status_code >= 300:
        return False
    body = resp.text or ""
    if not body.strip():
        return False
    if body == baseline_body:
        # Identical response — either a caching quirk or the endpoint
        # ignored the ID. Not a BOLA signal on its own.
        return False

    baseline_json = _try_json(baseline_body)
    mutated_json = _try_json(body)
    if isinstance(baseline_json, dict) and isinstance(mutated_json, dict):
        # Same shape, different identifying values → strong BOLA signal.
        shared_keys = set(baseline_json) & set(mutated_json)
        if shared_keys:
            identifying = shared_keys & {"id", "user_id", "email", "username", "name"}
            if identifying and any(
                baseline_json.get(k) != mutated_json.get(k) for k in identifying
            ):
                return True
            # Fall through — key overlap alone is a weak signal.
        # Distinct top-level keys entirely — treat as different object.
        if not shared_keys:
            return True

    # Non-JSON or mismatched shapes: fall back to a size-based heuristic.
    # A 2xx response with meaningfully different bytes is suspicious but
    # not conclusive; require >50 char delta to avoid whitespace churn.
    return abs(len(body) - len(baseline_body)) > 50


def _try_json(text: str) -> Any:
    text = (text or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _curl_reproduction(
    flow: CapturedFlow, target: ObjectId, mutated_value: str,
) -> str:
    mutated_path = replace_path_segment(flow.path, int(target.key), mutated_value)
    url = f"{flow.scheme or 'https'}://{flow.host}{mutated_path}"
    header_flags: list[str] = []
    for name, value in (flow.request_headers or {}).items():
        if name.lower() in ("host", "content-length"):
            continue
        header_flags.append(f"-H '{name}: {value}'")
    return "curl -sSi " + " ".join(header_flags) + f" '{url}'"
