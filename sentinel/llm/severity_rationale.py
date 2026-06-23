"""LLM-generated severity rationales for auth-gated findings.

When the DAST pipeline can't reach the vulnerable surface because of an
auth gate, we still want the report to explain the residual risk in
plain English. This module turns the four available signals —

  - vulnerability class (e.g. "Deep Link Scheme Confusion")
  - static evidence (the originating SAST finding's evidence dict)
  - observed runtime behaviour (e.g. "Redirected to LoginActivity")
  - blocking-state description (e.g. "auto-login script returned auth.fail")

into a two-sentence Djini-style rationale of the form::

    Dynamic exploitability was not confirmed because <blocking reason>,
    but the risk remains for authenticated users if <attack condition>.

Integration:
- ``LLMTriager`` calls ``generate_auth_gated_rationale`` whenever a
  finding's ``verification_state == "auth_gated"`` after its own pass.
- The router is shared with the triager, so circuit-breaker / failover
  behaviour comes free.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sentinel.llm.router import FreeProviderRouter, RouterError

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = (
    "You are a senior mobile security engineer writing a finding "
    "rationale for an enterprise VAPT report. Style: precise, "
    "calm, exactly two sentences, no hedging like 'might' / 'could' "
    "unless evidence demands it.\n\n"
    "You will be given:\n"
    "  - vulnerability class (the bug being investigated)\n"
    "  - static evidence (what static analysis saw in the code)\n"
    "  - observed runtime behaviour (what the device did during DAST)\n"
    "  - blocking reason (why the runtime probe could not reach the bug)\n\n"
    "Write exactly two sentences in this shape:\n"
    "  Sentence 1: 'Dynamic exploitability was not confirmed "
    "because <blocking reason>, ...'\n"
    "  Sentence 2: '...but the risk remains for authenticated users "
    "if <attack condition>.'\n\n"
    "Output JSON only: {\"rationale\": \"<two sentences>\"}. No markdown, "
    "no preamble, no trailing commentary."
)


@dataclass
class RationaleInput:
    """Bundle the four fields the LLM needs to author a rationale."""

    vuln_class: str
    static_evidence: dict[str, Any]
    observed_runtime_behavior: str
    blocking_reason: str

    def as_user_message(self) -> str:
        """Render the inputs into a single user-message payload."""
        # Keep the evidence dict trimmed — the LLM only needs the summary
        # / title / vector / sample fields, not the full multi-KB dump.
        trimmed: dict[str, Any] = {}
        for key in (
            "title", "summary", "vector", "schemes", "hosts", "activity",
            "factory", "flags_expr", "code", "manifest_uses_cleartext_traffic",
        ):
            if key in self.static_evidence:
                trimmed[key] = self.static_evidence[key]
        return (
            f"Vulnerability class: {self.vuln_class}\n"
            f"Observed runtime behaviour: "
            f"{self.observed_runtime_behavior or '(none captured)'}\n"
            f"Blocking reason: {self.blocking_reason}\n"
            f"Static evidence (trimmed):\n"
            f"{json.dumps(trimmed, indent=2, default=str)[:1800]}"
        )


def _fallback_rationale(payload: RationaleInput) -> str:
    """Deterministic template used when the LLM router is unavailable.

    Same two-sentence shape as the LLM output so consumers don't need a
    code path for missing rationale.
    """
    return (
        f"Dynamic exploitability was not confirmed because "
        f"{payload.blocking_reason.rstrip('.')}, but the risk remains "
        f"for authenticated users if a logged-in account reaches the "
        f"{payload.vuln_class.lower()} surface identified in static "
        f"analysis."
    )


async def generate_auth_gated_rationale(
    payload: RationaleInput,
    *,
    router: FreeProviderRouter | None = None,
    max_tokens: int = 240,
) -> str:
    """Generate an auth-gated severity rationale.

    Always returns a non-empty string. Falls back to a deterministic
    template when no LLM provider is available — the report layer
    treats both the same, so the bucket-split UI is never blank.
    """
    if router is None:
        router = FreeProviderRouter()

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": payload.as_user_message()},
    ]

    try:
        response = await router.query(
            messages=messages,
            tier="T2",
            temperature=0.2,
            max_tokens=max_tokens,
            json_mode=True,
        )
    except RouterError as exc:
        logger.info("[rationale] router unavailable, using template: %s", exc)
        return _fallback_rationale(payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[rationale] LLM call failed: %s", exc)
        return _fallback_rationale(payload)

    content = (response or {}).get("content") or ""
    rationale = _extract_rationale(content)
    if not rationale:
        logger.info(
            "[rationale] empty/invalid LLM payload — using template",
        )
        return _fallback_rationale(payload)
    return rationale[:1500]


def _extract_rationale(content: str) -> str:
    """Pull the rationale string out of the LLM's JSON envelope.

    Tolerant of:
      - clean JSON: ``{"rationale": "..."}``
      - JSON wrapped in a code fence
      - the model accidentally writing prose with the rationale on one line
    """
    if not content:
        return ""
    text = content.strip()
    # Strip markdown fences if the model added them.
    if text.startswith("```"):
        text = text.split("```", 2)
        text = text[1] if len(text) >= 2 else ""
        # Drop a leading "json\n" hint.
        if text.startswith("json"):
            text = text.split("\n", 1)[-1]
        text = text.strip().rstrip("`").strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # Last-resort: maybe the model just dumped the sentence pair.
        if "." in text:
            return text.split("\n", 1)[0].strip()
        return ""
    if isinstance(obj, dict):
        value = obj.get("rationale")
        if isinstance(value, str):
            return value.strip()
    return ""


__all__ = [
    "RationaleInput",
    "generate_auth_gated_rationale",
]
