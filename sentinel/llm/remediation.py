"""LLM-suggested remediation patches — for human review, never auto-apply.

A separate pass after triage. For every finding that LLM triage marked
``VERIFIED`` we ask the same router for a unified-diff fix. The
contract with the LLM is strict:

* The system prompt instructs the model to output **only** a unified
  diff inside a single fenced `````diff`` block, with
  no prose.
* If the model believes it cannot produce a safe fix it must emit the
  literal sentinel ``NO_SAFE_FIX`` instead.

We then validate the response with the ``unidiff`` library. Any of
the failure modes (LLM error, malformed diff, ``NO_SAFE_FIX``,
zero-hunk diff) results in ``patch_status=UNAVAILABLE`` rather than
a crash — patch generation is a quality-of-life feature; it must
never sink a scan.

**The disclaimer is the whole story.** Every successful patch carries
a human-readable warning that:

1. the diff was generated against decompiled bytecode, NOT the
   original source, so a literal ``patch -p1`` won't apply, and
2. the change is a suggestion that requires human review before
   adoption — security-critical edits cannot be machine-decided.

That disclaimer travels with the finding into the report, into the
``.diff`` file header, and into any UI that surfaces it. Removing it
is a regression — tests pin its presence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

try:
    from unidiff import PatchSet
    from unidiff.errors import UnidiffParseError
    _HAS_UNIDIFF = True
except ImportError:  # pragma: no cover — declared in pyproject.toml
    _HAS_UNIDIFF = False
    PatchSet = None  # type: ignore[assignment]
    UnidiffParseError = Exception  # type: ignore[assignment, misc]

from sentinel.core.finding import Finding
from sentinel.triage.models import TriageOutcome
from sentinel.triage.triager import LLMTriager

logger = logging.getLogger(__name__)


# ---------- Public constants ----------

#: Verbatim string the model emits when it declines to suggest a fix.
NO_SAFE_FIX_SENTINEL = "NO_SAFE_FIX"

#: Patch status strings written into ``evidence["patch_status"]``.
PATCH_STATUS_SUGGESTED = "SUGGESTED_REVIEW_REQUIRED"
PATCH_STATUS_UNAVAILABLE = "UNAVAILABLE"

#: The human-review disclaimer attached to every successful patch.
#: Single source of truth — tests assert on this string verbatim.
DISCLAIMER = (
    "AI Suggested — Requires Human Review. "
    "Generated against decompiled code. "
    "Apply equivalent change to original source after manual review."
)

#: Tier on the LLM router used for remediation. Tier 1 = strong models
#: (Cerebras / Groq Llama-3.3-70b); we want code-generation quality,
#: not the cheaper triage tier.
_DEFAULT_LLM_TIER = "T1"

#: Cap the snippet we send to the model to keep prompts bounded.
_MAX_SNIPPET_CHARS = 4000

#: Cap the response we read from the model. A patch large enough to
#: exceed this is almost certainly not the focused fix we asked for.
_MAX_RESPONSE_TOKENS = 1500


# ---------- Result wrapper ----------

@dataclass
class PatchResult:
    """Outcome of one remediation attempt — separate from Finding so
    callers can decide what to attach without round-tripping through
    Pydantic on every change."""
    status: str                 # PATCH_STATUS_*
    diff_text: str | None       # raw unified diff, or None
    reason: str | None = None   # why UNAVAILABLE (for debugging / docs)


# ---------- Prompt ----------

# Kept module-level so tests can call _build_prompt() and assert
# stability of the wording. The prompt is intentionally terse and
# imperative — small models honour explicit format constraints far
# more reliably than soft requests.
_SYSTEM_PROMPT = (
    "You are a senior secure-code reviewer. You will be shown a single "
    "Android vulnerability and the affected code. Output ONLY a "
    "unified-diff patch that fixes the specific vulnerability and "
    "nothing else. Do not change unrelated logic, do not refactor, "
    "do not add comments, do not add tests. "
    "Wrap the diff in a single fenced ```diff block. "
    "If you cannot produce a safe fix, output exactly the single line "
    f"{NO_SAFE_FIX_SENTINEL} (no diff, no other text)."
)


def _build_prompt(finding: Finding) -> list[dict[str, str]]:
    """Render the OpenAI-style messages array for one finding.

    Trimmed to bound prompt size — pathological evidence (e.g. a
    serialised string table) is truncated rather than rejected.
    """
    snippet = _extract_snippet(finding)[:_MAX_SNIPPET_CHARS]
    file = _extract_file(finding) or "(unknown file)"
    recommendation = (finding.recommendation or "").strip()
    user = (
        f"vuln_class: {finding.vuln_class}\n"
        f"file: {file}\n"
        f"agent_recommendation: {recommendation}\n"
        f"\n"
        f"Vulnerable code (decompiled — line numbers approximate):\n"
        f"```\n{snippet}\n```\n"
        f"\n"
        f"Produce the minimal unified diff that fixes the vulnerability."
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user},
    ]


# ---------- Field extraction (mirrors core/diff.py shape) ----------

def _extract_snippet(finding: Finding) -> str:
    ev = finding.evidence or {}
    for key in ("code", "snippet", "context", "matched_line", "summary"):
        val = ev.get(key)
        if isinstance(val, str) and val.strip():
            return val
    trace = ev.get("trace")
    if isinstance(trace, list) and trace:
        last = trace[-1]
        if isinstance(last, dict) and last.get("code"):
            return str(last["code"])
    # Fall back to the recommendation text as context — better than
    # nothing for findings whose evidence shape is exotic.
    return finding.recommendation or ""


def _extract_file(finding: Finding) -> str:
    ev = finding.evidence or {}
    for key in ("source_file", "sink_file", "file", "path",
                "decompiled_file", "java_file"):
        val = ev.get(key)
        if val:
            return str(val)
    trace = ev.get("trace")
    if isinstance(trace, list) and trace:
        last = trace[-1]
        if isinstance(last, dict) and last.get("file"):
            return str(last["file"])
    return ""


# ---------- Response parsing ----------

def parse_llm_response(text: str) -> PatchResult:
    """Validate that ``text`` is either ``NO_SAFE_FIX`` or a well-formed
    unified diff, and return a :class:`PatchResult` describing the
    outcome.

    Public function (no underscore) because tests use it directly to
    pin the parser shape without going through the LLM mock.
    """
    if text is None:
        return PatchResult(
            PATCH_STATUS_UNAVAILABLE, None, "empty response",
        )

    stripped = text.strip()
    if not stripped:
        return PatchResult(
            PATCH_STATUS_UNAVAILABLE, None, "empty response",
        )

    # Honour the model's "I decline" path verbatim — even if it's
    # buried inside whitespace or a code fence.
    if NO_SAFE_FIX_SENTINEL in stripped:
        # …unless the model also included a substantive diff alongside
        # it. Treat that as ambiguous and prefer UNAVAILABLE.
        body = _extract_diff_body(stripped)
        if body is None:
            return PatchResult(
                PATCH_STATUS_UNAVAILABLE, None,
                "model returned NO_SAFE_FIX",
            )

    body = _extract_diff_body(stripped)
    if body is None:
        return PatchResult(
            PATCH_STATUS_UNAVAILABLE, None,
            "response did not contain a fenced diff block",
        )

    if not _HAS_UNIDIFF:
        # Library missing: accept the diff as-is. The tests pin this
        # path; the library is declared in pyproject.toml so users
        # will always have it.
        return PatchResult(PATCH_STATUS_SUGGESTED, body)

    try:
        patch = PatchSet(body)
    except (UnidiffParseError, ValueError) as e:
        return PatchResult(
            PATCH_STATUS_UNAVAILABLE, None,
            f"unidiff parse failed: {e}",
        )

    # An empty PatchSet means we got ````diff\n```` with
    # nothing inside — equivalent to NO_SAFE_FIX.
    if len(patch) == 0:
        return PatchResult(
            PATCH_STATUS_UNAVAILABLE, None,
            "diff block contained zero hunks",
        )

    return PatchResult(PATCH_STATUS_SUGGESTED, body)


def _extract_diff_body(text: str) -> str | None:
    """Pull the contents of a `````diff … `````
    fence. Falls back to the whole text if it already *looks* like a
    diff (starts with ``--- ``).
    """
    fence_start = text.find("```diff")
    if fence_start != -1:
        body_start = text.find("\n", fence_start) + 1
        fence_end = text.find("```", body_start)
        if fence_end == -1:
            return None
        body = text[body_start:fence_end].strip()
        return body or None

    # Some models drop the ``diff`` tag.
    fence_start = text.find("```")
    if fence_start != -1:
        body_start = text.find("\n", fence_start) + 1
        fence_end = text.find("```", body_start)
        if fence_end != -1:
            body = text[body_start:fence_end].strip()
            if body and body.startswith(("--- ", "diff ")):
                return body

    # No fence at all — accept if it really is a diff.
    if text.startswith(("--- ", "diff ")):
        return text
    return None


# ---------- Generator ----------

class RemediationGenerator:
    """Drive the LLM router to produce one patch per VERIFIED finding.

    The router must implement an async ``query(messages, tier=..., …)``
    method whose return value is ``{"content": str, ...}`` — that's
    the public surface of :class:`FreeProviderRouter`. Tests pass a
    minimal stub with the same shape.
    """

    def __init__(self, router: Any) -> None:
        self._router = router
        self._log = logger

    async def generate_patches(
        self, findings: list[Finding],
    ) -> list[Finding]:
        """For each VERIFIED finding in ``findings``, attach a patch.

        Non-verified findings are left untouched. The same list is
        returned (mutated in place) so callers can chain the result
        through downstream rendering without re-keying.
        """
        for f in findings:
            if not self._should_patch(f):
                continue
            try:
                result = await self._generate_one(f)
            except Exception as e:  # noqa: BLE001
                # Router failures must never sink the scan — log and
                # mark the finding UNAVAILABLE.
                self._log.warning(
                    "[remediation] %s: router error %s: %s",
                    f.agent_id, type(e).__name__, e,
                )
                result = PatchResult(
                    PATCH_STATUS_UNAVAILABLE, None,
                    f"router error: {type(e).__name__}",
                )
            _attach_patch(f, result)
        return findings

    # ---------- Helpers ----------

    @staticmethod
    def _should_patch(finding: Finding) -> bool:
        """Only VERIFIED findings get patches.

        UNCERTAIN and FILTERED findings are explicitly skipped per the
        spec — UNCERTAIN because we don't yet know the bug is real
        (don't waste an LLM call on noise), FILTERED because the
        triage step already decided it isn't a bug (don't fix what
        isn't broken).
        """
        result = LLMTriager._get_result(finding)
        return result is not None and result.outcome == TriageOutcome.VERIFIED

    async def _generate_one(self, finding: Finding) -> PatchResult:
        messages = _build_prompt(finding)
        response = await self._router.query(
            messages=messages,
            tier=_DEFAULT_LLM_TIER,
            temperature=0.0,
            max_tokens=_MAX_RESPONSE_TOKENS,
        )
        content = (response or {}).get("content") if isinstance(response, dict) else None
        if content is None:
            return PatchResult(
                PATCH_STATUS_UNAVAILABLE, None,
                "router returned no content",
            )
        return parse_llm_response(str(content))


# ---------- Attach helpers ----------

def _attach_patch(finding: Finding, result: PatchResult) -> None:
    """Stash patch metadata into ``finding.evidence``.

    Fields written:
      * ``suggested_patch``    — the diff text (or None on UNAVAILABLE)
      * ``patch_status``       — PATCH_STATUS_*
      * ``patch_disclaimer``   — DISCLAIMER (only when SUGGESTED)
      * ``patch_unavailable_reason`` — debug string (only when UNAVAILABLE)

    Avoid clobbering existing evidence keys — we're an additive pass.
    """
    if finding.evidence is None:
        finding.evidence = {}
    finding.evidence["patch_status"] = result.status
    finding.evidence["suggested_patch"] = result.diff_text
    if result.status == PATCH_STATUS_SUGGESTED:
        finding.evidence["patch_disclaimer"] = DISCLAIMER
    else:
        finding.evidence["patch_unavailable_reason"] = (
            result.reason or "unknown"
        )


# ---------- File writer ----------

def render_diff_file(finding: Finding) -> str | None:
    """Render the contents of a ``output/patches/<finding_id>.diff``
    file, including the human-review banner header. Returns ``None``
    if the finding has no suggested patch — callers should not write
    a file in that case.

    Banner format:

      # SENTINEL AI-Suggested Patch — requires human review.
      # finding_id: <id>
      # vuln_class: <class>
      # agent_id:   <id>
      # severity:   <name>
      #
      # <DISCLAIMER>
      #
      # ----------------------------------------------------------
      <diff>
    """
    ev = finding.evidence or {}
    diff_text = ev.get("suggested_patch")
    if not diff_text:
        return None

    banner = "\n".join(
        f"# {line}" for line in (
            "SENTINEL AI-Suggested Patch — requires human review.",
            f"finding_id: {finding.finding_id}",
            f"vuln_class: {finding.vuln_class}",
            f"agent_id:   {finding.agent_id}",
            f"severity:   {finding.severity.value}",
            "",
            DISCLAIMER,
            "",
            "-" * 58,
        )
    )
    return banner + "\n" + str(diff_text).rstrip() + "\n"


__all__ = [
    "RemediationGenerator", "PatchResult",
    "parse_llm_response", "render_diff_file",
    "DISCLAIMER",
    "PATCH_STATUS_SUGGESTED", "PATCH_STATUS_UNAVAILABLE",
    "NO_SAFE_FIX_SENTINEL",
]
