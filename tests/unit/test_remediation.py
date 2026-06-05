"""Unit tests for LLM-suggested remediation (sentinel/llm/remediation.py)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.finding import Finding, Severity
from sentinel.llm.remediation import (
    DISCLAIMER,
    NO_SAFE_FIX_SENTINEL,
    PATCH_STATUS_SUGGESTED,
    PATCH_STATUS_UNAVAILABLE,
    RemediationGenerator,
    parse_llm_response,
    render_diff_file,
)
from sentinel.triage.models import TriageOutcome, TriageResult, TriageVerdict
from sentinel.triage.triager import LLMTriager

# ---------- Mock router ----------

class _MockRouter:
    """Minimal stand-in for FreeProviderRouter — records calls and
    returns a queued response.

    ``responses`` is a list popped front-to-back; each call to
    ``query()`` consumes one entry. If the entry is an Exception, it
    is raised — useful for testing router-failure handling. If it is
    a string, that's used as the ``content`` of a dict response.
    """

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def query(self, *, messages, tier="T1", **kwargs):
        self.calls.append({
            "messages": messages, "tier": tier, **kwargs,
        })
        if not self.responses:
            raise AssertionError("Mock router exhausted")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return {
            "content": nxt,
            "provider": "mock",
            "model": "mock-model",
        }


# ---------- Helpers ----------

def _verified_finding(
    *, agent_id: str = "C_007",
    vuln_class: str = "WEAK_CRYPTO",
    code: str = 'Cipher c = Cipher.getInstance("AES");',
    file: str = "com/example/Crypto.java",
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    """Build a finding pre-marked with TriageOutcome.VERIFIED."""
    f = Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.9,
        evidence={"source_file": file, "code": code},
        recommendation=(
            "Use authenticated encryption: AES/GCM/NoPadding with a "
            "random IV per message."
        ),
        session_id="patch_test_sess_1",
    )
    LLMTriager._attach_result(f, TriageResult(
        outcome=TriageOutcome.VERIFIED,
        verdict=TriageVerdict(
            is_real_bug=True,
            confidence=0.95,
            explanation=(
                "ECB-mode default; CBC without authentication on "
                "user data."
            ),
        ),
    ))
    return f


def _filtered_finding(**kwargs) -> Finding:
    f = _verified_finding(**kwargs)
    LLMTriager._attach_result(f, TriageResult(
        outcome=TriageOutcome.FILTERED,
        verdict=TriageVerdict(
            is_real_bug=False, confidence=0.9,
            explanation="Sanitizer present.",
            false_positive_reason="Input is constant",
        ),
    ))
    return f


def _uncertain_finding(**kwargs) -> Finding:
    f = _verified_finding(**kwargs)
    LLMTriager._attach_result(f, TriageResult(
        outcome=TriageOutcome.UNCERTAIN, verdict=None, error="rate-limit",
    ))
    return f


def _untriaged_finding(**kwargs) -> Finding:
    """Finding with no _triage marker at all — pre-triage state."""
    return Finding(
        agent_id=kwargs.get("agent_id", "C_007"),
        vuln_class=kwargs.get("vuln_class", "WEAK_CRYPTO"),
        severity=Severity.MEDIUM, confidence=0.9,
        evidence={"source_file": "x.java", "code": "x"},
        recommendation="rec",
        session_id="patch_test_sess_1",
    )


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# Realistic diff payload used by several tests below.
VALID_DIFF = """```diff
--- a/com/example/Crypto.java
+++ b/com/example/Crypto.java
@@ -10,1 +10,1 @@
-        Cipher c = Cipher.getInstance("AES");
+        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
```"""

VALID_DIFF_BODY = (
    "--- a/com/example/Crypto.java\n"
    "+++ b/com/example/Crypto.java\n"
    "@@ -10,1 +10,1 @@\n"
    '-        Cipher c = Cipher.getInstance("AES");\n'
    '+        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'
)


# =========================================================================
# Parser
# =========================================================================

def test_parse_valid_unified_diff_returns_suggested() -> None:
    r = parse_llm_response(VALID_DIFF)
    assert r.status == PATCH_STATUS_SUGGESTED
    assert r.diff_text is not None
    assert "AES/GCM/NoPadding" in r.diff_text
    assert r.reason is None


def test_parse_no_safe_fix_returns_unavailable() -> None:
    r = parse_llm_response(NO_SAFE_FIX_SENTINEL)
    assert r.status == PATCH_STATUS_UNAVAILABLE
    assert r.diff_text is None
    assert "NO_SAFE_FIX" in (r.reason or "")


def test_parse_empty_response_returns_unavailable() -> None:
    for s in ("", "   \n\n", None):
        r = parse_llm_response(s)  # type: ignore[arg-type]
        assert r.status == PATCH_STATUS_UNAVAILABLE


def test_parse_unfenced_prose_returns_unavailable() -> None:
    """Prose answers like 'Sure, here is the fix…' must not be
    accepted as diffs even when they describe a real change."""
    r = parse_llm_response(
        "Sure! Replace AES with AES/GCM/NoPadding in line 10.",
    )
    assert r.status == PATCH_STATUS_UNAVAILABLE


def test_parse_malformed_diff_returns_unavailable() -> None:
    """A response that's *structurally* a fenced diff but whose
    contents don't parse as a unified diff (no hunk headers) must
    fail validation."""
    r = parse_llm_response("```diff\nthis isn't actually a diff\n```")
    assert r.status == PATCH_STATUS_UNAVAILABLE


def test_parse_empty_diff_block_returns_unavailable() -> None:
    """An empty ```diff …``` fence yields zero hunks and must be
    rejected — equivalent to NO_SAFE_FIX."""
    r = parse_llm_response("```diff\n\n```")
    assert r.status == PATCH_STATUS_UNAVAILABLE


# =========================================================================
# Generator — only-verified gate
# =========================================================================

def test_generator_patches_only_verified_findings(tmp_path: Path) -> None:
    """VERIFIED gets a patch; FILTERED, UNCERTAIN, and untriaged are
    untouched. This is the spec's correctness gate — patching false
    positives is worse than skipping them."""
    verified  = _verified_finding(file="V.java")
    filtered  = _filtered_finding(file="F.java")
    uncertain = _uncertain_finding(file="U.java")
    untriaged = _untriaged_finding()

    router = _MockRouter([VALID_DIFF])
    gen = RemediationGenerator(router=router)
    _run(gen.generate_patches([verified, filtered, uncertain, untriaged]))

    # Only one LLM call should have been made — for the VERIFIED finding.
    assert len(router.calls) == 1

    assert verified.evidence["patch_status"] == PATCH_STATUS_SUGGESTED
    assert "patch_status" not in (filtered.evidence or {})
    assert "patch_status" not in (uncertain.evidence or {})
    assert "patch_status" not in (untriaged.evidence or {})


# =========================================================================
# Disclaimer — pinned on every successful patch
# =========================================================================

def test_disclaimer_attached_on_every_successful_patch() -> None:
    findings = [_verified_finding(file=f"F{i}.java") for i in range(3)]
    router = _MockRouter([VALID_DIFF, VALID_DIFF, VALID_DIFF])
    _run(RemediationGenerator(router=router).generate_patches(findings))
    for f in findings:
        assert f.evidence["patch_status"] == PATCH_STATUS_SUGGESTED
        assert f.evidence["patch_disclaimer"] == DISCLAIMER
        # Pin the human-review wording too — regression-guard.
        assert "Requires Human Review" in f.evidence["patch_disclaimer"]
        assert "decompiled code" in f.evidence["patch_disclaimer"]


def test_disclaimer_not_attached_when_patch_unavailable() -> None:
    """An UNAVAILABLE patch must not carry the disclaimer — the
    disclaimer is a statement about a *generated* patch, and there
    isn't one here. Tests pin this so we don't accidentally emit
    confusing claims about non-existent diffs."""
    f = _verified_finding()
    router = _MockRouter([NO_SAFE_FIX_SENTINEL])
    _run(RemediationGenerator(router=router).generate_patches([f]))
    assert f.evidence["patch_status"] == PATCH_STATUS_UNAVAILABLE
    assert "patch_disclaimer" not in f.evidence


# =========================================================================
# Router-failure resilience
# =========================================================================

def test_router_exception_does_not_crash_scan() -> None:
    """A raised router error must downgrade to UNAVAILABLE, not
    propagate out of generate_patches()."""
    f = _verified_finding()
    router = _MockRouter([RuntimeError("rate-limited")])
    findings = _run(
        RemediationGenerator(router=router).generate_patches([f]),
    )
    assert findings is not None
    assert f.evidence["patch_status"] == PATCH_STATUS_UNAVAILABLE
    assert "router error" in f.evidence["patch_unavailable_reason"]


def test_router_returns_none_content_handled() -> None:
    """The router occasionally returns ``{}`` (no content key). The
    generator must handle that without crashing."""
    f = _verified_finding()

    class _NoContentRouter:
        async def query(self, **kwargs):
            return {"provider": "mock"}  # no 'content' key

    _run(
        RemediationGenerator(router=_NoContentRouter()).generate_patches([f]),
    )
    assert f.evidence["patch_status"] == PATCH_STATUS_UNAVAILABLE


# =========================================================================
# Weak-crypto worked example
# =========================================================================

def test_weak_crypto_finding_gets_aes_gcm_diff() -> None:
    """End-to-end on the canonical weak-crypto example: the LLM returns
    the AES/GCM/NoPadding diff and the parsed result carries the fix."""
    f = _verified_finding(
        agent_id="C_007", vuln_class="WEAK_CRYPTO",
        code='Cipher c = Cipher.getInstance("AES");',
        file="com/example/Crypto.java",
    )
    router = _MockRouter([VALID_DIFF])
    _run(RemediationGenerator(router=router).generate_patches([f]))

    assert f.evidence["patch_status"] == PATCH_STATUS_SUGGESTED
    diff = f.evidence["suggested_patch"]
    assert "Cipher.getInstance" in diff
    assert "AES/GCM/NoPadding" in diff
    assert diff.startswith("--- ")


# =========================================================================
# File writer
# =========================================================================

def test_render_diff_file_includes_banner_and_disclaimer() -> None:
    """The .diff file body must lead with a comment banner that
    contains the finding ID, vuln class, and the human-review
    disclaimer. Tests pin every banner field — these are the cues a
    reviewer relies on."""
    f = _verified_finding()
    router = _MockRouter([VALID_DIFF])
    _run(RemediationGenerator(router=router).generate_patches([f]))

    body = render_diff_file(f)
    assert body is not None
    assert body.startswith("# SENTINEL AI-Suggested Patch")
    assert f"finding_id: {f.finding_id}" in body
    assert f"vuln_class: {f.vuln_class}" in body
    assert f"agent_id:   {f.agent_id}" in body
    assert DISCLAIMER in body
    # The actual diff content comes AFTER the banner.
    assert "AES/GCM/NoPadding" in body.split("# " + "-" * 58, 1)[1]


def test_render_diff_file_returns_none_for_unavailable() -> None:
    """Findings with patch_status=UNAVAILABLE must not be written.
    ``render_diff_file()`` returns ``None`` — the CLI writer relies on
    that to skip file creation."""
    f = _verified_finding()
    router = _MockRouter([NO_SAFE_FIX_SENTINEL])
    _run(RemediationGenerator(router=router).generate_patches([f]))
    assert render_diff_file(f) is None


def test_render_diff_file_returns_none_for_untouched_finding() -> None:
    """A finding that was never run through generate_patches() has no
    suggested_patch field — render_diff_file returns None rather
    than fabricating an empty file."""
    f = _untriaged_finding()
    assert render_diff_file(f) is None


# =========================================================================
# Prompt shape — sanity guard
# =========================================================================

def test_prompt_contains_required_elements() -> None:
    """Spot-check the prompt assembly. The LLM needs the vuln_class,
    the file, the recommendation, and the snippet — pinning these
    fields stops a future refactor from silently dropping context."""
    from sentinel.llm.remediation import _build_prompt
    f = _verified_finding(
        agent_id="C_007", vuln_class="WEAK_CRYPTO",
        code='Cipher c = Cipher.getInstance("DES");',
        file="com/example/Legacy.java",
    )
    msgs = _build_prompt(f)
    assert len(msgs) == 2
    assert msgs[0]["role"] == "system"
    assert "unified-diff" in msgs[0]["content"]
    assert NO_SAFE_FIX_SENTINEL in msgs[0]["content"]
    user = msgs[1]["content"]
    assert "WEAK_CRYPTO" in user
    assert "com/example/Legacy.java" in user
    assert "DES" in user


# =========================================================================
# Integration with cli helper (file-writing path)
# =========================================================================

def test_cli_helper_writes_one_file_per_verified(tmp_path: Path) -> None:
    """The CLI's _generate_and_write_patches helper iterates the
    generator's output and writes one .diff per SUGGESTED patch.
    Other statuses must not produce files."""
    from sentinel.cli import _generate_and_write_patches
    verified = _verified_finding(file="V.java")
    declined = _verified_finding(file="D.java")

    router = _MockRouter([VALID_DIFF, NO_SAFE_FIX_SENTINEL])
    written = _run(_generate_and_write_patches(
        router=router,
        findings=[verified, declined],
        patches_dir=tmp_path,
    ))
    assert written == 1
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == [f"{verified.finding_id}.diff"]
    body = (tmp_path / files[0]).read_text()
    assert DISCLAIMER in body
    assert "AES/GCM/NoPadding" in body


def test_cli_helper_zero_writes_when_no_verified_findings(
    tmp_path: Path,
) -> None:
    """When no finding is VERIFIED the helper still creates the dir
    (caller may want to inspect it) but writes zero files."""
    from sentinel.cli import _generate_and_write_patches
    fs = [_filtered_finding(), _uncertain_finding(), _untriaged_finding()]
    router = _MockRouter([])  # must never be called
    written = _run(_generate_and_write_patches(
        router=router, findings=fs, patches_dir=tmp_path,
    ))
    assert written == 0
    assert tmp_path.exists()
    assert list(tmp_path.iterdir()) == []
    assert router.calls == []


# ---------- Schema preservation ----------

def test_finding_remains_pydantic_valid_after_patch_attach() -> None:
    """Attaching patch metadata must not break Finding validation.
    `model_validate` round-trips the model — proves the evidence dict
    didn't blow the schema."""
    f = _verified_finding()
    _run(RemediationGenerator(router=_MockRouter([VALID_DIFF])).generate_patches([f]))
    # Re-validate via model_dump → model_validate round trip.
    Finding.model_validate(f.model_dump())
