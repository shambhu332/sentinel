"""Privacy sanitiser for swarm prompts.

The Red agent prompt would otherwise carry literal file paths, package
names, and possibly evidence snippets containing live API keys. We
strip these to placeholders before any LLM call so the LLM provider
never sees customer-identifying data.

Sanitisation rules:

  * file paths        → "<file>"
  * Android packages  → "<pkg>"
  * URLs              → "<url>"
  * IP addresses      → "<ip>"
  * AWS / GitHub / Stripe / Slack / JWT  → "<redacted-secret>"
  * Email addresses   → "<email>"
  * Tenant UUIDs      → "<tenant-id>"

The output preserves enough vuln-pattern structure (DES/AES keyword,
function names, line shapes) that the LLM can reason about the bug
without learning *whose* bug it is.
"""
from __future__ import annotations

import re
from typing import Any

# Order matters — more-specific regexes first.
_RULES: list[tuple[re.Pattern, str]] = [
    # Known-shape API keys
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "<aws-key>"),
    (re.compile(r"\b(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b"), "<gh-token>"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "<google-key>"),
    (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "<stripe-key>"),
    (re.compile(r"\bxox[baprs]-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]+\b"), "<slack-token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "<jwt>"),
    # Email
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "<email>"),
    # URLs
    (re.compile(r"https?://[A-Za-z0-9./%_\-]+"), "<url>"),
    # IPv4
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    # UUID-ish (tenant_id, session_id sometimes)
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "<tenant-id>"),
    # File paths — both POSIX and Windows-ish slashes
    (re.compile(r"(?:[A-Za-z]:)?(?:/|\\)[\w./\\\-]+\.(java|kt|xml|so|json|yaml|yml|properties|txt|html|js)\b"),
     "<file>"),
    # Android package names — three or more dotted identifiers
    (re.compile(r"\b(?:com|io|org|net)(?:\.[a-z][a-z0-9_]+){2,}\b"), "<pkg>"),
]


def sanitize_text(s: str) -> str:
    """Apply the rule set to a single string."""
    if not s:
        return s
    for pattern, replacement in _RULES:
        s = pattern.sub(replacement, s)
    return s


def sanitize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Deep-sanitize a Finding.evidence-shaped dict.

    Recurses into dicts and lists, replaces strings via `sanitize_text`,
    leaves other primitives alone. The output is a fresh structure so
    the original evidence is never mutated.
    """
    if isinstance(evidence, dict):
        return {k: sanitize_evidence(v) for k, v in evidence.items()}
    if isinstance(evidence, list):
        return [sanitize_evidence(x) for x in evidence]
    if isinstance(evidence, str):
        return sanitize_text(evidence)
    return evidence


__all__ = ["sanitize_text", "sanitize_evidence"]
