"""Deterministic rule-based remediation patches.

Complements `sentinel.llm.remediation` (LLM-generated patches) with a
fast, free, repeatable layer of rule-based fixes for the most common
findings:

  * weak crypto algorithm swaps (DES → AES, MD5 → SHA-256)
  * `PendingIntent` flag injection (add FLAG_IMMUTABLE)
  * cleartext URL upgrade (`http://` → `https://`)
  * `android:exported="true"` → `false` on activities without
    intent filters
  * `android:debuggable="true"` strip from manifest
  * `android:allowBackup="true"` → `false` (for sensitive apps)

Rule application order:
  1. The CLI / orchestrator asks `rule_based.patch(finding)`.
  2. If a rule matches, returns a unified diff and a confidence level.
  3. If no rule matches, caller falls through to the LLM generator.

This module never reads / writes disk by itself — it's a pure
transformer over the finding's evidence + recommendation. Callers
write the resulting `.diff` to the workspace via the existing
`sentinel.llm.remediation.render_diff_file` plumbing.
"""
from sentinel.remediation.rule_based import (
    RuleBasedPatcher,
    RulePatchResult,
    default_patcher,
    patch,
)

__all__ = [
    "RuleBasedPatcher",
    "RulePatchResult",
    "default_patcher",
    "patch",
]
