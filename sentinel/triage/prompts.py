"""Triage prompt templates per vulnerability class.

Each template renders into a single LLM prompt. The system prompt is shared.
Agent-specific prompts focus the LLM on the right questions for that bug class.

Design rule: prompts ALWAYS instruct the LLM to return JSON matching
TriageVerdict's schema. Examples are included to anchor the format.
"""
from __future__ import annotations

from sentinel.core.finding import Finding

SYSTEM_PROMPT = """\
You are a senior Android security analyst triaging static-analysis findings \
for a bug bounty hunter. Your job is to determine whether each candidate \
finding is a REAL exploitable bug worth submitting, or a FALSE POSITIVE.

You will receive:
1. A pattern-matching finding from an automated scanner
2. The actual source code where the pattern matched
3. The surrounding context

Be skeptical. Pattern matchers produce false positives. Common ones:
- Test/debug code that won't ship to production
- Strings used in error messages, not as actual credentials
- Random number generators used for non-security purposes (animation, IDs, sampling)
- Logging statements that print harmless metadata, not sensitive data
- WebView configurations gated behind a debug flag

But also: don't dismiss real bugs. If the code legitimately matches the \
vulnerability pattern in a production code path, it IS a finding.

Always respond with valid JSON matching this exact schema:
{
  "is_real_bug": true | false,
  "confidence": <float between 0.0 and 1.0>,
  "explanation": "<specific reasoning, must reference the code>",
  "adjusted_severity": "Critical" | "High" | "Medium" | "Low" | "Info" | null,
  "false_positive_reason": "<short reason, or null if is_real_bug=true>"
}

No extra fields. No markdown around the JSON. Just the JSON object.
"""


# Generic fallback prompt for any vuln_class without a specific template
_GENERIC_TEMPLATE = """\
Pattern-matching agent: {agent_id}
Vulnerability class: {vuln_class}
Reported severity: {severity}
Agent's confidence: {confidence:.2f}

Agent's evidence:
{evidence_summary}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is this a real {vuln_class} vulnerability that an attacker \
could exploit, or a false positive?

Consider:
- Does the code path actually execute in production builds?
- Is the matched pattern part of business logic or test/debug scaffolding?
- Is the agent's severity appropriate given the real impact?

Return JSON per the schema."""


# Per-class specialized prompts

_PROMPTS_BY_CLASS: dict[str, str] = {
    "Insecure Logging": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}
Agent's confidence: {confidence:.2f}

Agent's evidence:
{evidence_summary}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is sensitive data ACTUALLY being logged, or does the word \
matched (e.g. "password", "token") appear in a harmless context like a log \
message about a UI button or a comment?

Look at the literal string being concatenated into the Log call. If a real \
variable holding a password/token/credential is in the args, it's a real bug. \
If it's just a debug message that mentions "password" as a noun, it's a false \
positive.

Return JSON per the schema.""",

    "Weak Cryptography": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}
Detected primitive: {primitive}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is this weak crypto primitive used in a SECURITY context, \
or for a non-security purpose like a cache key, deduplication hash, or \
file checksum?

MD5/SHA-1 used for cache keys: false positive (not a security bug).
MD5/SHA-1 used for password hashing or signature verification: real bug.
DES/RC4 in any context: real bug (genuinely broken).
AES-ECB: almost always a real bug regardless of context.

Return JSON per the schema.""",

    "Insecure Random": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}
Security keyword nearby: {security_keyword}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is java.util.Random / Math.random() being used to generate \
something an attacker could exploit if predicted (session token, password \
reset code, IV, salt, OTP, CSRF token), OR is it being used for non-security \
purposes (game randomness, UI animation timing, A/B test bucket assignment, \
load balancing)?

If non-security: false positive. If security-sensitive: real High bug.

Return JSON per the schema.""",

    "Insecure Auth Token Storage": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}
Storage type: {storage_type}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Are credentials, tokens, or session data ACTUALLY being \
written to insecure storage in this code path, or does the file merely \
mention auth-related keywords in a different context (e.g. a comment, an \
error string, a UI label)?

Confirm:
1. Is there an actual write call (putString, write, insert) that writes \
   sensitive data?
2. Is the data sensitive (auth token, password, session ID), not just a \
   variable that happens to have an auth-sounding name?
3. Is the storage location truly insecure (plain SharedPreferences, sdcard, \
   unencrypted file)?

If all three: real bug. If any breaks down: false positive.

Return JSON per the schema.""",

    "Hardcoded Secrets": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}
Detected provider: {provider}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is this an actual hardcoded secret that would grant an \
attacker access to a real service, or is it a test/example/placeholder \
value?

Real bug indicators:
- Looks like a production-shaped key (full length, no AAA000 patterns)
- Not in a test directory or test file
- Not surrounded by comments saying "TODO replace" or "fake"
- The associated provider is one this app would actually use

False positive indicators:
- "EXAMPLE", "FAKE", "TEST" in or around the value
- In a unit test file or test fixture
- Provider doesn't match the app's domain (e.g., AWS key in a calculator app)

Return JSON per the schema.""",

    "Cleartext Traffic": """\
Pattern-matching agent: {agent_id}
Reported severity: {severity}

Source code context (file: {file_path}):
```java
{code_snippet}
```

Triage question: Is the HTTP URL pointing to a production endpoint that \
would carry sensitive traffic, or is it a localhost/development/known-public \
endpoint that doesn't matter?

Consider these explicit non-bugs:
- http://localhost or http://127.0.0.1
- http://10.0.2.2 (Android emulator host)
- Schema namespace URLs (xmlns="http://schemas.android.com/...")
- W3C/Apache schema definitions

A real production HTTP endpoint or any auth-related cleartext URL is a real \
bug.

Return JSON per the schema.""",
}


def render_prompt(finding: Finding, code_snippet: str, file_path: str) -> str:
    """Build the user prompt for a single finding.

    Returns the rendered template (without the system prompt — that's sent
    separately by the LLM router).
    """
    template = _PROMPTS_BY_CLASS.get(finding.vuln_class, _GENERIC_TEMPLATE)

    evidence = finding.evidence or {}
    evidence_summary = _summarize_evidence(evidence)

    return template.format(
        agent_id=finding.agent_id,
        vuln_class=finding.vuln_class,
        severity=finding.severity.value,
        confidence=finding.confidence,
        evidence_summary=evidence_summary,
        file_path=file_path or "(unknown)",
        code_snippet=code_snippet or "(no code context available)",
        # Class-specific extras (with safe fallbacks)
        primitive=evidence.get("primitive", "(unknown)"),
        security_keyword=_extract_security_keyword(evidence),
        storage_type=evidence.get("storage_type", "(unknown)"),
        provider=evidence.get("provider", evidence.get("category", "(unknown)")),
    )


def _summarize_evidence(evidence: dict) -> str:
    """Compact, LLM-friendly summary of an evidence dict."""
    parts: list[str] = []
    for key in ("title", "summary", "vector", "match_count", "category", "primitive", "storage_type"):
        if key in evidence and evidence[key]:
            value = evidence[key]
            if isinstance(value, str) and len(value) > 300:
                value = value[:300] + "..."
            parts.append(f"  {key}: {value}")
    return "\n".join(parts) if parts else "(no extra evidence)"


def _extract_security_keyword(evidence: dict) -> str:
    """Pull a security keyword from B_002-style hits if present."""
    hits = evidence.get("hits", [])
    if hits and isinstance(hits, list) and isinstance(hits[0], dict):
        kw = hits[0].get("security_keyword")
        if kw:
            return kw
    return "(none detected)"
