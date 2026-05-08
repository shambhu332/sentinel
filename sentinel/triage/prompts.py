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
finding is a REAL exploitable bug worth submitting, or a clear FALSE POSITIVE.

You will receive:
1. A pattern-matching finding from an automated scanner
2. The actual source code where the pattern matched (or "no code context" \
   for manifest-only findings or when JADX failed)
3. The surrounding context

CRITICAL DEFAULT RULE: If you cannot confidently rule a finding out as a \
false positive, you MUST mark it as a real bug (is_real_bug=true). \
The cost of a false negative (missing a real bug) is far higher than the \
cost of a false positive (which the bounty hunter can verify in 5 minutes).

Common true false positives:
- Test/debug code that won't ship to production (file path contains /test/)
- Strings used in error messages, not as actual credentials
- Random number generators used for non-security purposes (animation, IDs, sampling)
- Logging statements that print harmless metadata, not sensitive data
- WebView configurations gated behind a debug flag

CRITICAL — When code context is unavailable or empty:
If the source code shows "(no code context available)" — this means JADX \
failed (likely a large or obfuscated APK), or the finding came from manifest \
or bytecode analysis. In this case:
- The agent's pattern match was performed against bytecode, manifest, or \
  resources — NOT source code. The match is still valid evidence.
- Do NOT mark a finding as a false positive solely because you cannot see \
  the source. Mark it as is_real_bug=true with a note that source-level \
  verification was not possible.
- A hardcoded API key found in bytecode is still a real key. The binary \
  contains it regardless of whether you can see the calling code.
- A manifest-based finding (allowBackup=true, exported components, deep \
  links) needs no source confirmation — the manifest IS the evidence.

Examples of REAL bugs (mark as is_real_bug=true):
- DES, RC4, MD5 in any production code path → real bug
- AES-ECB anywhere → real bug
- allowBackup=true on apps storing sensitive data → real bug
- Cleartext HTTP for production endpoints → real bug
- Missing certificate pinning on banking/finance/auth apps → real bug
- Exported Content Providers without permissions → real bug
- java.util.Random in security context (tokens, sessions) → real bug
- Hardcoded credentials in plain SharedPreferences → real bug
- addJavascriptInterface + JS enabled WebView → real bug
- Log statements containing password/token variable concatenation → real bug
- Hardcoded production-shaped API key (AIza..., AKIA..., sk_live_..., ghp_...) \
  in any code or bytecode → real bug

Examples of TRUE false positives (mark as is_real_bug=false):
- The matched string is inside a comment or test fixture
- HTTP URL is localhost, 10.0.2.2, or a schema namespace (xmlns)
- Random() is clearly used for animation/UI timing/game logic only
- MD5 used purely as a non-security cache key (never compared for security)
- API key has obvious "EXAMPLE", "FAKE", "TEST", "YOUR_KEY_HERE" markers

When in doubt, mark as is_real_bug=true. The bounty hunter is a competent \
professional who will verify; they need leads, not denials.

Always respond with valid JSON matching this exact schema:
{
  "is_real_bug": true | false,
  "confidence": <float between 0.0 and 1.0>,
  "explanation": "<specific reasoning, must reference the code or evidence>",
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
attacker access to a real service, or is it a test/example/placeholder?

If code_snippet is "(no code context available)":
- The secret was extracted from bytecode/strings/resources directly.
- The key existing in the binary IS the bug, regardless of source visibility.
- Examine the agent's evidence: if the key looks like a production credential
  (e.g., starts with AIza, AKIA, sk_live_, ghp_, etc.) and doesn't contain
  obvious placeholder markers (EXAMPLE, FAKE, YOUR_KEY_HERE), mark as
  is_real_bug=true with high confidence.
- A Google API key 'AIza...' shipped in a banking app's bytecode is a real
  finding worth bounty submission.

Real bug indicators:
- Production-shaped key (correct length and prefix for its provider)
- Not in a test directory or test file
- No "TODO replace" or "fake" comments around it
- Provider matches an API the app would actually use

True false positive indicators:
- "EXAMPLE", "FAKE", "TEST", "YOUR_KEY_HERE" appears in or around the value
- Inside a unit test file or test fixture
- Provider has zero relation to the app's purpose

DEFAULT: when in doubt with no clear FP indicator, mark as is_real_bug=true.

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
