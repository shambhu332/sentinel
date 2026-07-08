"""A_001 — Hardcoded Credentials Agent.

Detects hardcoded API keys, passwords, tokens, and secrets in decompiled
Android source code (Java/Kotlin). Uses regex matching with Shannon entropy
filtering and simple intra-procedural taint analysis to determine whether
the secret reaches a dangerous sink.

Detection:
  1. Regex patterns with per-pattern entropy thresholds
  2. Placeholder / false-positive filtering
  3. Intra-procedural taint: secret → network / file / intent sink

Severity:
  HIGH   — secret reaches a dangerous sink or is a high-specificity pattern
  MEDIUM — secret present, no sink detected in immediate scope

CWE: CWE-798 (Hard-coded Credentials), CWE-259 (Hard-coded Password)
MASVS: MASVS-STORAGE-2
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface
from sentinel.tools.native_analyzer import shannon_entropy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Pattern:
    name: str
    regex: re.Pattern[str]
    entropy_threshold: float  # 0.0 = skip entropy check (pattern is specific enough)
    confidence: float
    description: str


_PATTERNS: list[_Pattern] = [
    _Pattern(
        name="api_key",
        regex=re.compile(
            r'(?i)(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
            re.MULTILINE,
        ),
        entropy_threshold=3.5,
        confidence=0.90,
        description="Hardcoded API key",
    ),
    _Pattern(
        name="bearer_token",
        regex=re.compile(r'(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})', re.MULTILINE),
        entropy_threshold=4.0,
        confidence=0.92,
        description="Hardcoded Bearer token",
    ),
    _Pattern(
        name="generic_token",
        regex=re.compile(
            r'(?i)(?:token|access_token|auth_token|refresh_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?',
            re.MULTILINE,
        ),
        entropy_threshold=4.0,
        confidence=0.88,
        description="Hardcoded authentication token",
    ),
    _Pattern(
        name="password_assignment",
        regex=re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',
            re.MULTILINE,
        ),
        entropy_threshold=2.5,
        confidence=0.75,
        description="Hardcoded password",
    ),
    _Pattern(
        name="aws_access_key",
        regex=re.compile(r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.98,
        description="AWS access key ID",
    ),
    _Pattern(
        name="google_api_key",
        regex=re.compile(r'AIza[0-9A-Za-z_\-]{35}', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.98,
        description="Google API key",
    ),
    _Pattern(
        name="stripe_live_key",
        regex=re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.98,
        description="Stripe live secret key",
    ),
    _Pattern(
        name="github_token",
        regex=re.compile(r'\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{36,}\b', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.97,
        description="GitHub personal access token",
    ),
    _Pattern(
        name="firebase_url",
        regex=re.compile(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.95,
        description="Firebase database URL",
    ),
    _Pattern(
        name="private_key_pem",
        regex=re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', re.MULTILINE),
        entropy_threshold=0.0,
        confidence=0.99,
        description="Embedded PEM private key",
    ),
]

_FP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'YOUR_[A-Z_]+_HERE', re.IGNORECASE),
    # Matches EXAMPLE, EXAMPLE_KEY_..., PLACEHOLDER, etc. — applied to secret_value only
    re.compile(r'(?i)\b(?:EXAMPLE|PLACEHOLDER|SAMPLE|DEMO|FAKE|XXXX|0000)'),
    re.compile(r'^\$?\{.*\}$'),
    re.compile(r'^[A-Z_]+_(?:ENV|VAR|KEY)$', re.IGNORECASE),
]

_TEST_PATH_RE = re.compile(r'[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub')

_DANGEROUS_SINKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'OkHttpClient|Retrofit|HttpURLConnection|Volley|\.openConnection'), "network_send"),
    (re.compile(r'sendBroadcast|startActivity|startService|new\s+Intent'), "intent_send"),
    (re.compile(r'FileWriter|FileOutputStream|openFileOutput|PrintWriter'), "file_write"),
    (re.compile(r'execSQL|rawQuery|\.query\s*\('), "sql_exec"),
    (re.compile(r'Runtime\.getRuntime\s*\(\s*\)\.exec|ProcessBuilder'), "command_exec"),
]


@dataclass
class _Match:
    pattern_name: str
    file_path: Path
    line_number: int
    matched_text: str
    secret_value: str
    entropy: float
    context_window: str
    confidence: float


class A001HardcodedCredsAgent(BaseAgent):
    """A_001: Hardcoded credential detection."""

    AGENT_ID = "A_001"
    VULN_CLASS = "Hardcoded Credentials"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, memory, config)

    async def is_applicable(self) -> bool:
        ctx = self._context
        has_java = ctx.decompiled_dir and ctx.decompiled_dir.exists()
        has_resources = ctx.resources_dir and ctx.resources_dir.exists()
        if not (has_java or has_resources):
            logger.info("[A_001] No decompiled source available — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        findings: list[Finding] = []

        source_root = ctx.decompiled_dir
        if not source_root or not source_root.exists():
            return findings

        java_files = list(source_root.rglob("*.java")) + list(source_root.rglob("*.kt"))

        for source_file in java_files:
            if _TEST_PATH_RE.search(str(source_file.relative_to(source_root))):
                continue

            try:
                content = source_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for match in self._find_secrets(source_file, content):
                if self._is_fp(match):
                    continue

                reaches_sink, sink_type = self._taint_check(content, match)
                severity = (
                    Severity.HIGH
                    if reaches_sink or match.confidence >= 0.95
                    else Severity.MEDIUM
                )
                findings.append(self._make_finding(match, reaches_sink, sink_type, severity))

        return findings

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _find_secrets(self, file_path: Path, content: str) -> list[_Match]:
        results: list[_Match] = []
        for pat in _PATTERNS:
            for m in pat.regex.finditer(content):
                secret = (m.group(1) if m.lastindex else m.group(0)).strip('"\' ')
                ent = shannon_entropy(secret)
                if pat.entropy_threshold > 0 and ent < pat.entropy_threshold:
                    continue
                line_num = content[: m.start()].count("\n") + 1
                lines = content.split("\n")
                ctx_start = max(0, line_num - 6)
                ctx_end = min(len(lines), line_num + 5)
                results.append(_Match(
                    pattern_name=pat.name,
                    file_path=file_path,
                    line_number=line_num,
                    matched_text=m.group(0)[:200],
                    secret_value=secret[:100],
                    entropy=round(ent, 2),
                    context_window="\n".join(lines[ctx_start:ctx_end]),
                    confidence=pat.confidence,
                ))
        return results

    def _is_fp(self, match: _Match) -> bool:
        for fp in _FP_PATTERNS:
            if fp.search(match.secret_value):
                return True
        if match.entropy < 2.0 and match.pattern_name not in ("aws_access_key", "google_api_key", "stripe_live_key", "github_token"):
            return True
        return False

    # ------------------------------------------------------------------
    # Taint (intra-procedural, 50-line window)
    # ------------------------------------------------------------------

    def _taint_check(self, content: str, match: _Match) -> tuple[bool, str | None]:
        var_name = self._extract_var_name(match.context_window, match.matched_text)
        lines = content.split("\n")
        decl = match.line_number - 1
        search_slice = lines[decl: min(len(lines), decl + 50)]
        search_text = "\n".join(search_slice)

        for sink_re, sink_type in _DANGEROUS_SINKS:
            if sink_re.search(search_text):
                if var_name and var_name in search_text:
                    return True, sink_type
                if match.matched_text[:20] in search_text:
                    return True, sink_type
        return False, None

    @staticmethod
    def _extract_var_name(context: str, matched_text: str) -> str | None:
        prefix = re.escape(matched_text[:30])
        for pattern in (
            rf'(?:String|final|var|val)\s+(\w+)\s*=.*{prefix}',
            rf'(\w+)\s*=.*{prefix}',
        ):
            m = re.search(pattern, context)
            if m:
                return m.group(1)
        return None

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        match: _Match,
        reaches_sink: bool,
        sink_type: str | None,
        severity: Severity,
    ) -> Finding:
        ctx = self._context
        rel_path = match.file_path.relative_to(ctx.workspace) if ctx.workspace in match.file_path.parents else match.file_path

        vuln_label = match.pattern_name.replace("_", " ").title()
        if reaches_sink:
            vuln_class = f"Hardcoded {vuln_label} — reaches {sink_type}"
        else:
            vuln_class = f"Hardcoded {vuln_label}"

        return Finding(
            agent_id=self.AGENT_ID,
            session_id=ctx.session_id,
            vuln_class=vuln_class,
            severity=severity,
            confidence=match.confidence,
            evidence={
                "file": str(rel_path),
                "line": match.line_number,
                "pattern": match.pattern_name,
                "matched_text": match.matched_text,
                "entropy": match.entropy,
                "reaches_dangerous_sink": reaches_sink,
                "sink_type": sink_type,
                "context": match.context_window[:500],
            },
            owasp="M2",
            masvs="MASVS-STORAGE-2",
            compliance_tags=["CWE-798", "CWE-259"],
            recommendation=(
                "1. Remove all hardcoded credentials from source code immediately.\n"
                "2. Use Android Keystore System for cryptographic keys and secrets.\n"
                "3. For API keys, fetch from a backend endpoint or use encrypted remote config.\n"
                "4. Use BuildConfig fields only for non-sensitive configuration.\n"
                "5. Add secret scanning (GitLeaks/TruffleHog) to your CI pipeline.\n"
                "6. Rotate any exposed credentials immediately."
            ),
            code_snippet={
                "file": str(rel_path),
                "line": match.line_number,
                "content": match.context_window[:1000],
            },
        )
