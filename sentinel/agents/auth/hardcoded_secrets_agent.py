"""A_004 — Hardcoded Secrets Agent.

Scans decompiled code, resource files, and manifests for embedded API keys,
tokens, and credentials that match well-known patterns from major cloud and
SaaS providers.

Why this matters: a leaked AWS access key gives attackers full access to the
victim's S3 buckets and EC2 instances. A leaked Stripe live key lets them
charge customers and view payment history. Bug bounty programs pay
$500-$5,000 for hardcoded secret findings, and up to $10,000+ when the
key is for a critical service like AWS root or production payment.

Detection pipeline:
1. Walk decompiled .java files and resource .xml files
2. Run a battery of regexes for AWS, GCP, Stripe, Twilio, Slack, GitHub, etc.
3. Filter out obvious test fixtures (keys containing "test", "example", "demo")
4. For each match, capture the file location and a redacted excerpt
5. Severity is per-provider — AWS keys are Critical, generic-looking strings
   labeled "key" are Medium
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Each detector is a tuple: (provider name, regex, severity, confidence)
# Patterns are deliberately conservative — we'd rather miss a real key than
# bury the user under false positives.
_DETECTORS: list[tuple[str, re.Pattern, Severity, float]] = [
    # AWS Access Key ID — high specificity
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     Severity.CRITICAL, 0.95),

    # GitHub personal access token / fine-grained
    ("GitHub Token", re.compile(r"\b(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b"),
     Severity.CRITICAL, 0.95),

    # Google API key — broad family (Maps, Cloud, Firebase, etc.)
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.HIGH, 0.85),

    # Stripe secret key (live)
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
     Severity.CRITICAL, 0.95),

    # Stripe restricted key
    ("Stripe Restricted Key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"),
     Severity.HIGH, 0.90),

    # Stripe publishable (lower severity — not a secret)
    ("Stripe Publishable Key", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
     Severity.LOW, 0.85),

    # Slack tokens
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]+\b"),
     Severity.HIGH, 0.90),

    # Slack webhook
    ("Slack Webhook URL", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
     Severity.HIGH, 0.90),

    # Twilio Account SID + Auth token (paired)
    ("Twilio Account SID", re.compile(r"\bAC[a-f0-9]{32}\b"),
     Severity.HIGH, 0.85),

    # SendGrid API key
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
     Severity.HIGH, 0.90),

    # Mailgun API key
    ("Mailgun API Key", re.compile(r"\bkey-[a-f0-9]{32}\b"),
     Severity.HIGH, 0.85),

    # JWT (informational — could be a sample)
    ("JSON Web Token", re.compile(
        r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
     Severity.MEDIUM, 0.65),

    # Private key (PEM block)
    ("PEM Private Key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PRIVATE)?(?:PRIVATE )?KEY-----"),
     Severity.CRITICAL, 0.95),
]

# Strings that, if present in the matched line, downgrade to a false-positive
_FALSE_POSITIVE_HINTS = (
    "test", "example", "sample", "fake", "dummy", "placeholder",
    "your_", "yourkey", "<your", "xxxx", "0000000000",
    "demo", "fixture", "mock",
)

# Cap files scanned for performance
_MAX_FILES_TO_SCAN = 3000


class HardcodedSecretsAgent(BaseAgent):
    """A_004: detects hardcoded API keys and credentials."""

    AGENT_ID = "A_004"
    VULN_CLASS = "Hardcoded Secret"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        """Needs decompiled source or extracted resources."""
        ctx = self._context
        has_decompiled = ctx.decompiled_dir and ctx.decompiled_dir.exists()
        has_resources = ctx.resources_dir and ctx.resources_dir.exists()
        if not has_decompiled and not has_resources:
            logger.info("[A_004] No decompiled source or resources — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Walk source and resource files, run detectors, group by provider."""
        ctx = self._context
        # Map provider name -> list of (matched_string, file_path, line_excerpt)
        hits: dict[str, list[dict[str, Any]]] = {}

        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            self._scan_directory(ctx.decompiled_dir, hits, ".java")
        if ctx.resources_dir and ctx.resources_dir.exists():
            self._scan_directory(ctx.resources_dir, hits, ".xml")

        if not hits:
            logger.info("[A_004] No hardcoded secrets detected")
            return []

        # One finding per provider with all hits aggregated
        findings: list[Finding] = []
        for provider, instances in hits.items():
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=instances[0]["severity"],
                confidence=instances[0]["confidence"],
                recommendation=self._build_recommendation(provider),
                evidence={
                    "title": f"Hardcoded {provider}",
                    "provider": provider,
                    "package": (ctx.manifest or {}).get("package", "?"),
                    "match_count": len(instances),
                    "matches": [
                        {
                            "redacted_value": self._redact(inst["value"]),
                            "file": inst["file"],
                            "context": inst["context"],
                        }
                        for inst in instances[:10]
                    ],
                    "vector": (
                        "Decompile the APK with apktool or JADX. The secret is "
                        "embedded as a string constant in the listed file(s). "
                        "Extract it directly from the source — no runtime "
                        "execution required."
                    ),
                },
            ))

        return findings

    def _scan_directory(
        self,
        root: Path,
        hits: dict[str, list[dict[str, Any]]],
        suffix: str,
    ) -> None:
        files_scanned = 0
        for path in root.rglob(f"*{suffix}"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[A_004] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            for provider, pattern, severity, confidence in _DETECTORS:
                for match in pattern.finditer(text):
                    matched = match.group(0)

                    # Get the surrounding line for context (and for FP detection)
                    start = max(0, text.rfind("\n", 0, match.start()) + 1)
                    end = text.find("\n", match.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end].strip()

                    # Skip lines that look like fixtures / placeholders
                    line_lower = line.lower()
                    if any(hint in line_lower for hint in _FALSE_POSITIVE_HINTS):
                        continue

                    rel = str(path.relative_to(root))
                    if provider not in hits:
                        hits[provider] = []
                    hits[provider].append({
                        "value": matched,
                        "file": rel,
                        "context": line[:200],
                        "severity": severity,
                        "confidence": confidence,
                    })

    @staticmethod
    def _redact(secret: str) -> str:
        """Show first 4 and last 4 characters, redact the middle."""
        if len(secret) <= 12:
            return secret[:4] + "***"
        return f"{secret[:4]}...{secret[-4:]}"

    @staticmethod
    def _build_recommendation(provider: str) -> str:
        return (
            f"Remove the hardcoded {provider} from the application source. "
            f"Rotate the credential immediately — assume it is already "
            f"compromised. Replace with a runtime-fetched value from a secure "
            f"backend, the Android Keystore, or a secrets management service. "
            f"Add a pre-commit hook or CI check (e.g. truffleHog, gitleaks) to "
            f"prevent recurrence."
        )
