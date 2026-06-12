"""A_004 — Hardcoded Secrets Agent.

Scans for embedded API keys, tokens, and credentials matching well-known
patterns from major cloud and SaaS providers.

Why this matters: a leaked AWS access key gives attackers full access to the
victim's S3 buckets and EC2 instances. A leaked Stripe live key lets them
charge customers and view payment history. Bug bounty programs pay
$500-$5,000 for hardcoded secret findings, and up to $10,000+ when the
key is for a critical service like AWS root or production payment.

Detection sources (Sprint 7.6.5):
1. JADX-decompiled Java + apktool resources (file-based scanning)
2. Androguard bytecode strings (always works, even on obfuscated APKs)

Sprint 7.6.5 made this agent crash-proof against JADX failures: even on
91MB obfuscated APKs where JADX times out, Androguard extracts strings
in ~25 seconds and the agent still finds the keys.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.tools.native_analyzer import shannon_entropy

logger = logging.getLogger(__name__)

# Shannon entropy floor for the matched secret value. Anything below this
# is almost certainly a placeholder, a regex false-positive that happened
# to satisfy the character class, or a value with too few unique chars to
# be a real key (e.g. "AKIAAAAAAAAAAAAAAAA"). 3.5 is the standard cutoff
# used by truffleHog / gitleaks; below that, real keys are vanishingly
# rare and false-positive rate explodes.
_ENTROPY_FLOOR = 3.5

# Providers whose match is a fixed-prefix structural token, not a random
# string — entropy filtering would drop real hits. PEM blocks are header
# strings; JWT structure has known low-entropy headers. Skip them.
_ENTROPY_EXEMPT_PROVIDERS = frozenset({
    "PEM Private Key",
    "JSON Web Token",
})


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
        """Applicable if ANY source is available — Java, resources, or bytecode."""
        ctx = self._context
        has_decompiled = ctx.decompiled_dir and ctx.decompiled_dir.exists()
        has_resources = ctx.resources_dir and ctx.resources_dir.exists()
        has_androguard = ctx.has_androguard()

        if not (has_decompiled or has_resources or has_androguard):
            logger.info("[A_004] No source available (Java, resources, or "
                        "bytecode) — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Run all available scanning paths and aggregate hits."""
        ctx = self._context

        # Map provider name -> list of {value, file, context, severity,
        # confidence, source}
        hits: dict[str, list[dict[str, Any]]] = {}

        # Path 1: JADX-decompiled Java
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            self._scan_directory(ctx.decompiled_dir, hits, ".java", source="java")

        # Path 2: apktool resources (XML files)
        if ctx.resources_dir and ctx.resources_dir.exists():
            self._scan_directory(ctx.resources_dir, hits, ".xml", source="resources")

        # Path 3: Androguard bytecode strings (always works if available)
        if ctx.has_androguard():
            self._scan_androguard_strings(hits)

        if not hits:
            logger.info("[A_004] No hardcoded secrets detected")
            return []

        # Deduplicate by matched value (same key found in Java AND bytecode
        # is one finding, not two)
        for provider in list(hits.keys()):
            hits[provider] = self._dedupe_by_value(hits[provider])

        # One finding per provider with all hits aggregated
        findings: list[Finding] = []
        for provider, instances in hits.items():
            sources_used = sorted({inst.get("source", "?") for inst in instances})
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
                    "sources": sources_used,
                    "matches": [
                        {
                            "redacted_value": self._redact(inst["value"]),
                            "file": inst["file"],
                            "context": inst["context"],
                            "source": inst.get("source", "?"),
                        }
                        for inst in instances[:10]
                    ],
                    "vector": (
                        "The secret is embedded as a string constant in the "
                        "APK. Extract it by decompiling with JADX/apktool or "
                        "by reading DEX bytecode strings — no runtime "
                        "execution required."
                    ),
                },
            ))

        return findings

    # ---------- File-based scanning (existing path) ----------

    def _scan_directory(
        self,
        root: Path,
        hits: dict[str, list[dict[str, Any]]],
        suffix: str,
        source: str,
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

                    # Entropy filter: real keys are high-entropy. Drop
                    # low-entropy matches before they reach the LLM
                    # triager — saves tokens and FP rate.
                    if (
                        provider not in _ENTROPY_EXEMPT_PROVIDERS
                        and shannon_entropy(matched) < _ENTROPY_FLOOR
                    ):
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
                        "source": source,
                    })

    # ---------- Androguard bytecode scanning (NEW in Sprint 7.6.5a) ----------

    def _scan_androguard_strings(
        self, hits: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Scan strings extracted from DEX bytecode by Androguard.

        Works on any APK regardless of size or obfuscation — runs in seconds.
        Especially valuable when JADX times out or fails (e.g., 91MB+ APKs).
        """
        androguard = self._context.sources.get("androguard")
        if androguard is None:
            return

        try:
            all_strings = androguard.get_all_strings()
        except Exception as e:  # noqa: BLE001
            logger.warning("[A_004] Androguard string extraction failed: %s", e)
            return

        logger.info("[A_004] Scanning %d bytecode strings", len(all_strings))

        # For Androguard strings we don't have file paths — we have raw
        # string constants from DEX. Track which strings we've already
        # captured per provider to avoid the same key showing up 50 times
        # (Android often interns identical strings).
        seen_per_provider: dict[str, set[str]] = {}

        for s in all_strings:
            if not s or len(s) < 8:
                # Tiny strings can't hold any of our targeted secrets
                continue

            for provider, pattern, severity, confidence in _DETECTORS:
                match = pattern.search(s)
                if not match:
                    continue

                matched = match.group(0)

                # FP filter: check the FULL string for placeholder hints
                # (since we don't have a "line" here)
                s_lower = s.lower()
                if any(hint in s_lower for hint in _FALSE_POSITIVE_HINTS):
                    continue

                # Entropy filter (same rule as the file-scan path)
                if (
                    provider not in _ENTROPY_EXEMPT_PROVIDERS
                    and shannon_entropy(matched) < _ENTROPY_FLOOR
                ):
                    continue

                # Dedupe: same key value from same provider counts once
                seen = seen_per_provider.setdefault(provider, set())
                if matched in seen:
                    continue
                seen.add(matched)

                if provider not in hits:
                    hits[provider] = []
                hits[provider].append({
                    "value": matched,
                    "file": "(extracted from DEX bytecode)",
                    "context": s[:200],
                    "severity": severity,
                    "confidence": confidence,
                    "source": "androguard",
                })

    @staticmethod
    def _dedupe_by_value(
        instances: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Collapse multiple hits of the same secret value into one entry.

        Prefer Java/resource hits over Androguard hits when deduping (they
        have file paths, which are more useful for the bounty report).
        """
        # Group by value
        by_value: dict[str, list[dict[str, Any]]] = {}
        for inst in instances:
            by_value.setdefault(inst["value"], []).append(inst)

        # Pick best representative for each value
        deduped: list[dict[str, Any]] = []
        source_priority = {"java": 0, "resources": 1, "androguard": 2}
        for _value, group in by_value.items():
            group.sort(key=lambda x: source_priority.get(x.get("source", ""), 99))
            best = group[0]
            # If found in multiple sources, note it
            sources = sorted({inst.get("source", "?") for inst in group})
            if len(sources) > 1:
                best = dict(best)
                best["source"] = "+".join(sources)
            deduped.append(best)

        return deduped

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
