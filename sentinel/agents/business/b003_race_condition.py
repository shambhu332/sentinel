"""B_003: Race Condition & TOCTOU Detection.

Detects time-of-check to time-of-use vulnerabilities and race conditions.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class RaceConditionAgent(BaseAgent):
    """Detect race condition vulnerabilities."""

    AGENT_ID = "B_003"
    VULN_CLASS = "Race Condition / TOCTOU"
    PHASE = "Phase 2"

    # Vulnerable patterns
    RACE_PATTERNS = [
        (r'if\s*\([^)]*balance[^)]*\)\s*{[^}]*balance\s*[-=]', 'Balance check without locking'),
        (r'if\s*\([^)]*count[^)]*\)\s*{[^}]*count\s*[+\-]=', 'Count check without synchronization'),
        (r'if\s*\([^)]*quantity[^)]*\)\s*{[^}]*quantity\s*[-=]', 'Quantity check without locking'),
        (r'if\s*\([^)]*\.exists\(\)[^)]*\)\s*{[^}]*\.create\(', 'Existence check before create'),
    ]

    async def is_applicable(self) -> bool:
        """Run if state-changing operations are detected."""
        return self.context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        """Analyze code for race condition vulnerabilities."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            for pattern, description in self.RACE_PATTERNS:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))

                for match in matches:
                    # Check if synchronized or locked
                    start = max(0, match.start() - 200)
                    end = min(len(content), match.end() + 200)
                    context_snippet = content[start:end]

                    is_protected = any(keyword in context_snippet for keyword in [
                        'synchronized',
                        'Lock',
                        'ReentrantLock',
                        'Semaphore',
                        '@Synchronized',
                    ])

                    if not is_protected:
                        findings.append(self._make_finding(
                            vuln_class="Race Condition Vulnerability",
                            severity=Severity.CRITICAL,
                            confidence=0.65,
                            evidence={
                                "file": rel_path,
                                "issue": description,
                                "code_snippet": match.group(0)[:200],
                                "description": "Check-then-act pattern without synchronization",
                            },
                            recommendation=(
                                f"Protect the check-then-act sequence with proper synchronization. "
                                f"Use synchronized blocks, ReentrantLock, or atomic operations. "
                                f"Issue: {description}"
                            ),
                            owasp="M1: Improper Platform Usage",
                            masvs="MSTG-CODE-7",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        ))

            # Check for double-spend patterns
            if 'redeem' in content.lower() or 'coupon' in content.lower():
                if 'synchronized' not in content and 'Lock' not in content:
                    findings.append(self._make_finding(
                        vuln_class="Potential Double-Spend Vulnerability",
                        severity=Severity.HIGH,
                        confidence=0.55,
                        evidence={
                            "file": rel_path,
                            "issue": "Redemption logic without synchronization",
                            "description": "Coupon/reward redemption may be vulnerable to parallel requests",
                        },
                        recommendation=(
                            "Implement server-side idempotency checks and proper locking "
                            "for redemption operations. Use database transactions with "
                            "appropriate isolation levels."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-CODE-7",
                    ))

        return findings
