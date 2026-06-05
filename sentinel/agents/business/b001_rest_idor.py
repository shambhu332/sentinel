"""B_001: REST API IDOR (Insecure Direct Object Reference) Detection.

Analyzes API endpoints for potential cross-user data access vulnerabilities.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class RestIdorAgent(BaseAgent):
    """Detect IDOR vulnerabilities in REST API endpoints."""

    AGENT_ID = "B_001"
    VULN_CLASS = "REST API IDOR"
    PHASE = "Phase 2"

    # Patterns for object ID parameters
    ID_PATTERNS = [
        r'/users?/(\d+)',
        r'/profile/(\d+)',
        r'/account/([a-f0-9-]+)',
        r'/order/(\d+)',
        r'/transaction/(\d+)',
        r'[?&]id=(\d+)',
        r'[?&]user_id=(\d+)',
        r'[?&]account_id=([a-f0-9-]+)',
    ]

    async def is_applicable(self) -> bool:
        """Run if REST API endpoints are detected."""
        return self.context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        """Analyze REST endpoints for IDOR vulnerabilities."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        endpoints_found = set()

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Find API endpoint definitions
            for pattern in self.ID_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    # Extract full URL context
                    for match in re.finditer(pattern, content):
                        start = max(0, match.start() - 100)
                        end = min(len(content), match.end() + 100)
                        context_snippet = content[start:end]

                        # Check for authorization checks
                        has_auth_check = any(keyword in context_snippet.lower() for keyword in [
                            'checkpermission',
                            'authorize',
                            'isowner',
                            'belongsto',
                            'userid',
                            'currentuser',
                        ])

                        if not has_auth_check:
                            endpoint = match.group(0)
                            if endpoint not in endpoints_found:
                                endpoints_found.add(endpoint)

                                findings.append(self._make_finding(
                                    vuln_class="Potential IDOR in REST Endpoint",
                                    severity=Severity.CRITICAL,
                                    confidence=0.70,
                                    evidence={
                                        "file": rel_path,
                                        "endpoint": endpoint,
                                        "pattern": pattern,
                                        "description": "Endpoint accepts object ID without visible authorization check",
                                        "context": context_snippet[:200],
                                    },
                                    recommendation=(
                                        f"Verify that endpoint '{endpoint}' checks if the authenticated user "
                                        "has permission to access the requested resource. Implement proper "
                                        "authorization checks before returning data."
                                    ),
                                    owasp="M1: Improper Platform Usage",
                                    masvs="MSTG-ARCH-2",
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                ))

        return findings
