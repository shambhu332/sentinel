"""N_011: GraphQL Fuzzer for IDOR and Authorization Issues.

Automated GraphQL mutation fuzzing for security vulnerabilities.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class GraphqlFuzzerAgent(BaseAgent):
    """Fuzz GraphQL endpoints for authorization issues."""

    AGENT_ID = "N_011"
    VULN_CLASS = "GraphQL Authorization Issues"
    PHASE = "Phase 4"

    async def is_applicable(self) -> bool:
        """Run if GraphQL endpoints are detected."""
        if not self.context.decompiled_dir:
            return False

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            if 'graphql' in content.lower() or 'apollo' in content.lower():
                return True
        return False

    async def analyze(self) -> list[Finding]:
        """Analyze GraphQL queries for potential vulnerabilities."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Find GraphQL queries and mutations
            query_pattern = r'(query|mutation)\s+(\w+)\s*\([^)]*\)\s*{([^}]+)}'
            matches = re.finditer(query_pattern, content, re.IGNORECASE | re.DOTALL)

            for match in matches:
                operation_type = match.group(1).lower()
                operation_name = match.group(2)
                operation_body = match.group(3)

                # Check for ID-based operations
                if re.search(r'\bid\s*:', operation_body, re.IGNORECASE):
                    has_auth_check = any(keyword in operation_body.lower() for keyword in [
                        'userid', 'ownerid', 'currentuser',
                    ])

                    if not has_auth_check and operation_type == 'mutation':
                        findings.append(self._make_finding(
                            vuln_class="GraphQL Mutation with ID Parameter",
                            severity=Severity.HIGH,
                            confidence=0.60,
                            evidence={
                                "file": rel_path,
                                "operation": operation_name,
                                "type": operation_type,
                            },
                            recommendation=(
                                f"Verify mutation '{operation_name}' checks authorization. "
                                "Test with different user IDs to ensure proper access control."
                            ),
                            owasp="M1: Improper Platform Usage",
                            masvs="MSTG-ARCH-2",
                        ))

        return findings
