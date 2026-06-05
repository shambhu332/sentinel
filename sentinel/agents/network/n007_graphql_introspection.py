"""N_007: GraphQL Introspection Detection.

Detects enabled GraphQL introspection in production.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

if TYPE_CHECKING:
    pass


class GraphqlIntrospectionAgent(BaseAgent):
    """Detect GraphQL introspection vulnerabilities."""

    AGENT_ID = "N_007"
    VULN_CLASS = "GraphQL Introspection Enabled"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        """Run if GraphQL endpoints are detected."""
        if not self.context.decompiled_dir:
            return False

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            if any(keyword in content for keyword in ['graphql', 'GraphQL', '/graphql', 'apollo']):
                return True
        return False

    async def analyze(self) -> list[Finding]:
        """Analyze GraphQL implementation for introspection issues."""
        findings: list[Finding] = []

        if not self.context.decompiled_dir:
            return findings

        graphql_endpoints = set()

        for java_file in self.context.decompiled_dir.rglob("*.java"):
            content = java_file.read_text(errors="replace")
            rel_path = str(java_file.relative_to(self.context.decompiled_dir))

            # Find GraphQL endpoint URLs
            url_patterns = [
                r'https?://[^"\s]+/graphql',
                r'"(/graphql[^"]*)"',
            ]

            for pattern in url_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    endpoint = match.group(0).strip('"')
                    if endpoint not in graphql_endpoints:
                        graphql_endpoints.add(endpoint)

                        # Check if introspection is explicitly disabled
                        has_introspection_check = any(keyword in content for keyword in [
                            'introspection',
                            'disableIntrospection',
                            'introspectionEnabled',
                        ])

                        if not has_introspection_check:
                            findings.append(self._make_finding(
                                vuln_class="GraphQL Introspection Not Explicitly Disabled",
                                severity=Severity.MEDIUM,
                                confidence=0.65,
                                evidence={
                                    "file": rel_path,
                                    "endpoint": endpoint,
                                    "description": "GraphQL endpoint without introspection controls",
                                },
                                recommendation=(
                                    f"Disable GraphQL introspection in production for endpoint '{endpoint}'. "
                                    "Introspection exposes the entire schema, revealing all queries, mutations, "
                                    "and types. Configure your GraphQL server to disable introspection in production."
                                ),
                                owasp="M1: Improper Platform Usage",
                                masvs="MSTG-ARCH-2",
                                poc=(
                                    "Test introspection with:\n"
                                    "POST /graphql\n"
                                    '{"query": "{ __schema { types { name } } }"}\n\n'
                                    "If successful, the entire schema is exposed."
                                ),
                            ))

            # Check for Apollo Client configuration
            if 'ApolloClient' in content or 'apollo-android' in content:
                if 'introspection' not in content.lower():
                    findings.append(self._make_finding(
                        vuln_class="Apollo Client Without Introspection Config",
                        severity=Severity.LOW,
                        confidence=0.55,
                        evidence={
                            "file": rel_path,
                            "description": "Apollo Client configured without introspection settings",
                        },
                        recommendation=(
                            "Ensure the GraphQL server has introspection disabled in production. "
                            "While client-side configuration doesn't control this, verify server settings."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-ARCH-2",
                    ))

        return findings
