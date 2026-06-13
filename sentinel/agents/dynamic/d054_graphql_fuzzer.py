"""D_054 — GraphQL query fuzzer (Dynamic Testing Target)."""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_GQL_MARKERS = (
    "ApolloClient", "graphql/queries", "apollographql",
    'String QUERY', '"query "', '"query{', '"mutation {',
)
_USERID_FIELD_RE = re.compile(r"\"(userId|accountId|uid|customerId)\"\s*:\s*[\"$]")


class GraphqlFuzzerAgent(BaseAgent):
    AGENT_ID = "D_054"
    VULN_CLASS = "GraphQL Endpoint Fuzz Target (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        hits: set[str] = set()
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2500:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(m in text for m in _GQL_MARKERS):
                hits.add(str(path.relative_to(root)))
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.MEDIUM,
            confidence=0.65,
            recommendation=(
                f"{len(hits)} GraphQL touch point(s) found. The Frida hook "
                "via mitmproxy will fire two payload families: "
                "deeply-nested introspection queries (depth 10+) to test "
                "for query-depth DoS, and IDOR perturbation that swaps "
                "userId / accountId fields with attacker-controlled "
                "values. Add query-depth limit + cost analysis + auth "
                "on per-object resolvers."
            ),
            evidence={
                "files": sorted(hits)[:20],
                "dynamic_target": True,
                "frida_payload": {
                    "depth_payload_template":
                        "{ user { friends " * 10 + "} " + "} " * 10,
                    "idor_field_swap": ["userId", "accountId", "customerId"],
                    "swap_targets": ["1", "2", "admin", "-1", "0", "9999999"],
                    "intercept_at": "mitmproxy",
                    "safety_budget": {
                        "max_actions_total": 40,
                        "max_actions_per_sec": 2,
                        "wall_clock_budget_s": 60,
                        "max_consecutive_crashes": 5,
                    },
                },
            },
        )]


__all__ = ["GraphqlFuzzerAgent"]
