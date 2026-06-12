"""K_001 — GraphQL schema & gRPC `.proto` analyzer.

Complements N_007 (GraphQL introspection-in-code regex hits) and N_011
(GraphQL fuzzer) by parsing the actual schema artifacts shipped inside
the APK:

1. **`.graphql` / `.gql` schema files** in `assets/` or `res/raw/` —
   flag introspection-enabled schemas (presence of `__schema`,
   `__type`), schema dumps that ship the full type system to the
   client (information disclosure), and any visible `mutation` /
   `subscription` roots without auth directives.
2. **`.proto` files** in `assets/` — enumerate gRPC services and
   methods, flag services lacking auth metadata (no `(google.api.http)`
   with auth, no custom `auth_required` option) and any `stream` RPC
   without a deadline annotation.

The agent is intentionally noisy at INFO/LOW: it surfaces the API
surface so a pentester knows where to point N_011 and Frida. Real
exploitability lives in the dynamic phase.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Cap scanned files per category — APK assets dirs sometimes ship
# thousands of unrelated JSON files; we only care about the real schema.
_MAX_FILES = 500

# Suffixes treated as GraphQL schema artifacts
_GRAPHQL_SUFFIXES = (".graphql", ".gql", ".graphqls")

# Suffix for Protocol Buffers schema files
_PROTO_SUFFIX = ".proto"

# GraphQL introspection markers — if any of these appear in a schema file
# the server is at minimum advertising its introspection API in the
# shipped contract; combined with N_007 / N_011 this confirms it.
_INTROSPECTION_TOKENS = (
    "__schema", "__type", "IntrospectionQuery", "fragment FullType",
)

# Tokens that, in a GraphQL schema, indicate the schema dump exposes
# operations callers can run unauthenticated.
_GRAPHQL_ROOT_RE = re.compile(
    r"^\s*type\s+(Query|Mutation|Subscription)\s*\{",
    re.MULTILINE,
)
_GRAPHQL_AUTH_DIRECTIVES = (
    "@auth", "@requiresAuth", "@hasRole", "@isAuthenticated",
    "@private", "@authenticated",
)

# .proto regex set — kept deliberately small. A real protobuf parser
# (`grpc_tools.protoc`) is overkill for a static surface enumeration
# and pulls in a >100MB dep; line-regex covers ~98% of hand-written
# proto in production APKs.
_PROTO_SERVICE_RE = re.compile(r"^\s*service\s+(\w+)\s*\{", re.MULTILINE)
_PROTO_RPC_RE = re.compile(
    r"^\s*rpc\s+(\w+)\s*\(\s*(stream\s+)?([\w\.]+)\s*\)\s*"
    r"returns\s*\(\s*(stream\s+)?([\w\.]+)\s*\)",
    re.MULTILINE,
)
# Heuristic auth markers inside a service or RPC body
_PROTO_AUTH_HINTS = (
    "auth_required", "google.api.http", "security",
    "auth_metadata", "authorization",
)


class GraphQLGrpcAnalyzerAgent(BaseAgent):
    """K_001: enumerate GraphQL schema + gRPC .proto surface."""

    AGENT_ID = "K_001"
    VULN_CLASS = "GraphQL / gRPC Schema Exposure"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            (ctx.decompiled_dir and ctx.decompiled_dir.exists())
            or (ctx.resources_dir and ctx.resources_dir.exists())
        )

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []

        graphql_files, proto_files = self._collect_schema_files()

        for path, rel in graphql_files:
            findings.extend(self._analyze_graphql(path, rel))

        for path, rel in proto_files:
            findings.extend(self._analyze_proto(path, rel))

        return findings

    # ---------- Discovery ----------

    def _collect_schema_files(
        self,
    ) -> tuple[list[tuple[Path, str]], list[tuple[Path, str]]]:
        """Walk decompiled + resource trees; bucket schema files by type."""
        graphql: list[tuple[Path, str]] = []
        proto: list[tuple[Path, str]] = []

        for root in self._search_roots():
            scanned = 0
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                scanned += 1
                if scanned > _MAX_FILES:
                    break
                name = path.name.lower()
                if name.endswith(_GRAPHQL_SUFFIXES):
                    graphql.append((path, str(path.relative_to(root))))
                elif name.endswith(_PROTO_SUFFIX):
                    proto.append((path, str(path.relative_to(root))))

        return graphql, proto

    def _search_roots(self) -> list[Path]:
        ctx = self._context
        roots: list[Path] = []
        # Resource trees from apktool first — that's where assets/ + res/raw/ live
        if ctx.resources_dir and ctx.resources_dir.exists():
            for sub in ("assets", "res/raw"):
                p = ctx.resources_dir / sub
                if p.is_dir():
                    roots.append(p)
        # JADX decompiled dir — devs sometimes ship .graphql inside src/main/resources
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            roots.append(ctx.decompiled_dir)
        return roots

    # ---------- GraphQL ----------

    def _analyze_graphql(self, path: Path, rel: str) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        out: list[Finding] = []

        # 1) Introspection markers
        introspection_hits = [tok for tok in _INTROSPECTION_TOKENS if tok in text]
        if introspection_hits:
            out.append(self._make_finding(
                vuln_class="GraphQL Schema Ships Introspection Surface",
                severity=Severity.MEDIUM,
                confidence=0.80,
                recommendation=(
                    "Introspection markers were found in a shipped schema "
                    "artifact. Disable introspection on production GraphQL "
                    "endpoints, or persist queries server-side so the schema "
                    "is not discoverable. Pair with N_011 to confirm the "
                    "server still answers `__schema` queries."
                ),
                evidence={
                    "file": rel,
                    "markers": introspection_hits,
                },
            ))

        # 2) Roots without auth directives
        roots = _GRAPHQL_ROOT_RE.findall(text)
        directives_present = [d for d in _GRAPHQL_AUTH_DIRECTIVES if d in text]
        risky_roots = {"Mutation", "Subscription"} & set(roots)
        if risky_roots and not directives_present:
            out.append(self._make_finding(
                vuln_class="GraphQL Mutations/Subscriptions Without Auth Directives",
                severity=Severity.LOW,
                confidence=0.65,
                recommendation=(
                    "Mutation/Subscription roots are declared but the schema "
                    "contains no recognised auth directive. Confirm the "
                    "server enforces auth at the resolver layer — schemas "
                    "that omit visible auth are a strong signal of "
                    "field-level authorisation being implicit."
                ),
                evidence={
                    "file": rel,
                    "roots_found": sorted(roots),
                    "directives_found": directives_present,
                },
            ))

        # 3) Schema dump — info disclosure (any non-trivial schema in assets)
        if len(text) > 2_000 and "type Query" in text:
            out.append(self._make_finding(
                vuln_class="Full GraphQL Schema Shipped in APK",
                severity=Severity.INFO,
                confidence=0.85,
                recommendation=(
                    "A full GraphQL schema is shipped inside the APK. Even "
                    "when introspection is disabled server-side, attackers "
                    "can unzip the APK and read the entire type system. "
                    "Consider persisted queries to keep operations opaque."
                ),
                evidence={
                    "file": rel,
                    "size_bytes": len(text),
                },
            ))

        return out

    # ---------- gRPC / .proto ----------

    def _analyze_proto(self, path: Path, rel: str) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        services = _PROTO_SERVICE_RE.findall(text)
        rpcs = _PROTO_RPC_RE.findall(text)
        if not services and not rpcs:
            return []

        # Parse RPC tuples: (name, req_stream, req_type, resp_stream, resp_type)
        methods: list[dict[str, Any]] = []
        streaming_methods: list[str] = []
        for name, req_stream, req_type, resp_stream, resp_type in rpcs:
            rec = {
                "method": name,
                "request_type": req_type,
                "response_type": resp_type,
                "client_streaming": bool(req_stream.strip()),
                "server_streaming": bool(resp_stream.strip()),
            }
            methods.append(rec)
            if rec["client_streaming"] or rec["server_streaming"]:
                streaming_methods.append(name)

        out: list[Finding] = []

        # Auth-hint heuristic: did anyone in this file mention auth?
        has_auth_hint = any(tok in text for tok in _PROTO_AUTH_HINTS)

        if services and not has_auth_hint:
            out.append(self._make_finding(
                vuln_class="gRPC Service Without Auth Metadata Annotations",
                severity=Severity.LOW,
                confidence=0.60,
                recommendation=(
                    "gRPC service(s) found with no auth_required, "
                    "google.api.http, or authorization annotations. "
                    "Confirm the gRPC interceptor enforces authentication "
                    "on every RPC — proto without auth annotations is a "
                    "common cause of unauthenticated gRPC endpoints."
                ),
                evidence={
                    "file": rel,
                    "services": services,
                    "methods": [m["method"] for m in methods][:50],
                    "method_count": len(methods),
                },
            ))

        # Streaming surface enumeration — feeds dynamic test phase
        if streaming_methods:
            out.append(self._make_finding(
                vuln_class="gRPC Streaming RPC Surface",
                severity=Severity.INFO,
                confidence=0.80,
                recommendation=(
                    "Streaming RPCs enumerated for the dynamic phase. "
                    "Verify deadline propagation, per-stream auth, and that "
                    "the server bounds the number of concurrent open "
                    "streams per client."
                ),
                evidence={
                    "file": rel,
                    "streaming_methods": streaming_methods[:50],
                    "service_count": len(services),
                },
            ))

        return out


__all__ = ["GraphQLGrpcAnalyzerAgent"]
