"""D_017 — GraphQL Persisted-Query Bypass.

Modern GraphQL APIs use *persisted queries* — the client sends an
opaque hash (the query's SHA-256) and the server resolves it against
a server-side allow-list of pre-registered operations. Properly
implemented, this gives you both bandwidth savings and a defence
mechanism: arbitrary queries (introspection, sensitive selection
sets, expensive recursive lookups) are simply not in the allow-list
and the server rejects them with a ``PersistedQueryNotFound`` error.

The bug class: many servers ship the Apollo "Automatic Persisted
Queries" (APQ) protocol, which *registers* a new query on the fly
whenever the client sends both the hash and the full query body.
With APQ on in production, anyone who knows the protocol can send a
``{ "extensions": {"persistedQuery": {"sha256Hash": "..."}}, "query":
"<arbitrary>" }`` payload and the server registers + executes it,
defeating the allow-list entirely.

Detection
---------

Pure mitmproxy-side analysis. We walk every captured GraphQL flow
and look at the request body / query string. A flow is a GraphQL
endpoint when:

* the path includes ``/graphql`` / ``/gql`` / ``/api/graphql``, OR
* the body is JSON with a ``"query"`` or ``"operationName"`` key, OR
* the response Content-Type contains ``application/graphql-response``.

Then we classify three categories:

* **CRITICAL** — request carries the APQ extension AND a full
  ``query`` string (the registration path is exercised). The server
  is allowing on-the-fly query registration in production.
* **HIGH** — introspection query (``__schema``, ``__type``) sent
  alongside a persisted-query hash. Server responded 200 with a
  ``data`` field, meaning introspection is reachable through the
  bypass.
* **MEDIUM** — server response contains ``PersistedQueryNotFound``
  *and* the immediately following request includes the same hash
  with a full query string (the canonical APQ "register and retry"
  handshake — confirms the bypass path is active).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_GRAPHQL_PATH = re.compile(r"/(?:graphql|gql)\b", re.IGNORECASE)
_INTROSPECTION = re.compile(
    r"__(?:schema|type)\b",
    re.IGNORECASE,
)


class GraphqlPersistedQueryAgent(BaseAgent):
    """D_017: detect Apollo APQ register-on-the-fly bypasses."""

    AGENT_ID = "D_017"
    VULN_CLASS = "GraphQL Persisted-Query Bypass"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_017] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        registration_hits: list[dict[str, Any]] = []
        introspection_hits: list[dict[str, Any]] = []
        handshake_hits: list[dict[str, Any]] = []

        # We need flow ordering for the "register and retry" handshake
        # detection — mitmproxy gives us flows in observed order.
        last_pqn_hash: tuple[str, str] | None = None  # (host, hash)

        for flow in capture.flows:
            host = getattr(flow, "host", "") or ""
            method = (getattr(flow, "method", "") or "").upper()
            path = getattr(flow, "path", "") or ""
            req_body = getattr(flow, "request_body", "") or ""
            resp_body = getattr(flow, "response_body", "") or ""
            status = int(getattr(flow, "response_status", 0) or 0)
            if not _looks_graphql(path, req_body, flow):
                continue

            parsed = _parse_graphql_request(req_body)
            if parsed is None:
                continue
            query_str, persisted_hash = parsed

            sample = {
                "host": host, "method": method, "path": path,
                "status": status,
                "has_hash": bool(persisted_hash),
                "has_query": bool(query_str),
            }

            if persisted_hash and query_str:
                registration_hits.append({**sample,
                                          "hash_prefix": persisted_hash[:16]})
                if _INTROSPECTION.search(query_str):
                    if 200 <= status < 300 and '"data"' in resp_body:
                        introspection_hits.append({
                            **sample,
                            "hash_prefix": persisted_hash[:16],
                        })

            # Handshake detection: a PersistedQueryNotFound response
            # immediately followed by a re-issue with both hash and
            # query.
            if (last_pqn_hash is not None
                    and last_pqn_hash[0] == host
                    and last_pqn_hash[1] == persisted_hash
                    and query_str and persisted_hash):
                handshake_hits.append({
                    **sample,
                    "hash_prefix": persisted_hash[:16],
                })
            if "PersistedQueryNotFound" in resp_body and persisted_hash:
                last_pqn_hash = (host, persisted_hash)
            else:
                last_pqn_hash = None

        findings: list[Finding] = []
        if registration_hits:
            findings.append(self._registration_finding(registration_hits))
        if introspection_hits:
            findings.append(self._introspection_finding(introspection_hits))
        if handshake_hits:
            findings.append(self._handshake_finding(handshake_hits))
        return findings

    def _registration_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.85,
            evidence={
                "issue": (
                    "The GraphQL endpoint is invoked with both a "
                    "``persistedQuery.sha256Hash`` extension AND a "
                    "full ``query`` body. This is the Apollo "
                    "Automatic Persisted Queries (APQ) registration "
                    "path. With APQ on in production, an attacker can "
                    "register any operation on the fly — defeating "
                    "the persisted-query allow-list entirely."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: GraphQL request inspected for "
                    "the APQ extension and a non-empty query string "
                    "in the same payload."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Disable APQ in production. Apollo Server: set "
                "``persistedQueries: false`` or supply only a "
                "read-only ``PersistedQueryCache`` populated at build "
                "time from the client's manifest. Apollo Router: set "
                "``apq.enabled: false`` and use the "
                "``persisted_queries`` plugin with "
                "``safelist.require_id: true``. Reject any request "
                "that carries a hash AND a query body — pick one."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _introspection_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="GraphQL Introspection Reachable via APQ Bypass",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "A GraphQL introspection query (``__schema`` / "
                    "``__type``) was answered 2xx with a ``data`` "
                    "field even though it was wrapped in the APQ "
                    "envelope. The complete API surface is now "
                    "machine-readable to anyone who can hit the "
                    "endpoint — feeding GraphQL fuzzers, query "
                    "explorers, and reconnaissance tools."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: persisted-query body decoded; "
                    "embedded GraphQL string scanned for __schema / "
                    "__type tokens; response status + body checked."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Disable introspection in production (Apollo: "
                "``introspection: false``; Federation: set "
                "``router.introspection: false``). Pair with "
                "persisted-query enforcement so unknown operations "
                "are rejected at the router."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

    def _handshake_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="GraphQL APQ Register-and-Retry Handshake Active",
            severity=Severity.MEDIUM,
            confidence=0.85,
            evidence={
                "issue": (
                    "The capture shows the canonical Apollo APQ "
                    "register-and-retry handshake: server responds "
                    "``PersistedQueryNotFound``, client immediately "
                    "re-issues with the same hash plus the full "
                    "query body, server then answers. The server "
                    "is accepting client-side registration of new "
                    "queries — the persisted-query allow-list is "
                    "not enforced."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "mitmproxy capture: PersistedQueryNotFound "
                    "response immediately followed by a re-issue of "
                    "the same hash with a non-empty query body."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Enforce a server-side persisted-query allow-list "
                "loaded at deploy time from the client's manifest. "
                "Reject any registration attempt outright. If the "
                "client is dynamic enough that a manifest is "
                "impractical, swap to a custom auth header that the "
                "edge gateway pins to a client-version-specific "
                "manifest."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )


# ---------- helpers ----------


def _looks_graphql(path: str, body: str, flow: Any) -> bool:
    if _GRAPHQL_PATH.search(path):
        return True
    if body and ('"query"' in body or '"operationName"' in body):
        return True
    headers = getattr(flow, "response_headers", {}) or {}
    ctype = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ctype = str(v).lower()
            break
    return "application/graphql" in ctype


def _parse_graphql_request(
    body: str,
) -> tuple[str, str] | None:
    """Return (query_string, persisted_hash) — either may be empty.

    Returns None when the body isn't recognised as a GraphQL request.
    """
    if not body or not body.strip().startswith("{"):
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    query = str(data.get("query") or "").strip()
    persisted_hash = ""
    extensions = data.get("extensions")
    if isinstance(extensions, dict):
        pq = extensions.get("persistedQuery")
        if isinstance(pq, dict):
            persisted_hash = str(pq.get("sha256Hash") or "").strip()
    if not query and not persisted_hash:
        return None
    return query, persisted_hash
