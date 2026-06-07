"""D_009 — IDOR / Mass-Assignment Candidate Identifier.

Authenticated mobile flows routinely embed a user identifier in the
URL path, query string, or JSON body. When the server fails to verify
that the bearer token actually owns that identifier, swapping the
identifier reveals other users' data (classic IDOR / BOLA — OWASP API
Top 10 #1). Mass-assignment is the dual: the server happily accepts
extra JSON keys the client UI never sends (``is_admin``,
``balance_override``, ``role``) because the controller binds the body
straight onto a model.

A *true* confirmation needs an active replayer that re-fires each
authenticated request with a perturbed identifier and observes the
response. That belongs in the exploit engine and is opt-in. This
agent does the upstream candidate-identification work over the
mitmproxy capture:

* Endpoints that carry a user-ID-shaped path / query parameter
  *and* return user-scoped data become IDOR candidates.
* Endpoints whose request body carries privilege-relevant keys
  become mass-assignment candidates.

Detection (IDOR)
----------------

A flow is an IDOR candidate when:

1. Method is GET / POST / PUT / PATCH / DELETE.
2. The path contains a segment that looks like a user ID — pure
   integer, UUID, or a base32/base58/base64-shaped opaque string
   ≥ 6 chars — under any of the path tokens commonly used for owner
   refs (``users``, ``user``, ``accounts``, ``profiles``, ``customers``,
   ``orders``, ``invoices``, ``transactions``, ``cards``, ``wallets``,
   ``messages``, ``conversations``, ``files``, ``documents``).
3. The response is 200 and the body has any of the typical
   user-PII shapes (``email``, ``phone``, ``balance``, ``address``,
   ``ssn``, ``dob`` keys, or `"@"` chars).

Detection (mass-assignment)
---------------------------

A flow is a mass-assignment candidate when:

1. Method is POST / PUT / PATCH.
2. Request body is JSON.
3. Body contains one or more keys whose name matches the privilege /
   audit keyword list (``is_admin``, ``admin``, ``role``,
   ``permissions``, ``is_verified``, ``email_verified``,
   ``balance_override``, ``is_premium``).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_OWNER_PATH_TOKENS = (
    "users", "user", "accounts", "account", "profiles", "profile",
    "customers", "customer", "orders", "order", "invoices", "invoice",
    "transactions", "transaction", "cards", "card", "wallets", "wallet",
    "messages", "message", "conversations", "conversation",
    "files", "file", "documents", "document",
)
_PII_KEY_HINTS = re.compile(
    r'"(?:email|phone|mobile|balance|address|ssn|dob|first_name|'
    r'last_name|full_name|aadhaar|pan|iban|account_number)"\s*:',
    re.IGNORECASE,
)
_PRIV_KEYS = {
    "is_admin", "admin", "role", "roles", "permissions",
    "is_verified", "email_verified", "phone_verified",
    "balance_override", "is_premium", "is_pro", "scope",
    "kyc_status", "account_status",
}

_INT_ID = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_\-]{6,}$")


class IdorCandidateAgent(BaseAgent):
    """D_009: identify IDOR and mass-assignment replay candidates."""

    AGENT_ID = "D_009"
    VULN_CLASS = "IDOR / Mass-Assignment Candidate"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_009] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        idor_seen: dict[tuple[str, str, str], dict[str, Any]] = {}
        mass_seen: dict[tuple[str, str, str], dict[str, Any]] = {}

        for flow in capture.flows:
            method = (getattr(flow, "method", "") or "").upper()
            path = getattr(flow, "path", "") or ""
            host = getattr(flow, "host", "") or ""

            # ---- IDOR ----
            if method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                id_segment = _detect_owner_id(path)
                status = int(getattr(flow, "response_status", 0) or 0)
                if id_segment and 200 <= status < 300:
                    body = getattr(flow, "response_body", "") or ""
                    if _PII_KEY_HINTS.search(body) or "@" in body[:2000]:
                        key = (host, _template(path), method)
                        entry = idor_seen.setdefault(key, {
                            "host": host, "method": method,
                            "path": path, "id_segment": id_segment,
                            "occurrence_count": 0,
                        })
                        entry["occurrence_count"] += 1

            # ---- mass assignment ----
            if method in ("POST", "PUT", "PATCH"):
                priv_keys = _detect_priv_keys(flow)
                if priv_keys:
                    key = (host, _template(path), method)
                    entry = mass_seen.setdefault(key, {
                        "host": host, "method": method,
                        "path": path, "priv_keys": set(),
                        "occurrence_count": 0,
                    })
                    entry["priv_keys"].update(priv_keys)
                    entry["occurrence_count"] += 1

        findings: list[Finding] = []
        for entry in idor_seen.values():
            findings.append(self._idor_finding(entry))
        for entry in mass_seen.values():
            findings.append(self._mass_finding(entry))
        return findings

    def _idor_finding(self, entry: dict[str, Any]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.70,
            evidence={
                "issue": (
                    "The application makes an authenticated request "
                    f"to {entry['host']}{entry['path']} where the path "
                    f"contains an owner identifier "
                    f"({entry['id_segment']!r}) and the response "
                    "returns user-shaped PII. If the server does not "
                    "verify that the bearer token owns that "
                    "identifier, swapping it reveals other users' "
                    "data (IDOR / OWASP API Top-10 #1)."
                ),
                "host": entry["host"],
                "method": entry["method"],
                "path": entry["path"],
                "id_segment_observed": entry["id_segment"],
                "occurrence_count": entry["occurrence_count"],
                "vector": (
                    "mitmproxy capture: state-affecting or read "
                    "endpoint with an owner-shaped path segment "
                    "returning PII. Confirmation requires the exploit "
                    "engine to re-issue with a perturbed ID under the "
                    "same session token."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "On every request, derive the owner identity from the "
                "session token (JWT claim or session record) and "
                "compare it to the resource owner. Reject mismatches "
                "with 403 before any read. Avoid putting raw "
                "sequential integers in user-facing paths — opaque "
                "UUIDs raise the per-request cost of a brute-force "
                "enumeration but are not a substitute for the "
                "ownership check."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-2",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )

    def _mass_finding(self, entry: dict[str, Any]) -> Finding:
        keys = sorted(entry["priv_keys"])
        return self._make_finding(
            vuln_class="Mass-Assignment Candidate",
            severity=Severity.HIGH,
            confidence=0.75,
            evidence={
                "issue": (
                    "The application sends an authenticated "
                    f"{entry['method']} to "
                    f"{entry['host']}{entry['path']} whose JSON body "
                    f"contains privilege-relevant keys ({keys}). If "
                    "the server binds the body directly onto a model "
                    "or DTO without an allow-list, an attacker can "
                    "add the same keys to a normal request and "
                    "escalate privileges or override server-only "
                    "fields."
                ),
                "host": entry["host"],
                "method": entry["method"],
                "path": entry["path"],
                "privilege_keys_observed": keys,
                "occurrence_count": entry["occurrence_count"],
                "vector": (
                    "mitmproxy capture: JSON request body contains "
                    "privilege / audit keys the client UI rarely "
                    "needs to set. Confirmation requires the exploit "
                    "engine to re-issue a normal request with "
                    "is_admin / role / similar added."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Use an explicit input DTO with an allow-list of "
                "fields the client may set; never pass the raw "
                "request body into a model constructor or "
                "ActiveRecord-style mass assigner. In Spring use "
                "@JsonProperty + @JsonIgnoreProperties(ignoreUnknown="
                "true), in Django REST use explicit fields= in the "
                "serializer, in Rails use strong_parameters with "
                "permit. Server-only fields (role, is_admin, "
                "balance) must never be writable via any client "
                "endpoint."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        )


# ---------- heuristics ----------


def _detect_owner_id(path: str) -> str | None:
    parts = path.split("?", 1)[0].split("/")
    for i, p in enumerate(parts):
        if p.lower() in _OWNER_PATH_TOKENS and i + 1 < len(parts):
            nxt = parts[i + 1]
            if _INT_ID.match(nxt) or _UUID.match(nxt) or (
                _OPAQUE_ID.match(nxt) and len(nxt) >= 6
            ):
                return nxt
    return None


def _detect_priv_keys(flow: Any) -> set[str]:
    body = getattr(flow, "request_body", "") or ""
    if not body or "{" not in body:
        return set()
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return set()
    return _walk_priv_keys(parsed)


def _walk_priv_keys(obj: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in _PRIV_KEYS:
                out.add(str(k))
            out |= _walk_priv_keys(v)
    elif isinstance(obj, list):
        for x in obj:
            out |= _walk_priv_keys(x)
    return out


def _template(path: str) -> str:
    parts = path.split("?", 1)[0].split("/")
    return "/".join(
        "{id}" if (_INT_ID.match(p) or _UUID.match(p)
                   or (_OPAQUE_ID.match(p) and len(p) >= 10))
        else p
        for p in parts
    )
