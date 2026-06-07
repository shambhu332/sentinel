"""D_010 — JWT Weakness Observer.

Bearer-token authentication on mobile apps is nearly universal and JWT
is the dominant format. The library default is fine; the bugs come
from the application's own choices:

* ``alg: "none"`` accepted by the verifier (CVE-2015-9235 family).
* Symmetric ``HS256`` with a weak / guessable secret — once you have
  one token, you can brute-force the signing key offline and forge
  every other token.
* ``exp`` claim missing or set in the distant future — a stolen token
  remains valid forever.
* Missing ``aud`` / ``iss`` claim — token from one tenant accepted by
  another.
* ``kid`` field that looks like a path traversal or SQL fragment —
  enables key-confusion attacks against the verifier.
* JWTs that round-trip in URL query strings or response bodies (not
  ``Authorization`` headers) — they end up in browser history,
  proxy logs, and analytics pipelines.

This is pure passive analysis of the mitmproxy capture. We pull every
``Authorization: Bearer <token>`` header, decode the JWT, and emit
one finding per distinct weakness category we observe.

We never log the full token. Every finding shows only the header /
payload claim shape and a SHA-256 prefix of the signing input so a
reviewer can correlate evidence without leaking a usable credential.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_JWT_PATTERN = re.compile(
    r"\b([A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,})\b"
)
_BEARER = re.compile(r"^\s*Bearer\s+(.+)$", re.IGNORECASE)
_SUSPECT_KID = re.compile(
    r"(?:\.\./|/etc/|/proc/|--|;|\bUNION\b|\bSELECT\b)",
    re.IGNORECASE,
)


class JwtWeaknessAgent(BaseAgent):
    """D_010: detect JWT misconfigurations across the mitmproxy capture."""

    AGENT_ID = "D_010"
    VULN_CLASS = "JWT Weakness"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_010] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        # Each category accumulates evidence across observed tokens.
        # We emit at most one finding per category.
        evidence: dict[str, list[dict[str, Any]]] = {
            "alg_none": [],
            "alg_hs_weak_key": [],
            "missing_exp": [],
            "long_exp": [],
            "missing_aud_iss": [],
            "suspect_kid": [],
            "token_in_url": [],
        }

        seen_tokens: set[str] = set()
        for flow in capture.flows:
            tokens = _extract_tokens(flow)
            for source, raw in tokens:
                parsed = _decode_jwt(raw)
                if parsed is None:
                    continue
                header, payload, signing_input, signature = parsed
                token_id = hashlib.sha256(signing_input.encode()).hexdigest()[:16]
                if token_id in seen_tokens:
                    continue
                seen_tokens.add(token_id)

                host = getattr(flow, "host", "") or ""
                method = getattr(flow, "method", "") or ""
                path = getattr(flow, "path", "") or ""

                _classify_token(
                    header, payload, signing_input, signature,
                    source, host, method, path, token_id, evidence,
                )

        findings: list[Finding] = []
        if evidence["alg_none"]:
            findings.append(self._alg_none_finding(evidence["alg_none"]))
        if evidence["alg_hs_weak_key"]:
            findings.append(self._weak_key_finding(evidence["alg_hs_weak_key"]))
        if evidence["missing_exp"]:
            findings.append(self._missing_exp_finding(evidence["missing_exp"]))
        if evidence["long_exp"]:
            findings.append(self._long_exp_finding(evidence["long_exp"]))
        if evidence["missing_aud_iss"]:
            findings.append(self._missing_aud_iss_finding(
                evidence["missing_aud_iss"],
            ))
        if evidence["suspect_kid"]:
            findings.append(self._suspect_kid_finding(evidence["suspect_kid"]))
        if evidence["token_in_url"]:
            findings.append(self._token_in_url_finding(
                evidence["token_in_url"],
            ))
        return findings

    # ---------- per-category findings ----------

    def _alg_none_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "A JWT served by the application carries "
                    "``alg: \"none\"`` in its header. If the backend's "
                    "verifier honours this algorithm — a documented "
                    "default-on-CVE in several JWT libraries — an "
                    "attacker can forge arbitrary tokens by submitting "
                    "an unsigned JWT with the desired payload."
                ),
                "weakness": "alg_none",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: Authorization header / "
                    "response body inspected for JWT-shaped values; "
                    "header section decoded to read the alg claim."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "On the verifier, explicitly require a strong "
                "algorithm (``HS256``, ``RS256``, ``ES256``) and "
                "reject any other value before signature checking. "
                "Pin the algorithm into the verifier's configuration "
                "rather than reading it from the JWT header — never "
                "trust the alg the token itself reports."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def _weak_key_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JWT Weak HMAC Signing Key",
            severity=Severity.HIGH,
            confidence=0.70,
            evidence={
                "issue": (
                    "JWTs use ``HS256``/``HS384``/``HS512`` (symmetric "
                    "HMAC) for signing. If the secret is short or "
                    "guessable, an offline brute-force against any one "
                    "captured token recovers the signing key and lets "
                    "the attacker forge every other token. We could "
                    "not confirm the key strength from the capture, "
                    "but reviewer-side cracking with hashcat mode 16500 "
                    "or jwt-cracker should run against a known-bad "
                    "dictionary before shipping."
                ),
                "weakness": "alg_hs_weak_key_candidate",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: tokens flagged because their "
                    "alg header is HS* and so the signing key is a "
                    "secret shared between the app's backend and "
                    "anyone who can crack it."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Move to asymmetric signing (``RS256`` / ``ES256``) so "
                "the verifier only needs a public key — clients and "
                "intermediate services cannot forge new tokens even "
                "if compromised. If HS* is required, use a "
                "cryptographically random 256-bit secret stored in a "
                "secret manager, never a human-chosen passphrase, and "
                "rotate on compromise."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _missing_exp_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JWT Missing Expiry Claim",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "Captured JWTs do not carry an ``exp`` (expiration) "
                    "claim. A stolen token remains valid forever — "
                    "device theft, malware exfiltration, or accidental "
                    "leakage into client logs all become permanent "
                    "compromise rather than time-limited."
                ),
                "weakness": "missing_exp",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: JWT payload section decoded "
                    "and inspected for the ``exp`` claim."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Set ``exp`` to a short window (5–60 min for access "
                "tokens, longer for refresh tokens) and have the "
                "verifier reject the token strictly. Pair short "
                "access tokens with a rotating refresh-token flow "
                "(RFC 6749) and revoke refresh tokens server-side on "
                "logout / suspected compromise."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _long_exp_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JWT Excessive Expiry Window",
            severity=Severity.MEDIUM,
            confidence=0.85,
            evidence={
                "issue": (
                    "Captured JWTs carry an ``exp`` claim more than 30 "
                    "days in the future. The lifetime functionally "
                    "equals 'forever' for any practical attacker; a "
                    "device-lifted token is good until the user "
                    "manually rotates a credential they don't know "
                    "exists."
                ),
                "weakness": "long_exp",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: JWT payload section decoded; "
                    "``exp`` claim compared against ``iat`` / capture "
                    "time."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Cap access-token lifetimes at one hour or less and "
                "rotate refresh tokens on every use. Never issue a "
                "long-lived bearer that doubles as a refresh token."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        )

    def _missing_aud_iss_finding(
        self, items: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="JWT Missing Audience / Issuer Claim",
            severity=Severity.MEDIUM,
            confidence=0.80,
            evidence={
                "issue": (
                    "Captured JWTs do not bind to a specific audience "
                    "or issuer. A token issued for one tenant / "
                    "environment / service is indistinguishable from "
                    "any other, enabling token-replay across "
                    "deployments."
                ),
                "weakness": "missing_aud_iss",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: JWT payload section decoded "
                    "and inspected for ``aud`` / ``iss`` claims."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Always set ``aud`` to a stable identifier for the "
                "intended consumer (e.g., the API hostname) and "
                "``iss`` to your authorisation server's identifier. "
                "Enforce both on the verifier; reject mismatches."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        )

    def _suspect_kid_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JWT Suspicious kid Header",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "Captured JWTs carry a ``kid`` (key-id) header "
                    "whose value contains characters suggestive of "
                    "path traversal (``../``), SQL injection "
                    "(``--``, ``UNION``, ``SELECT``), or file-system "
                    "addressing (``/etc/``, ``/proc/``). When the "
                    "verifier uses ``kid`` to look up the signing key "
                    "from disk or a database, unsanitised "
                    "attacker-controlled values become RCE / "
                    "key-confusion bugs."
                ),
                "weakness": "suspect_kid",
                "samples": items[:5],
                "vector": "JWT header decoded and ``kid`` claim inspected.",
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Verify the ``kid`` against an explicit allow-list of "
                "expected key identifiers before any lookup. Never "
                "use the raw value in a filesystem path, SQL query, "
                "or shell argument. Prefer JWKS endpoint resolution "
                "with strict matching on the kid claim."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def _token_in_url_finding(self, items: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JWT Carried in URL",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "JWTs appear in URL query strings, not in the "
                    "``Authorization`` header. URLs end up in browser "
                    "history, server access logs, intermediary "
                    "proxies, error-reporting tools, and Play / iOS "
                    "analytics — the token leaks to every party in "
                    "the chain."
                ),
                "weakness": "token_in_url",
                "samples": items[:5],
                "vector": (
                    "mitmproxy capture: URLs scanned for JWT-shaped "
                    "values in the query string."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Move every bearer token into the ``Authorization: "
                "Bearer`` header. Never put a JWT, session ID, or "
                "refresh token in a URL query string, fragment, or "
                "path segment."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        )


# ---------- helpers ----------


def _extract_tokens(flow: Any) -> list[tuple[str, str]]:
    """Return (source, raw_jwt) pairs found in the flow."""
    out: list[tuple[str, str]] = []
    headers = getattr(flow, "request_headers", {}) or {}
    for h_name, h_val in headers.items():
        if h_name.lower() == "authorization":
            m = _BEARER.match(str(h_val))
            if m:
                raw = m.group(1).strip()
                if _looks_jwt(raw):
                    out.append(("authorization_header", raw))
    # Token-in-URL
    url = getattr(flow, "url", "") or ""
    if "?" in url:
        for m in _JWT_PATTERN.finditer(url):
            out.append(("url_query", m.group(1)))
    return out


def _looks_jwt(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3 and len(parts[0]) >= 4 and len(parts[1]) >= 4


def _decode_jwt(
    raw: str,
) -> tuple[dict, dict, str, str] | None:
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, f"{parts[0]}.{parts[1]}", parts[2]


def _b64decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _classify_token(
    header: dict,
    payload: dict,
    signing_input: str,
    signature: str,
    source: str,
    host: str,
    method: str,
    path: str,
    token_id: str,
    evidence: dict[str, list[dict[str, Any]]],
) -> None:
    sample = {
        "host": host,
        "method": method,
        "path": path,
        "source": source,
        "token_id": token_id,
        "header_keys": sorted(header.keys()),
        "payload_keys": sorted(payload.keys()),
    }

    alg = str(header.get("alg") or "").strip().upper()
    if alg in ("NONE", ""):
        evidence["alg_none"].append({
            **sample, "alg": alg, "signature_empty": signature == "",
        })
    elif alg.startswith("HS"):
        evidence["alg_hs_weak_key"].append({**sample, "alg": alg})

    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        evidence["missing_exp"].append(sample)
    elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = exp - iat
        if lifetime > 30 * 24 * 3600:  # > 30 days
            evidence["long_exp"].append({
                **sample,
                "lifetime_days": round(lifetime / 86400, 1),
            })
    elif isinstance(exp, (int, float)):
        # No iat — compare with now()
        now = datetime.now(timezone.utc).timestamp()
        if exp - now > 30 * 24 * 3600:
            evidence["long_exp"].append({
                **sample,
                "lifetime_days": round((exp - now) / 86400, 1),
            })

    if payload.get("aud") is None and payload.get("iss") is None:
        evidence["missing_aud_iss"].append(sample)

    kid = header.get("kid")
    if isinstance(kid, str) and _SUSPECT_KID.search(kid):
        evidence["suspect_kid"].append({**sample, "kid": kid})

    if source == "url_query":
        evidence["token_in_url"].append(sample)
