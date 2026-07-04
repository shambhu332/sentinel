"""API_004 — Excessive Data Exposure analyzer.

Post-processing agent that cross-references what the backend actually
**returns** against what the mobile app actually **renders**. When the
server ships a sensitive field the client never touches, we've found an
excessive-data-exposure defect (OWASP API3:2019, still relevant even
though the 2023 list reframed it under BOPLA).

Signal chain:

1. Walk every captured flow's JSON response body and collect the set of
   **keys** appearing at any depth.
2. Filter that set against a curated list of sensitive key substrings
   (``ssn``, ``credit_card``, ``password_hash``, ``internal_ip`` and a
   few close cousins). The match is case-insensitive substring so
   ``credit_card_last4`` and ``creditCardNumber`` both trip.
3. For each sensitive key hit, grep the decompiled sources + resources
   for a literal string reference. Presence = the client actually binds
   it into UI or logic; absence = the API is over-sharing.

This is deliberately a *cheap* SAST↔DAST correlation — no HTTP calls, no
LLM. It runs after the DAST phase completes and consumes the mitmproxy
capture that other agents already produced.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.tools.mitmproxy_runner import CapturedFlow

logger = logging.getLogger(__name__)


# Substrings matched case-insensitively against JSON response keys.
# Extendable via ``config['extra_sensitive_keys']``.
_DEFAULT_SENSITIVE_KEYS: tuple[str, ...] = (
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cardnumber",
    "cvv",
    "cvc",
    "password_hash",
    "password_digest",
    "pwd_hash",
    "salt",
    "internal_ip",
    "private_ip",
    "internal_host",
    "internal_url",
    "api_secret",
    "client_secret",
    "dob",
    "date_of_birth",
)

_SOURCE_SUFFIXES: tuple[str, ...] = (".java", ".kt", ".xml", ".smali", ".json")

# Cap on files scanned per source directory to keep large APKs bounded.
_MAX_FILES_PER_ROOT = 15000


class DataExposureAgent(BaseAgent):
    """API_004: flag response fields the API returns but the mobile app ignores."""

    AGENT_ID = "API_004"
    VULN_CLASS = "Excessive Data Exposure"
    PHASE = "Phase 4"

    async def is_applicable(self) -> bool:
        capture = (self._context.sources or {}).get("mitmproxy")
        if capture is None:
            return False
        flows = getattr(capture, "flows", None) or []
        return any(_is_json_response(flow) for flow in flows)

    async def analyze(self) -> list[Finding]:
        capture = (self._context.sources or {}).get("mitmproxy")
        flows: list[CapturedFlow] = list(getattr(capture, "flows", []) or [])
        if not flows:
            return []

        cfg = self._config or {}
        extras = tuple(cfg.get("extra_sensitive_keys") or ())
        sensitive_keys = tuple(k.lower() for k in (_DEFAULT_SENSITIVE_KEYS + extras))

        # Bucket sensitive hits by (host, endpoint_path, key_name) so a
        # chatty endpoint that returns the same field on every response
        # only produces one finding.
        hits: dict[tuple[str, str, str], _Hit] = {}
        for flow in flows:
            if not _is_json_response(flow):
                continue
            payload = _try_json(flow.response_body)
            if payload is None:
                continue
            for key_path, key_name, sample in _walk_leaf_pairs(payload):
                lower_name = key_name.lower()
                matched = next(
                    (needle for needle in sensitive_keys if needle in lower_name),
                    None,
                )
                if matched is None:
                    continue
                bucket = (flow.host, flow.path, key_name)
                if bucket in hits:
                    continue
                hits[bucket] = _Hit(flow, key_name, key_path, matched, sample)

        if not hits:
            return []

        client_corpus = _load_client_corpus(self._context)

        findings: list[Finding] = []
        for hit in hits.values():
            if _key_referenced_in_client(hit.key_name, client_corpus):
                # App actually consumes the field — server is oversharing is
                # arguable but not clearly a defect.
                continue
            findings.append(self._build_finding(hit))
        return findings

    def _build_finding(self, hit: _Hit) -> Finding:
        flow = hit.flow
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.8,
            evidence={
                "host": flow.host,
                "endpoint": flow.path,
                "method": (flow.method or "GET").upper(),
                "response_status": flow.response_status,
                "key_name": hit.key_name,
                "key_path": hit.key_path,
                "sensitive_match": hit.sensitive_needle,
                "sample_value_masked": _mask(hit.sample),
                "description": (
                    f"{flow.method or 'GET'} {flow.host}{flow.path} returns "
                    f"`{hit.key_path}` (sensitive: matches "
                    f"`{hit.sensitive_needle}`), but no reference to this "
                    "field name was found in the decompiled client sources "
                    "or resources. The backend is shipping data the app "
                    "doesn't use."
                ),
            },
            recommendation=(
                "Trim the response shape at the API boundary — use explicit "
                "serializers (DRF, Marshmallow, Pydantic response_model) that "
                "list the fields to send. Do not rely on the client to "
                "ignore extra data; any attacker with a proxy can read it. "
                "For high-value data (SSN, card, password hashes), also "
                "verify the field isn't logged anywhere upstream."
            ),
            owasp="API3:2019 Excessive Data Exposure",
            masvs="MSTG-STORAGE-4",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            observed_result=(
                f"Response body from {flow.method} {flow.host}{flow.path} "
                f"contains `{hit.key_path}`; no reference to `{hit.key_name}` "
                "found in decompiled Java/Kotlin/XML/Smali."
            ),
            verification_status="verified by API_004 SAST cross-reference",
        )


class _Hit:
    """One sensitive field hit before the client-side lookup."""

    __slots__ = ("flow", "key_name", "key_path", "sensitive_needle", "sample")

    def __init__(
        self,
        flow: CapturedFlow,
        key_name: str,
        key_path: str,
        sensitive_needle: str,
        sample: Any,
    ) -> None:
        self.flow = flow
        self.key_name = key_name
        self.key_path = key_path
        self.sensitive_needle = sensitive_needle
        self.sample = sample


# ---------- Helpers ----------

def _is_json_response(flow: CapturedFlow) -> bool:
    if not flow.response_body:
        return False
    headers = flow.response_headers or {}
    ctype = headers.get("content-type") or headers.get("Content-Type") or ""
    if "json" in ctype.lower():
        return True
    stripped = flow.response_body.lstrip()
    return stripped.startswith(("{", "["))


def _try_json(text: str) -> Any:
    text = (text or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _walk_leaf_pairs(
    node: Any, prefix: str = "$",
) -> Iterable[tuple[str, str, Any]]:
    """Yield ``(json_path, key_name, value)`` for every dict leaf under ``node``.

    Nested objects and arrays are traversed; array indices appear in the
    path as ``[i]``. Only dict keys are considered sensitive candidates —
    values are carried so evidence can show a masked sample.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}"
            if isinstance(v, (dict, list)):
                yield from _walk_leaf_pairs(v, path)
            else:
                yield path, str(k), v
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_leaf_pairs(item, f"{prefix}[{i}]")


def _load_client_corpus(context: Any) -> str:
    """Concatenate decompiled sources + resources into one grep target."""
    roots: list[Path] = []
    decompiled = getattr(context, "decompiled_dir", None)
    if decompiled and Path(decompiled).exists():
        roots.append(Path(decompiled))
    resources = getattr(context, "resources_dir", None)
    if resources and Path(resources).exists():
        roots.append(Path(resources))

    chunks: list[str] = []
    for root in roots:
        scanned = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            scanned += 1
            if scanned > _MAX_FILES_PER_ROOT:
                logger.debug(
                    "api_004: capped source scan at %d files under %s",
                    _MAX_FILES_PER_ROOT, root,
                )
                break
            try:
                chunks.append(path.read_text(errors="replace"))
            except OSError:
                continue
    return "\n".join(chunks)


def _key_referenced_in_client(key_name: str, corpus: str) -> bool:
    """True if ``key_name`` appears in the client corpus.

    Matches either the raw ``key_name`` (JSON commonly uses snake_case) or
    its ``camelCase`` counterpart (Kotlin/Java field names). Absence in
    both spellings is the finding signal.
    """
    if not corpus:
        return False
    if _find_word(corpus, key_name):
        return True
    camel = _snake_to_camel(key_name)
    if camel != key_name and _find_word(corpus, camel):
        return True
    return False


def _find_word(haystack: str, needle: str) -> bool:
    if not needle:
        return False
    pattern = re.compile(rf"(?<!\w){re.escape(needle)}(?!\w)", re.IGNORECASE)
    return bool(pattern.search(haystack))


def _snake_to_camel(name: str) -> str:
    parts = name.split("_")
    if len(parts) <= 1:
        return name
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:] if p)


def _mask(value: Any) -> str:
    s = str(value)
    if len(s) <= 4:
        return "***"
    if len(s) <= 8:
        return s[0] + "***" + s[-1]
    return s[:2] + "***" + s[-2:]
