"""API traffic parser — turns a mitmproxy JSONL capture into structured
inputs for the API-testing agents (BOLA / Mass Assignment / Data Exposure).

Consumers get three primitives:

* :func:`load_flows` — read a ``mitm_capture.jsonl`` (or the legacy
  ``mitmproxy_flows.jsonl``) into a list of :class:`CapturedFlow`.
* :func:`group_by_endpoint` — bucket flows under a templated
  ``(host, method, path)`` key so ``/users/42`` and ``/users/9001`` collapse
  into ``/users/{id}``.
* :func:`extract_object_ids` — pull ID-shaped values out of URL segments
  and JSON request/response bodies for mutation candidates.

The templating regex mirrors the one used by
:mod:`sentinel.agents.api_security.openapi_inferrer` on purpose — both
modules must produce the same endpoint key for the same flow so agents can
correlate observations across the pipeline.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sentinel.tools.mitmproxy_runner import CapturedFlow

logger = logging.getLogger(__name__)


# ---------- Constants ----------

# Path segments that look like IDs get templated. Kept in sync with the
# equivalent regex inside openapi_inferrer._templatize_path.
_ID_SEGMENT_RE = re.compile(
    r"^("
    r"\d{1,}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}"
    r"|[A-Za-z0-9_-]{20,}"
    r")$"
)

# Header names commonly carrying a per-user credential. Lower-cased for
# case-insensitive matching against captured headers.
_AUTH_HEADER_NAMES = (
    "authorization",
    "x-auth-token",
    "x-api-key",
    "x-access-token",
    "cookie",
    "x-csrf-token",
    "x-session-token",
)

# JSON body keys likely to hold an object identifier the agent might mutate.
_BODY_ID_KEY_RE = re.compile(r"^(id|.+_id|.+Id)$")


# ---------- Data classes ----------

@dataclass(frozen=True)
class EndpointKey:
    """Templated identity for a group of related flows.

    Equality/hashing is on the tuple (host, method, template) so the class
    can be used as a dict key.
    """

    host: str
    method: str
    template: str  # e.g. "/api/v1/users/{id}"

    def __str__(self) -> str:  # pragma: no cover - debug convenience
        return f"{self.method} {self.host}{self.template}"


@dataclass(frozen=True)
class ObjectId:
    """A single ID-shaped value found inside a flow.

    Attributes:
        location: ``"path"`` for URL-segment IDs, ``"body"`` for JSON body keys.
        key: For path IDs the segment index (as a string); for body IDs the
            JSON key name. Kept as ``str`` so both flavours share a type.
        value: The raw ID value.
        is_numeric: True if ``value`` is entirely digits — governs whether the
            BOLA verifier can safely do ±1 mutation.
    """

    location: str
    key: str
    value: str
    is_numeric: bool


# ---------- Loading ----------

def _candidate_paths(hint: Path) -> list[Path]:
    """Given a hint path, return the concrete candidates to try in order.

    Accepts either the current ``mitm_capture.jsonl`` name or the older
    ``mitmproxy_flows.jsonl`` the design brief referenced.
    """
    if hint.is_file():
        return [hint]
    if hint.is_dir():
        return [hint / "mitm_capture.jsonl", hint / "mitmproxy_flows.jsonl"]
    # Not a file, not a dir — still try both siblings so callers can pass
    # either name directly.
    return [hint, hint.with_name("mitmproxy_flows.jsonl")]


def load_flows(path: Path) -> list[CapturedFlow]:
    """Read a mitmproxy JSONL capture into ``CapturedFlow`` instances.

    Malformed lines and error records (produced by the addon when it can't
    serialize a flow) are skipped rather than raising — the capture file is
    an audit artefact, not a strict schema.
    """
    for candidate in _candidate_paths(Path(path)):
        if candidate.is_file():
            path = candidate
            break
    else:
        logger.debug("api_parser: no capture file found near %s", path)
        return []

    flows: list[CapturedFlow] = []
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("api_parser: skip malformed line %d in %s", line_no, path)
            continue
        if "error" in record and "method" not in record:
            # Addon emits {"error": "..."} rows when a flow fails to encode.
            continue
        try:
            flows.append(
                CapturedFlow(
                    method=str(record.get("method", "")).upper(),
                    url=str(record.get("url", "")),
                    scheme=str(record.get("scheme", "")),
                    host=str(record.get("host", "")),
                    path=str(record.get("path", "")),
                    request_headers=dict(record.get("request_headers") or {}),
                    request_body=str(record.get("request_body", "") or ""),
                    response_status=int(record.get("response_status") or 0),
                    response_headers=dict(record.get("response_headers") or {}),
                    response_body=str(record.get("response_body", "") or ""),
                    tls_failed=bool(record.get("tls_failed", False)),
                    timestamp=float(record.get("timestamp") or 0.0),
                )
            )
        except (TypeError, ValueError):
            logger.debug("api_parser: skip unusable record on line %d", line_no)
    return flows


# ---------- Templating / grouping ----------

def templatize_path(path: str) -> str:
    """Replace ID-shaped segments in ``path`` with ``{id}``."""
    if not path or path == "/":
        return path or "/"
    parts = path.split("/")
    return "/".join("{id}" if _ID_SEGMENT_RE.match(p) else p for p in parts)


def group_by_endpoint(
    flows: Iterable[CapturedFlow],
) -> dict[EndpointKey, list[CapturedFlow]]:
    """Bucket flows by ``(host, method, templated_path)``.

    Flows with no host are skipped — they're always addon artefacts. The
    query string is stripped from the path before templating so
    ``/orders?limit=10`` and ``/orders?limit=25`` land in the same bucket.
    """
    groups: dict[EndpointKey, list[CapturedFlow]] = defaultdict(list)
    for flow in flows:
        host = (flow.host or "").lower()
        if not host:
            continue
        method = (flow.method or "GET").upper()
        raw_path = (flow.path or "/").split("?", 1)[0]
        template = templatize_path(raw_path)
        groups[EndpointKey(host, method, template)].append(flow)
    return dict(groups)


# ---------- Auth extraction ----------

def extract_auth_headers(flow: CapturedFlow) -> dict[str, str]:
    """Return the subset of request headers that look like credentials.

    Header names are returned in their **original casing** so the replayed
    request looks identical to the captured one on the wire.
    """
    result: dict[str, str] = {}
    for name, value in (flow.request_headers or {}).items():
        if name.lower() in _AUTH_HEADER_NAMES and value:
            result[name] = value
    return result


# ---------- ID extraction ----------

def _walk_json_ids(node: Any, out: list[ObjectId]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (str, int)) and _BODY_ID_KEY_RE.match(str(k)):
                s = str(v)
                out.append(ObjectId(
                    location="body", key=str(k),
                    value=s, is_numeric=s.isdigit(),
                ))
            _walk_json_ids(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk_json_ids(item, out)


def extract_object_ids(flow: CapturedFlow) -> list[ObjectId]:
    """Enumerate ID-shaped values from URL segments and JSON body keys.

    Path IDs appear before body IDs so callers that only mutate the first
    one keep the most exploitable target (the URL-embedded ID).
    """
    ids: list[ObjectId] = []

    # Path segments
    raw_path = (flow.path or "/").split("?", 1)[0]
    for idx, segment in enumerate(raw_path.split("/")):
        if _ID_SEGMENT_RE.match(segment):
            ids.append(ObjectId(
                location="path", key=str(idx),
                value=segment, is_numeric=segment.isdigit(),
            ))

    # JSON body
    body = flow.request_body or ""
    if body.strip().startswith(("{", "[")):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            _walk_json_ids(payload, ids)

    return ids


# ---------- Convenience: mutate an ID inside a URL path ----------

def replace_path_segment(path: str, segment_index: int, new_value: str) -> str:
    """Return ``path`` with the segment at ``segment_index`` replaced.

    Preserves the query string. Returns ``path`` unchanged if the index is
    out of range — the caller decides whether that's an error.
    """
    if "?" in path:
        raw, qs = path.split("?", 1)
        qs = "?" + qs
    else:
        raw, qs = path, ""
    parts = raw.split("/")
    if 0 <= segment_index < len(parts):
        parts[segment_index] = new_value
    return "/".join(parts) + qs
