"""Unit tests for the mitmproxy API traffic parser (sentinel.tools.api_parser)."""
from __future__ import annotations

import json

import pytest

from sentinel.tools.api_parser import (
    EndpointKey,
    ObjectId,
    extract_auth_headers,
    extract_object_ids,
    group_by_endpoint,
    load_flows,
    replace_path_segment,
    templatize_path,
)
from sentinel.tools.mitmproxy_runner import CapturedFlow


# ---------- Helpers ----------

def _flow(**overrides) -> CapturedFlow:
    defaults = dict(
        method="GET",
        url="https://api.example.com/v1/users/42",
        scheme="https",
        host="api.example.com",
        path="/v1/users/42",
        request_headers={"Authorization": "Bearer abc.def"},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 42, "email": "a@b.c"}',
        tls_failed=False,
        timestamp=0.0,
    )
    defaults.update(overrides)
    return CapturedFlow(**defaults)


# ---------- Templating ----------

def test_templatize_numeric_segment():
    assert templatize_path("/v1/users/42") == "/v1/users/{id}"


def test_templatize_uuid_segment():
    p = "/orders/550e8400-e29b-41d4-a716-446655440000/items"
    assert templatize_path(p) == "/orders/{id}/items"


def test_templatize_opaque_token_segment():
    assert templatize_path("/sessions/aBcDeF0123456789xyzq") == "/sessions/{id}"


def test_templatize_short_slug_stays_literal():
    # 'orders' is not ID-shaped, mustn't be templated.
    assert templatize_path("/v1/orders") == "/v1/orders"


def test_templatize_root_path():
    assert templatize_path("/") == "/"
    assert templatize_path("") == "/"


# ---------- Grouping ----------

def test_group_by_endpoint_collapses_ids():
    flows = [_flow(path="/v1/users/1"), _flow(path="/v1/users/2")]
    groups = group_by_endpoint(flows)
    assert len(groups) == 1
    key = next(iter(groups))
    assert key == EndpointKey("api.example.com", "GET", "/v1/users/{id}")
    assert len(groups[key]) == 2


def test_group_by_endpoint_strips_query_string():
    flows = [_flow(path="/orders?limit=10"), _flow(path="/orders?limit=25")]
    groups = group_by_endpoint(flows)
    assert list(groups.keys()) == [EndpointKey("api.example.com", "GET", "/orders")]


def test_group_by_endpoint_ignores_hostless_flows():
    flows = [_flow(host=""), _flow(host="api.example.com")]
    groups = group_by_endpoint(flows)
    assert len(groups) == 1


def test_group_by_endpoint_separates_methods():
    flows = [_flow(method="GET"), _flow(method="POST", path="/v1/users/42")]
    groups = group_by_endpoint(flows)
    assert {k.method for k in groups} == {"GET", "POST"}


# ---------- Auth extraction ----------

def test_extract_auth_headers_only_credential_headers():
    flow = _flow(request_headers={
        "Authorization": "Bearer abc",
        "X-API-Key": "k",
        "User-Agent": "Sentinel/1.0",
        "Accept": "application/json",
    })
    auth = extract_auth_headers(flow)
    assert set(auth.keys()) == {"Authorization", "X-API-Key"}


def test_extract_auth_headers_preserves_case():
    """The replayed request must look byte-identical to the wire capture."""
    flow = _flow(request_headers={"AuThOrIzAtIoN": "Bearer weird"})
    auth = extract_auth_headers(flow)
    assert "AuThOrIzAtIoN" in auth


def test_extract_auth_headers_empty_when_absent():
    flow = _flow(request_headers={"User-Agent": "curl"})
    assert extract_auth_headers(flow) == {}


# ---------- Object ID extraction ----------

def test_extract_object_ids_from_path():
    ids = extract_object_ids(_flow(path="/v1/users/42"))
    assert any(o.location == "path" and o.value == "42" and o.is_numeric for o in ids)


def test_extract_object_ids_from_json_body():
    body = json.dumps({"user_id": 7, "name": "Ada", "nested": {"id": "abc-123"}})
    ids = extract_object_ids(_flow(
        method="POST", path="/v1/orders", request_body=body,
    ))
    body_ids = [o for o in ids if o.location == "body"]
    keys = {o.key for o in body_ids}
    assert "user_id" in keys and "id" in keys


def test_extract_object_ids_uuid_path_segment_is_non_numeric():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    ids = extract_object_ids(_flow(path=f"/orders/{uuid}"))
    match = [o for o in ids if o.location == "path"]
    assert match and match[0].value == uuid and not match[0].is_numeric


def test_extract_object_ids_ignores_non_id_body_keys():
    body = json.dumps({"amount": 100, "currency": "USD"})
    ids = extract_object_ids(_flow(method="POST", request_body=body))
    assert [o for o in ids if o.location == "body"] == []


def test_extract_object_ids_tolerates_malformed_body():
    # A non-JSON body must not raise.
    extract_object_ids(_flow(method="POST", request_body="{not-json"))


# ---------- replace_path_segment ----------

def test_replace_path_segment_swaps_indexed_segment():
    assert replace_path_segment("/v1/users/42", 3, "43") == "/v1/users/43"


def test_replace_path_segment_preserves_query_string():
    assert replace_path_segment("/v1/users/42?verbose=1", 3, "9") == "/v1/users/9?verbose=1"


def test_replace_path_segment_out_of_range_returns_original():
    assert replace_path_segment("/v1/users/42", 99, "9") == "/v1/users/42"


# ---------- load_flows ----------

def _write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records))


def test_load_flows_reads_valid_records(tmp_path):
    capture = tmp_path / "mitm_capture.jsonl"
    _write_jsonl(capture, [
        {"method": "GET", "url": "https://a.example.com/x", "scheme": "https",
         "host": "a.example.com", "path": "/x", "request_headers": {},
         "request_body": "", "response_status": 200, "response_headers": {},
         "response_body": "{}", "tls_failed": False, "timestamp": 1.0},
    ])
    flows = load_flows(capture)
    assert len(flows) == 1
    assert flows[0].host == "a.example.com"
    assert flows[0].method == "GET"


def test_load_flows_skips_malformed_and_error_lines(tmp_path):
    capture = tmp_path / "mitm_capture.jsonl"
    capture.write_text(
        "\n".join([
            '{"error": "addon exploded"}',           # skipped
            "not-json-at-all",                       # skipped
            json.dumps({                             # kept
                "method": "POST", "url": "https://x/y", "scheme": "https",
                "host": "x", "path": "/y",
                "request_headers": {}, "request_body": "",
                "response_status": 201, "response_headers": {},
                "response_body": "", "tls_failed": False, "timestamp": 0.0,
            }),
        ])
    )
    flows = load_flows(capture)
    assert len(flows) == 1 and flows[0].method == "POST"


def test_load_flows_accepts_directory_hint(tmp_path):
    (tmp_path / "mitm_capture.jsonl").write_text(json.dumps({
        "method": "GET", "url": "https://h/p", "scheme": "https",
        "host": "h", "path": "/p", "request_headers": {}, "request_body": "",
        "response_status": 200, "response_headers": {}, "response_body": "",
        "tls_failed": False, "timestamp": 0.0,
    }))
    assert load_flows(tmp_path)  # dir hint resolves to mitm_capture.jsonl


def test_load_flows_accepts_legacy_filename(tmp_path):
    """The design brief called the file mitmproxy_flows.jsonl — support both."""
    (tmp_path / "mitmproxy_flows.jsonl").write_text(json.dumps({
        "method": "GET", "url": "https://h/p", "scheme": "https",
        "host": "h", "path": "/p", "request_headers": {}, "request_body": "",
        "response_status": 200, "response_headers": {}, "response_body": "",
        "tls_failed": False, "timestamp": 0.0,
    }))
    assert len(load_flows(tmp_path)) == 1


def test_load_flows_returns_empty_when_missing(tmp_path):
    assert load_flows(tmp_path / "does-not-exist.jsonl") == []
