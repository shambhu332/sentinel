"""Tests for sentinel.tools.api_parser.APITrafficMap wrapper."""
from __future__ import annotations

import json

from sentinel.tools.api_parser import (
    APITrafficMap,
    EndpointKey,
    build_traffic_map,
    group_by_endpoint,
)
from sentinel.tools.mitmproxy_runner import CapturedFlow


def _flow(**overrides) -> CapturedFlow:
    defaults = dict(
        method="GET",
        url="https://api.example.com/v1/users/42",
        scheme="https",
        host="api.example.com",
        path="/v1/users/42",
        request_headers={"Authorization": "Bearer x"},
        request_body="",
        response_status=200,
        response_headers={},
        response_body="{}",
        tls_failed=False,
        timestamp=0.0,
    )
    defaults.update(overrides)
    return CapturedFlow(**defaults)


def test_build_returns_wrapper():
    m = build_traffic_map([_flow()])
    assert isinstance(m, APITrafficMap)
    assert len(m) == 1


def test_endpoints_alias_group_by_endpoint():
    flows = [_flow(path="/users/1"), _flow(path="/users/2")]
    m = build_traffic_map(flows)
    key = EndpointKey("api.example.com", "GET", "/users/{id}")
    assert key in m.endpoints
    assert m.endpoints[key] == group_by_endpoint(flows)[key]


def test_auth_headers_extracted_per_endpoint_preserving_case():
    m = build_traffic_map([_flow(request_headers={"AuThOrIzAtIoN": "Bearer weird"})])
    key = next(iter(m.endpoints))
    assert m.auth_headers[key] == {"AuThOrIzAtIoN": "Bearer weird"}


def test_sample_payloads_decode_json_body():
    body = json.dumps({"email": "a@b.c"})
    m = build_traffic_map([_flow(method="POST", request_body=body)])
    key = next(iter(m.endpoints))
    assert m.sample_payloads[key] == {"email": "a@b.c"}


def test_sample_payloads_none_for_empty_body():
    m = build_traffic_map([_flow(request_body="")])
    key = next(iter(m.endpoints))
    assert m.sample_payloads[key] is None


def test_sample_payloads_string_for_non_json_body():
    m = build_traffic_map([_flow(method="POST", request_body="email=a@b.c")])
    key = next(iter(m.endpoints))
    assert m.sample_payloads[key] == "email=a@b.c"


def test_flows_for_method_filters():
    flows = [
        _flow(method="GET", path="/users/1"),
        _flow(method="POST", path="/users", request_body='{"a":1}'),
    ]
    m = build_traffic_map(flows)
    gets = m.flows_for_method("get")
    posts = m.flows_for_method("POST")
    assert len(gets) == 1 and gets[0].method == "GET"
    assert len(posts) == 1 and posts[0].method == "POST"


def test_map_iteration_yields_key_group_pairs():
    m = build_traffic_map([_flow()])
    for key, group in m:
        assert isinstance(key, EndpointKey)
        assert group
