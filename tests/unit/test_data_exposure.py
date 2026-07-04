"""Unit tests for API_004 Excessive Data Exposure analyzer."""
from __future__ import annotations

import json

import pytest

from sentinel.agents.api_security import DataExposureAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _mk_context(tmp_path, flows=None, client_files=None):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    decompiled = ws / "decompiled"
    decompiled.mkdir(exist_ok=True)
    resources = ws / "resources"
    resources.mkdir(exist_ok=True)

    if client_files:
        for rel, content in client_files.items():
            path = decompiled / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.resources_dir = resources
    if flows is not None:
        ctx.sources["mitmproxy"] = MitmproxyCapture(
            flows=flows,
            capture_file=tmp_path / "mitm_capture.jsonl",
            duration_seconds=0.0,
            flow_count=len(flows),
        )
    return ctx


def _flow(response_json, **overrides) -> CapturedFlow:
    defaults = dict(
        method="GET",
        url="https://api.example.com/v1/users/42",
        scheme="https",
        host="api.example.com",
        path="/v1/users/42",
        request_headers={"Authorization": "Bearer x"},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body=json.dumps(response_json),
        tls_failed=False,
        timestamp=0.0,
    )
    defaults.update(overrides)
    return CapturedFlow(**defaults)


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_without_capture(memory, tmp_path):
    ctx = _mk_context(tmp_path)
    agent = DataExposureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_with_only_non_json_responses(memory, tmp_path):
    flow = _flow({}, response_body="<html>", response_headers={"Content-Type": "text/html"})
    ctx = _mk_context(tmp_path, flows=[flow])
    agent = DataExposureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_json_response(memory, tmp_path):
    ctx = _mk_context(tmp_path, flows=[_flow({"id": 1})])
    agent = DataExposureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- Positive detection ----------

@pytest.mark.asyncio
async def test_flags_ssn_absent_from_client(memory, tmp_path):
    """SSN in response body, no reference in decompiled sources → HIGH finding."""
    flows = [_flow({"id": 1, "email": "a@b.c", "ssn": "123-45-6789"})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "UserActivity.java": "TextView emailField = view.findViewById(R.id.email);",
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "API_004"
    assert f.severity == Severity.HIGH
    assert f.evidence["key_name"] == "ssn"
    assert f.evidence["sensitive_match"] == "ssn"
    assert f.evidence["endpoint"] == "/v1/users/42"
    assert "123" not in f.evidence["sample_value_masked"], "value must be masked"


@pytest.mark.asyncio
async def test_flags_credit_card_variants(memory, tmp_path):
    """`credit_card_last4` should trip on the `credit_card` substring rule."""
    flows = [_flow({"credit_card_last4": "1234", "name": "Alice"})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "UserActivity.java": "// nothing relevant",
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["key_name"] == "credit_card_last4"
    assert findings[0].evidence["sensitive_match"] == "credit_card"


@pytest.mark.asyncio
async def test_detects_nested_password_hash(memory, tmp_path):
    """Sensitive keys inside nested objects must still trip."""
    flows = [_flow({"user": {"id": 1, "auth": {"password_hash": "$argon2id$..."}}})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "Empty.java": "class Empty {}",
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["key_path"] == "$.user.auth.password_hash"


@pytest.mark.asyncio
async def test_detects_in_array_element(memory, tmp_path):
    flows = [_flow({"users": [{"id": 1, "internal_ip": "10.0.0.1"}]})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "Empty.java": "class Empty {}",
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert "internal_ip" in findings[0].evidence["key_path"]


# ---------- Negative: client references the field ----------

@pytest.mark.asyncio
async def test_no_finding_when_client_references_snake_case_key(memory, tmp_path):
    flows = [_flow({"id": 1, "ssn": "123-45-6789"})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "UserActivity.java":
            'String ssn = json.getString("ssn");\n'
            'binding.tvSsn.setText(ssn);',
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_client_uses_camel_case(memory, tmp_path):
    """API returns password_hash; Kotlin field is `passwordHash`."""
    flows = [_flow({"password_hash": "$argon2id$..."})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={
        "UserModel.kt": "data class UserModel(val passwordHash: String)",
    })
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- Non-sensitive keys are ignored ----------

@pytest.mark.asyncio
async def test_ignores_non_sensitive_keys(memory, tmp_path):
    """`email` and `name` aren't on the sensitive list; no findings."""
    flows = [_flow({"id": 1, "email": "a@b.c", "name": "Alice"})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={"Empty.java": ""})
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- De-duplication ----------

@pytest.mark.asyncio
async def test_deduplicates_across_flows(memory, tmp_path):
    """Same endpoint returning `ssn` on many responses = one finding."""
    flows = [_flow({"ssn": f"111-22-{i:04d}"}) for i in range(5)]
    ctx = _mk_context(tmp_path, flows=flows, client_files={"Empty.java": ""})
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1


# ---------- Config extension ----------

@pytest.mark.asyncio
async def test_extra_sensitive_keys_from_config(memory, tmp_path):
    flows = [_flow({"id": 1, "dob": "1990-01-01"})]
    ctx = _mk_context(tmp_path, flows=flows, client_files={"Empty.java": ""})
    agent = DataExposureAgent(
        context=ctx, memory=memory,
        config={"extra_sensitive_keys": ["dob"]},
    )
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["sensitive_match"] == "dob"


# ---------- Content-type sniffing ----------

@pytest.mark.asyncio
async def test_sniffs_json_body_without_content_type(memory, tmp_path):
    """Some captures lack Content-Type; body-shape sniff should still work."""
    flow = _flow({"ssn": "123"}, response_headers={})
    ctx = _mk_context(tmp_path, flows=[flow], client_files={"Empty.java": ""})
    agent = DataExposureAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
