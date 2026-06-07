"""Unit tests for D_010 JwtWeaknessAgent."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.agents.dynamic import JwtWeaknessAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture


def _b64u(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("ascii")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict, payload: dict, signature: str = "abcdefg") -> str:
    return f"{_b64u(header)}.{_b64u(payload)}.{signature}"


def _flow(
    method: str = "GET",
    path: str = "/api/v1/me",
    *,
    host: str = "api.example.com",
    auth: str | None = None,
    url_jwt: str | None = None,
) -> CapturedFlow:
    headers: dict[str, str] = {}
    url = f"https://{host}{path}"
    if auth is not None:
        headers["Authorization"] = auth
    if url_jwt is not None:
        url += f"?token={url_jwt}"
    return CapturedFlow(
        method=method, url=url, scheme="https",
        host=host, path=path,
        request_headers=headers,
        response_status=200,
        response_body="{}",
    )


def _capture(*flows: CapturedFlow) -> MitmproxyCapture:
    return MitmproxyCapture(
        flows=list(flows), capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=10.0, flow_count=len(flows),
    )


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path, scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


# ---------- basic plumbing ----------


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = JwtWeaknessAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_auth_headers_no_findings(ctx, memory):
    ctx.sources["mitmproxy"] = _capture(_flow())
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_well_formed_jwt_no_findings(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"},
        {"sub": "u1", "iat": iat, "exp": iat + 600,
         "aud": "api.example.com", "iss": "https://auth.example.com"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- alg=none ----------


@pytest.mark.asyncio
async def test_alg_none_is_critical(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "u1", "iat": iat, "exp": iat + 600,
         "aud": "api.example.com", "iss": "https://auth"},
        signature="",
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    none_finding = next(
        (f for f in findings if f.evidence.get("weakness") == "alg_none"),
        None,
    )
    assert none_finding is not None
    assert none_finding.severity == Severity.CRITICAL


# ---------- HS* candidate ----------


@pytest.mark.asyncio
async def test_hs256_flagged_as_weak_key_candidate(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "u1", "iat": iat, "exp": iat + 600,
         "aud": "api.example.com", "iss": "https://auth"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    hs = next(
        (f for f in findings
         if f.evidence.get("weakness") == "alg_hs_weak_key_candidate"),
        None,
    )
    assert hs is not None
    assert hs.severity == Severity.HIGH


# ---------- missing exp ----------


@pytest.mark.asyncio
async def test_missing_exp_is_high(ctx, memory):
    jwt = _make_jwt(
        {"alg": "RS256"},
        {"sub": "u1", "aud": "x", "iss": "y"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    miss = next(
        (f for f in findings if f.evidence.get("weakness") == "missing_exp"),
        None,
    )
    assert miss is not None
    assert miss.severity == Severity.HIGH


# ---------- long exp ----------


@pytest.mark.asyncio
async def test_long_exp_is_medium(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "RS256"},
        {"sub": "u1", "iat": iat, "exp": iat + 365 * 86400,
         "aud": "x", "iss": "y"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    long_f = next(
        (f for f in findings if f.evidence.get("weakness") == "long_exp"),
        None,
    )
    assert long_f is not None
    assert long_f.severity == Severity.MEDIUM


# ---------- missing aud/iss ----------


@pytest.mark.asyncio
async def test_missing_aud_iss_is_medium(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "RS256"},
        {"sub": "u1", "iat": iat, "exp": iat + 600},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    miss = next(
        (f for f in findings
         if f.evidence.get("weakness") == "missing_aud_iss"),
        None,
    )
    assert miss is not None
    assert miss.severity == Severity.MEDIUM


# ---------- suspect kid ----------


@pytest.mark.asyncio
async def test_suspect_kid_is_high(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "RS256", "kid": "../../../etc/passwd"},
        {"sub": "u1", "iat": iat, "exp": iat + 600,
         "aud": "x", "iss": "y"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(auth=f"Bearer {jwt}"))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    sk = next(
        (f for f in findings if f.evidence.get("weakness") == "suspect_kid"),
        None,
    )
    assert sk is not None
    assert sk.severity == Severity.HIGH


# ---------- token in URL ----------


@pytest.mark.asyncio
async def test_token_in_url_is_high(ctx, memory):
    iat = int(datetime.now(timezone.utc).timestamp())
    jwt = _make_jwt(
        {"alg": "RS256"},
        {"sub": "u1", "iat": iat, "exp": iat + 600,
         "aud": "x", "iss": "y"},
    )
    ctx.sources["mitmproxy"] = _capture(_flow(url_jwt=jwt))
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    tu = next(
        (f for f in findings if f.evidence.get("weakness") == "token_in_url"),
        None,
    )
    assert tu is not None
    assert tu.severity == Severity.HIGH


# ---------- one finding per category even with many tokens ----------


@pytest.mark.asyncio
async def test_categories_collapse_across_tokens(ctx, memory):
    # Two different tokens, both missing exp — should produce one finding.
    jwt1 = _make_jwt({"alg": "RS256"}, {"sub": "u1", "aud": "x", "iss": "y"})
    jwt2 = _make_jwt({"alg": "RS256"}, {"sub": "u2", "aud": "x", "iss": "y"})
    ctx.sources["mitmproxy"] = _capture(
        _flow(auth=f"Bearer {jwt1}"),
        _flow(auth=f"Bearer {jwt2}", path="/api/v1/users"),
    )
    findings = await JwtWeaknessAgent(
        context=ctx, memory=memory,
    ).analyze()
    miss = [f for f in findings if f.evidence.get("weakness") == "missing_exp"]
    assert len(miss) == 1
    assert len(miss[0].evidence["samples"]) == 2
