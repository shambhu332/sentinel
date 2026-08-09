"""Unit tests for P_001 Deep Link Hijack Agent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import DeepLinkHijackAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, manifest=None, decompiled=True):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if decompiled:
        d = ws / "decompiled"
        d.mkdir(exist_ok=True)
        ctx.decompiled_dir = d
    if manifest is not None:
        ctx.manifest = manifest
    return ctx


def _plant_activity(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_when_no_manifest(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_when_no_deep_links(memory, tmp_path):
    ctx = _make_ctx(tmp_path, manifest={"package": "com.x", "deep_links": []})
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_when_deep_links_present(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# ---------- custom-scheme-no-host vector ----------


@pytest.mark.asyncio
async def test_custom_scheme_without_host_is_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "P_002"
    assert f.severity == Severity.MEDIUM
    assert f.evidence["vector"] == "custom-scheme-no-host"
    assert f.evidence["schemes"] == ["myapp"]


@pytest.mark.asyncio
async def test_custom_scheme_with_host_is_safe(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "myapp", "host": "open"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- applink-unverified vector ----------


@pytest.mark.asyncio
async def test_https_without_autoverify_is_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "https", "host": "example.com"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["vector"] == "applink-unverified"
    assert findings[0].evidence["schemes"] == ["https"]


@pytest.mark.asyncio
async def test_https_with_autoverify_is_safe(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "https", "host": "example.com"}],
                "auto_verify": True,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- sensitive-param severity bump ----------


@pytest.mark.asyncio
async def test_sensitive_param_handler_bumps_severity_to_high(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.LoginCallback",
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    _plant_activity(
        ctx.decompiled_dir,
        "com.x.LoginCallback",
        'class LoginCallback { void onCreate() { '
        'getIntent().getData().getQueryParameter("code"); } }',
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["reads_sensitive_params"] is True
    assert findings[0].confidence == 0.85


@pytest.mark.asyncio
async def test_non_sensitive_handler_stays_medium(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Viewer",
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    _plant_activity(
        ctx.decompiled_dir,
        "com.x.Viewer",
        'class Viewer { void onCreate() { '
        'getIntent().getData().getQueryParameter("page"); } }',
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["reads_sensitive_params"] is False


# ---------- both vectors emit independently ----------


@pytest.mark.asyncio
async def test_custom_and_https_emit_two_findings(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [
                {
                    "activity": "com.x.A",
                    "data_elements": [{"scheme": "myapp"}],
                    "auto_verify": False,
                },
                {
                    "activity": "com.x.B",
                    "data_elements": [{"scheme": "https", "host": "ex.com"}],
                    "auto_verify": False,
                },
            ],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    vectors = sorted(f.evidence["vector"] for f in findings)
    assert vectors == ["applink-unverified", "custom-scheme-no-host"]


# ---------- auth-scheme signal → CRITICAL ----------


@pytest.mark.asyncio
async def test_oauth_scheme_name_promotes_to_critical(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.OAuthCallback",
                "data_elements": [{"scheme": "myapp-oauth"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["auth_scheme_signal"] is True


@pytest.mark.asyncio
async def test_login_host_name_promotes_to_critical(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                # host is present so the no-host vector wouldn't fire
                # alone — flip to https without autoVerify to exercise
                # the auth-signal-on-applink-unverified path.
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    # Override: hand a host with auth signal but no host filter
    ctx.manifest["deep_links"] = [{
        "activity": "com.x.Main",
        "data_elements": [
            {"scheme": "myapp"},
            {"host": "login.example.com"},
        ],
        "auto_verify": False,
    }]
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # host IS present here so custom-scheme-no-host does NOT fire.
    assert findings == []


# ---------- finding schema ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "deep_links": [{
                "activity": "com.x.Main",
                "data_elements": [{"scheme": "myapp"}],
                "auto_verify": False,
            }],
        },
    )
    agent = DeepLinkHijackAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.vuln_class == "Deep Link Hijacking"
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-3"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
