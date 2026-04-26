"""Unit tests for F_001 Firebase Misconfiguration Agent."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sentinel.agents.cloud import FirebaseMisconfigAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    """Throwaway in-memory memory bus for each test."""
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def basic_context(tmp_path):
    """ScanContext with empty workspace and decompiled directory."""
    ws = tmp_path / "ws"
    ws.mkdir()
    decompiled = ws / "decompiled"
    decompiled.mkdir()
    resources = ws / "resources"
    resources.mkdir()

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk-bytes")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.resources_dir = resources
    return ctx


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_when_no_decompiled_dir(memory, tmp_path):
    """Agent skips when JADX hasn't run."""
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    # decompiled_dir is None
    agent = FirebaseMisconfigAgent(context=ctx, memory=memory)
    assert agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_decompiled_dir(memory, basic_context):
    agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
    assert agent.is_applicable() is True


# ---------- candidate extraction ----------

@pytest.mark.asyncio
async def test_no_findings_when_no_firebase_urls(memory, basic_context):
    """Agent emits zero findings on a Firebase-free APK."""
    java_file = basic_context.decompiled_dir / "MainActivity.java"
    java_file.write_text("public class MainActivity { /* no firebase */ }")

    agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_extracts_firebaseio_url_from_java(memory, basic_context):
    """Agent finds a Firebase URL embedded in decompiled Java."""
    java_file = basic_context.decompiled_dir / "ApiClient.java"
    java_file.write_text(
        'private static final String DB_URL = "https://my-test-project.firebaseio.com";'
    )

    # Mock the probe to return a "secured" response so we don't try real HTTP
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "Permission denied"}'
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    # 401 means properly secured — no findings emitted
    assert findings == []


@pytest.mark.asyncio
async def test_emits_critical_for_publicly_readable_db(memory, basic_context):
    """Public Firebase database produces a Critical finding."""
    java_file = basic_context.decompiled_dir / "FirebaseHelper.java"
    java_file.write_text(
        'String url = "https://leaky-app-prod.firebaseio.com";'
    )

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({
            "users": {
                "u1": {"email": "alice@example.com", "balance": 1000},
                "u2": {"email": "bob@example.com", "balance": 500},
            }
        })
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.agent_id == "F_001"
    assert "leaky-app-prod" in f.evidence["project_id"]
    assert f.evidence["http_status"] == 200
    assert f.evidence["url"].endswith("firebaseio.com")
    assert "alice@example.com" in f.evidence["data_sample"]


@pytest.mark.asyncio
async def test_skips_empty_database(memory, basic_context):
    """A database that returns 'null' is empty, not vulnerable."""
    java_file = basic_context.decompiled_dir / "EmptyDB.java"
    java_file.write_text('"https://empty-db.firebaseio.com"')

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "null"
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    assert findings == []


@pytest.mark.asyncio
async def test_skips_permission_denied_response(memory, basic_context):
    """A 200 response with 'Permission denied' content is properly secured."""
    java_file = basic_context.decompiled_dir / "Protected.java"
    java_file.write_text('"https://protected-db.firebaseio.com"')

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"error": "Permission denied"}'
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    assert findings == []


@pytest.mark.asyncio
async def test_handles_network_error_gracefully(memory, basic_context):
    """If the probe fails (DNS error, timeout), the agent doesn't crash."""
    java_file = basic_context.decompiled_dir / "Broken.java"
    java_file.write_text('"https://nonexistent-12345.firebaseio.com"')

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("DNS failed"))
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    # Network errors mean we couldn't confirm — emit no finding
    assert findings == []


@pytest.mark.asyncio
async def test_extracts_from_google_services_json(memory, basic_context):
    """google-services.json is the gold-standard source of project IDs."""
    gs_path = basic_context.resources_dir / "google-services.json"
    gs_path.write_text(json.dumps({
        "project_info": {
            "project_id": "my-cool-app-prod",
            "firebase_url": "https://my-cool-app-prod.firebaseio.com",
        }
    }))

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({"data": "exposed"})
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
        findings = await agent.analyze()

    assert len(findings) == 1
    assert findings[0].evidence["project_id"] == "my-cool-app-prod"


@pytest.mark.asyncio
async def test_skips_well_known_non_target_project_ids(memory, basic_context):
    """We don't probe Google's own example/test Firebase projects."""
    java_file = basic_context.decompiled_dir / "Sample.java"
    java_file.write_text(
        '"https://firebase.firebaseio.com" + "https://google.firebaseio.com"'
    )

    agent = FirebaseMisconfigAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []
