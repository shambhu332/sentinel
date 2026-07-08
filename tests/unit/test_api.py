"""API smoke tests — confirm every endpoint returns correct shape."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import create_app
from sentinel.api.scan_runner import ScanJob


def _client() -> TestClient:
    return TestClient(create_app())


def _authed_client() -> TestClient:
    """Build a TestClient that bypasses JWT auth on /scans endpoints.

    Real auth is verified in tests/unit/test_auth.py — the scan-endpoint
    tests below only care about the request/response *shape* of the
    scan API, so we override get_current_active_user with a stub that
    returns a fake user. This mirrors the standard FastAPI testing
    pattern via app.dependency_overrides.
    """
    from sentinel.auth.jwt_auth import get_current_active_user

    app = create_app()

    async def _stub_user() -> dict:
        return {"id": "test-user", "email": "test@example.com",
                "username": "tester", "is_active": True}

    app.dependency_overrides[get_current_active_user] = _stub_user
    return TestClient(app)


# ---------- Scan-endpoint helpers ----------

# A minimal byte payload that looks enough like an APK (ZIP magic) for the
# upload pipeline to accept it. The actual orchestrator never runs because
# launch_scan is stubbed in the scans_api fixture below.
_FAKE_APK_BYTES = b"PK\x03\x04SENTINEL_TEST_FIXTURE\x00\x00"


def _post_apk(client: TestClient, name: str = "test.apk"):
    """POST a tiny fake APK to /scans and return the Response."""
    return client.post(
        "/scans",
        files={
            "apk": (
                name, _FAKE_APK_BYTES, "application/vnd.android.package-archive",
            ),
        },
    )


@pytest.fixture
def scans_api(monkeypatch, tmp_path):
    """Wire the /scans endpoints to a no-op launch_scan + fresh registry.

    The real launch_scan kicks off the full orchestrator in a background
    task. For API-shape tests we only care that POST registers a job and
    returns a session_id, GET surfaces it, DELETE removes it. The stub
    creates a ScanJob, registers it, and skips the orchestrator task.
    """
    # Fresh registry per test so test_list_scans only sees what this test
    # created.
    from sentinel.api import scan_runner
    monkeypatch.setattr(scan_runner, "_registry", None)

    async def _stub_launch(apk_path: Path, apk_filename: str, options):
        from sentinel.core.scan_context import generate_session_id
        job = ScanJob(
            session_id=generate_session_id(),
            apk_path=apk_path,
            apk_filename=apk_filename,
            options=options,
        )
        await scan_runner.get_registry().add(job)
        # No background task — keeps tests fast and deterministic.
        return job

    monkeypatch.setattr(
        "sentinel.api.routes.scans.launch_scan", _stub_launch,
    )
    yield _authed_client()


# ---------- Meta endpoints ----------

def test_root():
    r = _client().get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "SENTINEL"
    assert "legal" in body


def test_health():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_status():
    r = _client().get("/status")
    assert r.status_code == 200
    body = r.json()
    assert "cerebras_configured" in body
    assert "workspace" in body


def test_openapi_available():
    r = _client().get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "SENTINEL API"


def test_request_id_header():
    r = _client().get("/health")
    assert "X-Request-ID" in r.headers


# ---------- Agents endpoints ----------

def test_list_agents():
    r = _client().get("/agents")
    assert r.status_code == 200
    agents = r.json()
    assert len(agents) > 30
    assert any(a["id"] == "F_001" for a in agents)


def test_list_agents_filter():
    r = _client().get("/agents", params={"category": "Firebase"})
    assert r.status_code == 200
    agents = r.json()
    assert all(a["category"] == "Firebase" for a in agents)
    assert any(a["id"] == "F_001" for a in agents)


def test_get_agent_by_id():
    r = _client().get("/agents/F_001")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "F_001"
    assert body["name"] == "Firebase Misconfiguration"


def test_get_agent_not_found():
    r = _client().get("/agents/ZZZ_999")
    assert r.status_code == 404


# ---------- Scans endpoints ----------

def test_create_scan_returns_session_id(scans_api):
    r = _post_apk(scans_api, "fake.apk")
    assert r.status_code == 202
    body = r.json()
    assert "session_id" in body
    assert body["status"] == "queued"
    assert body["apk_filename"] == "fake.apk"
    assert body["apk_size_bytes"] == len(_FAKE_APK_BYTES)


def test_scans_require_auth(monkeypatch):
    from sentinel.core import config as cfg
    monkeypatch.setenv("SENTINEL_DEV_AUTH_BYPASS", "0")
    cfg.reset_settings()
    try:
        r = _client().get("/scans")
        assert r.status_code == 401
    finally:
        cfg.reset_settings()


def test_list_scans_contains_created(scans_api):
    sid = _post_apk(scans_api, "a.apk").json()["session_id"]
    list_resp = scans_api.get("/scans")
    assert list_resp.status_code == 200
    ids = [s["session_id"] for s in list_resp.json()]
    assert sid in ids


def test_get_scan_by_id(scans_api):
    sid = _post_apk(scans_api, "b.apk").json()["session_id"]
    r = scans_api.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert r.json()["session_id"] == sid


def test_get_scan_not_found():
    # Auth required first; we want the 404 for the actual missing record.
    r = _authed_client().get("/scans/nonexistent123")
    assert r.status_code == 404


def test_cancel_scan(scans_api):
    sid = _post_apk(scans_api, "c.apk").json()["session_id"]
    cancel = scans_api.delete(f"/scans/{sid}")
    assert cancel.status_code == 204


def test_create_scan_rejects_missing_apk_path():
    # The /scans endpoint now expects a multipart `apk` file field, so
    # an empty body triggers FastAPI's 422 validation error. Auth dep
    # is satisfied via the override client so the 422 surfaces.
    r = _authed_client().post("/scans", json={})
    assert r.status_code == 422


def test_create_scan_rejects_unsupported_extension(scans_api):
    r = scans_api.post(
        "/scans",
        files={"apk": ("payload.zip", _FAKE_APK_BYTES, "application/zip")},
    )
    assert r.status_code == 400
    assert "unsupported extension" in r.json()["detail"]


# ---------- Scope endpoints ----------

def test_scope_parse_text():
    r = _authed_client().post("/scope/parse", json={
        "mode": "text",
        "value": "In scope: com.example.app. Out of scope: com.example.test",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["source_mode"] == "text"
    assert "com.example.app" in body["scope"]["in_scope_packages"]


def test_scope_parse_invalid_mode():
    r = _authed_client().post("/scope/parse", json={"mode": "invalid", "value": "x"})
    assert r.status_code == 422


def test_scope_parse_empty_value():
    r = _authed_client().post("/scope/parse", json={"mode": "text", "value": ""})
    assert r.status_code == 422


def test_scope_parse_requires_auth(monkeypatch):
    from sentinel.core import config as cfg
    monkeypatch.setenv("SENTINEL_DEV_AUTH_BYPASS", "0")
    cfg.reset_settings()
    try:
        r = _client().post("/scope/parse", json={"mode": "text", "value": "In scope: com.x"})
        assert r.status_code == 401
    finally:
        cfg.reset_settings()


# ---------- Reports endpoints ----------

def test_reports_require_auth(monkeypatch):
    from sentinel.core import config as cfg
    monkeypatch.setenv("SENTINEL_DEV_AUTH_BYPASS", "0")
    cfg.reset_settings()
    try:
        r = _client().get("/reports")
        assert r.status_code == 401
    finally:
        cfg.reset_settings()


def test_api_sast_roster_uses_full_static_catalog():
    from sentinel.api.scan_runner import SAST_AGENTS

    agent_ids = [agent.AGENT_ID for agent in SAST_AGENTS]
    assert len(agent_ids) >= 60
    assert len(agent_ids) == len(set(agent_ids))
    for required in ("META_002", "A_013", "B_007", "C_016", "N_014", "P_012", "SCA_001", "TAINT_001", "SG_001"):
        assert required in agent_ids
