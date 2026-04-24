"""API smoke tests — confirm every endpoint returns correct shape."""
from fastapi.testclient import TestClient

from sentinel.api.app import create_app


def _client() -> TestClient:
    return TestClient(create_app())


# ---------- Meta endpoints ----------

def test_root():
    r = _client().get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "SENTINEL"
    assert "disclaimer" in body


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

def test_create_scan_returns_session_id():
    r = _client().post("/scans", json={"apk_path": "/tmp/fake.apk"})
    assert r.status_code == 202
    body = r.json()
    assert "session_id" in body
    assert body["status"] == "queued"


def test_list_scans_contains_created():
    c = _client()
    create = c.post("/scans", json={"apk_path": "/tmp/a.apk"})
    sid = create.json()["session_id"]
    list_resp = c.get("/scans")
    assert list_resp.status_code == 200
    ids = [s["session_id"] for s in list_resp.json()]
    assert sid in ids


def test_get_scan_by_id():
    c = _client()
    sid = c.post("/scans", json={"apk_path": "/tmp/b.apk"}).json()["session_id"]
    r = c.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert r.json()["session_id"] == sid


def test_get_scan_not_found():
    r = _client().get("/scans/nonexistent123")
    assert r.status_code == 404


def test_cancel_scan():
    c = _client()
    sid = c.post("/scans", json={"apk_path": "/tmp/c.apk"}).json()["session_id"]
    cancel = c.delete(f"/scans/{sid}")
    assert cancel.status_code == 204


def test_create_scan_rejects_missing_apk_path():
    r = _client().post("/scans", json={})
    assert r.status_code == 422  # Pydantic validation error


# ---------- Scope endpoints ----------

def test_scope_parse_text():
    r = _client().post("/scope/parse", json={
        "mode": "text",
        "value": "In scope: com.example.app. Out of scope: com.example.test",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["source_mode"] == "text"
    assert "com.example.app" in body["scope"]["in_scope_packages"]


def test_scope_parse_invalid_mode():
    r = _client().post("/scope/parse", json={"mode": "invalid", "value": "x"})
    assert r.status_code == 422


def test_scope_parse_empty_value():
    r = _client().post("/scope/parse", json={"mode": "text", "value": ""})
    assert r.status_code == 422
