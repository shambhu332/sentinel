"""Integration tests for PostgresMemory (Phase 1.1).

Spins up a real Postgres container via testcontainers, applies the
migrations in migrations/*.sql, and exercises the T1 code paths that
depend on RLS, BRIN indexes, and the partition machinery.

Skipped when Docker isn't reachable — CI runs these; local dev without
Docker still gets green pytest.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"


def _docker_available() -> bool:
    if os.getenv("SENTINEL_SKIP_POSTGRES_TESTS") == "1":
        return False
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytestmark = [pytestmark, pytest.mark.skipif(
    not _docker_available(),
    reason="Docker unavailable — Postgres integration test skipped.",
)]


@pytest.fixture(scope="module")
def postgres_url() -> str:
    from testcontainers.postgres import PostgresContainer

    container = PostgresContainer("postgres:16-alpine")
    container.start()
    try:
        dsn = container.get_connection_url().replace(
            "postgresql+psycopg2://", "postgresql://",
        )
        yield dsn
    finally:
        container.stop()


@pytest.fixture(scope="module")
async def migrated(postgres_url: str) -> str:
    import asyncpg

    conn = await asyncpg.connect(dsn=postgres_url)
    try:
        for sql_path in sorted(MIGRATIONS_DIR.glob("[0-9]*.sql")):
            await conn.execute(sql_path.read_text())
    finally:
        await conn.close()
    return postgres_url


@pytest.fixture
async def memory(migrated: str):
    from sentinel.memory.postgres import PostgresMemory

    tenant_id = str(uuid.uuid4())
    m = PostgresMemory(dsn=migrated, tenant_id=tenant_id)
    await m.connect()
    try:
        yield m
    finally:
        await m.close()


class TestConnectivity:
    async def test_ping(self, memory):
        h = await memory.health_check()
        assert h["tier1"] is True

    async def test_safe_dsn_redacts_password(self):
        from sentinel.memory.postgres import PostgresMemory

        m = PostgresMemory(dsn="postgresql://u:secret@h:5432/db")
        assert "secret" not in m._safe_dsn()
        assert "***" in m._safe_dsn()


class TestEvents:
    async def test_publish_and_poll_roundtrip(self, memory):
        sid = f"sess_test_{uuid.uuid4().hex[:8]}"
        await memory.publish_event(sid, "phase.started", {"phase": "recon"})
        await memory.publish_event(sid, "agent.completed", {"agent": "A_001"})
        events = await memory.poll_events(sid)
        assert len(events) == 2
        assert events[0]["event_type"] == "phase.started"
        assert events[0]["payload"] == {"phase": "recon"}
        assert events[1]["event_type"] == "agent.completed"

    async def test_poll_filter_by_event_type(self, memory):
        sid = f"sess_test_{uuid.uuid4().hex[:8]}"
        await memory.publish_event(sid, "phase.started", {})
        await memory.publish_event(sid, "phase.completed", {})
        only = await memory.poll_events(sid, event_type="phase.completed")
        assert len(only) == 1
        assert only[0]["event_type"] == "phase.completed"


class TestFindings:
    async def _mk(self, sid: str, sev):
        from sentinel.core.finding import Finding

        return Finding(
            agent_id="A_001",
            session_id=sid,
            vuln_class="hardcoded_credentials",
            severity=sev,
            confidence=0.9,
            recommendation="Rotate credential; use Android Keystore.",
        )

    async def test_save_and_get_finding(self, memory):
        from sentinel.core.finding import Severity
        sid = f"sess_test_{uuid.uuid4().hex[:8]}"
        finding = await self._mk(sid, Severity.HIGH)
        await memory.save_finding(finding)
        got = await memory.get_finding(sid, finding.finding_id)
        assert got is not None
        assert got.finding_id == finding.finding_id
        assert got.severity == finding.severity

    async def test_min_severity_filter(self, memory):
        from sentinel.core.finding import Severity
        sid = f"sess_test_{uuid.uuid4().hex[:8]}"
        low = await self._mk(sid, Severity.LOW)
        crit = await self._mk(sid, Severity.CRITICAL)
        await memory.save_finding(low)
        await memory.save_finding(crit)
        filtered = await memory.get_findings(sid, min_severity="High")
        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL


class TestAuditLog:
    async def test_write_audit_row(self, memory):
        await memory.write_audit(
            action="POST /scans",
            method="POST",
            path="/scans",
            status_code=201,
            ip="127.0.0.1",
            user_agent="pytest",
            request_id="req-abc",
            duration_ms=42,
        )
        async with memory._pool.acquire() as conn:
            n = await conn.fetchval(
                "SELECT count(*) FROM audit_log WHERE request_id = 'req-abc'"
            )
        assert n == 1

    async def test_update_is_blocked_by_rule(self, memory):
        """PG rule silently redirects UPDATE to no-op; verify row unchanged."""
        await memory.write_audit(action="GET /health", status_code=200,
                                 request_id="immutable-test")
        async with memory._pool.acquire() as conn:
            await conn.execute(
                "UPDATE audit_log SET status_code = 500 "
                "WHERE request_id = 'immutable-test'"
            )
            status = await conn.fetchval(
                "SELECT status_code FROM audit_log "
                "WHERE request_id = 'immutable-test'"
            )
        assert status == 200  # rule blocked the mutation
