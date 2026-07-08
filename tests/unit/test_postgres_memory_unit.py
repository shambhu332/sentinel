"""Unit tests for PostgresMemory that don't need a live server."""
from __future__ import annotations

import pytest

from sentinel.memory.interface import MemoryError
from sentinel.memory.postgres import PostgresMemory


def test_import():
    m = PostgresMemory(dsn="postgresql://u:p@h/db")
    assert m is not None


def test_safe_dsn_redacts_password():
    m = PostgresMemory(dsn="postgresql://u:supersecret@h:5432/db")
    dsn = m._safe_dsn()
    assert "supersecret" not in dsn
    assert "u:***" in dsn


def test_safe_dsn_no_userinfo():
    m = PostgresMemory(dsn="postgresql://localhost/db")
    assert m._safe_dsn() == "postgresql://localhost/db"


@pytest.mark.asyncio
async def test_operations_before_connect_raise():
    m = PostgresMemory(dsn="postgresql://u:p@h/db")
    with pytest.raises(MemoryError, match="not connected"):
        await m.publish_event("s", "e", {})
    with pytest.raises(MemoryError, match="not connected"):
        await m.write_audit(action="GET /")


@pytest.mark.asyncio
async def test_health_check_disconnected_is_all_false():
    m = PostgresMemory(dsn="postgresql://u:p@h/db")
    h = await m.health_check()
    assert h == {"tier1": False, "tier2": False, "tier3": False}


def test_fingerprint_stable_for_same_finding():
    from sentinel.core.finding import Finding, Severity

    f = Finding(
        agent_id="A_001",
        session_id="sess_test_00000001",
        vuln_class="hardcoded_credentials",
        severity=Severity.HIGH,
        confidence=0.9,
        recommendation="Rotate the credential and store in Keystore.",
    )
    assert PostgresMemory._fingerprint(f) == PostgresMemory._fingerprint(f)
    assert "A_001" in PostgresMemory._fingerprint(f)
