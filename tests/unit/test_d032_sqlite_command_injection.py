"""Unit tests for D_032 SqliteCommandInjectionAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import SqliteCommandInjectionAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events), duration_seconds=10.0,
        target_package="com.example.app", target_pid=12345,
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


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = SqliteCommandInjectionAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_value_keyword_with_literal_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="execSQL",
            sql="UPDATE users SET name='alice' WHERE id=42",
            args_count=0,
            caller_class="com.example.app.db.UserDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Unparameterised" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_comment_terminator_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="rawQuery",
            sql="SELECT * FROM users WHERE id=1; DROP TABLE users; --",
            args_count=0,
            caller_class="com.example.app.db.UserDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Comment" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_long_unparameterised_is_medium(ctx, memory):
    long_sql = (
        "SELECT user_id, user_name, user_email, last_login, "
        "preferences, account_state, two_factor_secret, "
        "recovery_email, locale_code, time_zone, created_at, "
        "updated_at, deleted_at FROM users JOIN sessions "
        "ON users.id = sessions.user_id JOIN audit_log "
        "ON sessions.id = audit_log.session_id WHERE flag=1"
    )
    assert len(long_sql) > 200
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="rawQuery",
            sql=long_sql,
            args_count=0,
            caller_class="com.example.app.db.AuditDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_parameterised_query_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="rawQuery",
            sql="SELECT * FROM users WHERE id=? AND name=?",
            args_count=2,
            caller_class="com.example.app.db.UserDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_short_constant_query_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="execSQL",
            sql="DELETE FROM cache",
            args_count=0,
            caller_class="com.example.app.db.CacheDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_semicolon_inside_string_literal_ignored(ctx, memory):
    """; / -- inside a quoted literal must not trip the comment rule."""
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="execSQL",
            sql="INSERT INTO notes (body) VALUES ('hello; world -- end')",
            args_count=0,
            caller_class="com.example.app.db.NotesDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    # Triggers the value-keyword + literal rule (VALUES + '…'), not
    # the comment rule. One finding, HIGH severity.
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_args_present_suppresses_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sqlite.query_executed",
            api="execSQL",
            sql="UPDATE users SET name=? WHERE id=?",
            args_count=2,
            caller_class="com.example.app.db.UserDao"),
    )
    findings = await SqliteCommandInjectionAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
