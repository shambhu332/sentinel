"""Unit tests for P_016 task hijack + P_017 foreground-service drift."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from sentinel.agents.platform.p016_task_hijack import TaskHijackAgent
from sentinel.agents.platform.p017_foreground_service_drift import (
    ForegroundServiceDriftAgent,
)
from sentinel.core.finding import Severity


def _ctx(manifest: dict, permissions: list[str] | None = None):
    return SimpleNamespace(
        session_id="sess-platform-gap-1",
        workspace=Path("/tmp"),
        manifest=manifest,
        permissions=permissions or [],
    )


# --- P_016 -----------------------------------------------------------------

def test_p016_flags_foreign_task_affinity_on_exported_activity():
    manifest = {
        "package": "com.app.victim",
        "activities": [{
            "name": ".Login",
            "exported": True,
            "taskAffinity": "com.evil.attacker",
            "launchMode": "standard",
        }],
    }
    agent = TaskHijackAgent(_ctx(manifest), SimpleNamespace())
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "taskAffinity" in findings[0].evidence["issues"][0]


def test_p016_flags_singletask_exported_no_permission():
    manifest = {
        "package": "com.app",
        "activities": [{
            "name": ".Dashboard",
            "exported": True,
            "launchMode": "singleTask",
        }],
    }
    agent = TaskHijackAgent(_ctx(manifest), SimpleNamespace())
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_p016_ignores_safe_activity():
    manifest = {
        "package": "com.app",
        "activities": [{
            "name": ".Safe",
            "exported": False,
            "launchMode": "standard",
            "taskAffinity": "com.app",
        }],
    }
    agent = TaskHijackAgent(_ctx(manifest), SimpleNamespace())
    findings = asyncio.run(agent.analyze())
    assert findings == []


def test_p016_flags_allow_task_reparenting():
    manifest = {
        "package": "com.app",
        "activities": [{
            "name": ".A",
            "exported": False,
            "allowTaskReparenting": True,
            "launchMode": "standard",
        }],
    }
    agent = TaskHijackAgent(_ctx(manifest), SimpleNamespace())
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    assert "allowTaskReparenting" in findings[0].evidence["issues"][0]


# --- P_017 -----------------------------------------------------------------

def test_p017_flags_missing_foreground_service_type():
    manifest = {
        "package": "com.app",
        "services": [{"name": ".Worker", "exported": False}],
    }
    agent = ForegroundServiceDriftAgent(_ctx(manifest), SimpleNamespace())
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    assert "foregroundServiceType missing" in findings[0].evidence["issues"][0]
    assert findings[0].severity == Severity.MEDIUM


def test_p017_flags_privileged_type_without_permission():
    manifest = {
        "package": "com.app",
        "services": [{
            "name": ".LocationWorker",
            "exported": False,
            "foregroundServiceType": "location",
        }],
    }
    agent = ForegroundServiceDriftAgent(
        _ctx(manifest, permissions=["android.permission.ACCESS_FINE_LOCATION"]),
        SimpleNamespace(),
    )
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    issues = findings[0].evidence["issues"]
    assert any("FOREGROUND_SERVICE_LOCATION" in i for i in issues)


def test_p017_flags_privileged_type_exported():
    manifest = {
        "package": "com.app",
        "services": [{
            "name": ".CamSvc",
            "exported": True,
            "foregroundServiceType": "camera",
        }],
    }
    agent = ForegroundServiceDriftAgent(
        _ctx(manifest, permissions=[
            "android.permission.CAMERA",
            "android.permission.FOREGROUND_SERVICE_CAMERA",
        ]),
        SimpleNamespace(),
    )
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    issues = findings[0].evidence["issues"]
    assert any("exported service" in i for i in issues)


def test_p017_silent_on_compliant_service():
    manifest = {
        "package": "com.app",
        "services": [{
            "name": ".LocSvc",
            "exported": False,
            "foregroundServiceType": "location",
        }],
    }
    agent = ForegroundServiceDriftAgent(
        _ctx(manifest, permissions=[
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.FOREGROUND_SERVICE_LOCATION",
        ]),
        SimpleNamespace(),
    )
    findings = asyncio.run(agent.analyze())
    assert findings == []
