"""Unit tests for P_011 ReceiverChainHijackAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import ReceiverChainHijackAgent
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


def _plant_class(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


def _receiver_entry(name: str, permission: str = "") -> dict:
    return {
        "type": "receiver",
        "name": name,
        "explicitly_exported": True,
        "has_intent_filter": True,
        "permission": permission,
    }


# Body templates ------------------------------------------------------


_CHAIN_NEW_INTENT = """
package com.x;
import android.content.*;
import android.net.Uri;
public class Forwarder extends BroadcastReceiver {
  public void onReceive(Context ctx, Intent intent) {
    String action = intent.getStringExtra("next_action");
    Intent forward = new Intent(action);
    ctx.sendBroadcast(forward);
  }
}
"""

_CHAIN_SET_DATA = """
package com.x;
import android.content.*;
import android.net.Uri;
public class Linker extends BroadcastReceiver {
  public void onReceive(Context ctx, Intent intent) {
    String uri = intent.getStringExtra("redirect");
    Intent forward = new Intent("android.intent.action.VIEW");
    forward.setData(Uri.parse(uri));
    ctx.startActivity(forward);
  }
}
"""

_CHAIN_BUNDLE_SOURCE = """
package com.x;
import android.content.*;
public class BundleForwarder extends BroadcastReceiver {
  public void onReceive(Context ctx, Intent intent) {
    String pkg = intent.getExtras().getString("target_pkg");
    Intent forward = new Intent("com.x.WAKE");
    forward.setPackage(pkg);
    ctx.startService(forward);
  }
}
"""

_BENIGN_NO_DISPATCH = """
package com.x;
import android.content.*;
public class Reader extends BroadcastReceiver {
  public void onReceive(Context ctx, Intent intent) {
    String tag = intent.getStringExtra("tag");
    android.util.Log.d("R", tag);
  }
}
"""

_BENIGN_HARDCODED_TARGET = """
package com.x;
import android.content.*;
public class Pinger extends BroadcastReceiver {
  public void onReceive(Context ctx, Intent intent) {
    Intent forward = new Intent("com.x.HEARTBEAT");
    forward.setPackage("com.x");
    ctx.sendBroadcast(forward);
  }
}
"""


# is_applicable -------------------------------------------------------


@pytest.mark.asyncio
async def test_not_applicable_without_manifest(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Forwarder")],
        },
        decompiled=False,
    )
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_not_applicable_without_exported_receivers(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [
                {"type": "activity", "name": "com.x.Main",
                 "explicitly_exported": True, "has_intent_filter": True,
                 "permission": ""},
            ],
        },
    )
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_when_exported_receiver_present(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Forwarder")],
        },
    )
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is True


# Detection -----------------------------------------------------------


@pytest.mark.asyncio
async def test_new_intent_from_extra_string_is_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Forwarder")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Forwarder", _CHAIN_NEW_INTENT)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "P_011"
    assert f.severity == Severity.HIGH
    # Only the new-Intent(<extra>) pattern is present here (no setter
    # call), so the single-pattern confidence (0.65) is expected.
    assert f.confidence == 0.65
    assert "new Intent(<extra>)" in f.evidence["pattern"]


@pytest.mark.asyncio
async def test_setdata_chain_is_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Linker")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Linker", _CHAIN_SET_DATA)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "setAction" in findings[0].evidence["pattern"] or "setData" in findings[0].evidence["pattern"]


@pytest.mark.asyncio
async def test_bundle_source_is_flagged(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.BundleForwarder")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.BundleForwarder", _CHAIN_BUNDLE_SOURCE)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_extra_read_without_dispatch_is_safe(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Reader")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Reader", _BENIGN_NO_DISPATCH)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_hardcoded_target_intent_is_safe(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Pinger")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Pinger", _BENIGN_HARDCODED_TARGET)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# Permission-gated demotion -------------------------------------------


@pytest.mark.asyncio
async def test_permission_guarded_receiver_demoted_to_medium(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [
                _receiver_entry("com.x.Forwarder", permission="com.x.SECURE"),
            ],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Forwarder", _CHAIN_NEW_INTENT)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == 0.55
    assert findings[0].evidence["permission"] == "com.x.SECURE"


# Multiple receivers --------------------------------------------------


@pytest.mark.asyncio
async def test_only_chain_receivers_in_multi_emit(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [
                _receiver_entry("com.x.Forwarder"),
                _receiver_entry("com.x.Reader"),
                _receiver_entry("com.x.Pinger"),
            ],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Forwarder", _CHAIN_NEW_INTENT)
    _plant_class(ctx.decompiled_dir, "com.x.Reader", _BENIGN_NO_DISPATCH)
    _plant_class(ctx.decompiled_dir, "com.x.Pinger", _BENIGN_HARDCODED_TARGET)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["receiver"] == "com.x.Forwarder"


# Finding-schema compliance ------------------------------------------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(
        tmp_path,
        manifest={
            "package": "com.x",
            "exported_components": [_receiver_entry("com.x.Forwarder")],
        },
    )
    _plant_class(ctx.decompiled_dir, "com.x.Forwarder", _CHAIN_NEW_INTENT)
    agent = ReceiverChainHijackAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.vuln_class == "Receiver Chain Hijack"
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
    assert f.evidence["snippet"]
