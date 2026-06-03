"""Unit tests for P_010 — Intent Redirect Agent (CWE-926)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sentinel.agents.platform import IntentRedirectAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

# ---------- Fixtures ----------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def context_with_decompiled(tmp_path):
    """ScanContext with an empty decompiled directory ready for fixture planting."""
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.manifest = {"package": "com.x", "exported_components": []}
    return ctx


def _plant(decompiled_dir: Path, fqcn: str, body: str) -> Path:
    """Drop a Java file at the canonical decompiled path for ``fqcn``."""
    parts = fqcn.split(".")
    java_file = decompiled_dir.joinpath(*parts).with_suffix(".java")
    java_file.parent.mkdir(parents=True, exist_ok=True)
    java_file.write_text(body)
    return java_file


# ---------- is_applicable ----------

@pytest.mark.asyncio
async def test_not_applicable_without_decompiled_dir(memory, tmp_path):
    """Skips when JADX did not produce a decompiled tree."""
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"x")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path,
        scope=BountyScope(),
    )
    agent = IntentRedirectAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_applicable_with_decompiled_dir(memory, context_with_decompiled):
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    assert await agent.is_applicable() is True


# ---------- analyze: positive cases ----------

@pytest.mark.asyncio
async def test_direct_extra_to_start_activity_is_high(memory, context_with_decompiled):
    """getParcelableExtra → startActivity with no sanitiser → HIGH."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.RedirectActivity",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class RedirectActivity extends Activity {
    public void onCreate(android.os.Bundle b) {
        Intent inner = (Intent) getIntent().getParcelableExtra("forward");
        startActivity(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "P_010"
    assert f.severity == Severity.HIGH
    assert f.confidence == pytest.approx(0.85)
    assert f.evidence["sink_method"] == "startActivity"
    assert f.evidence["variable"] == "inner"
    assert f.evidence["cwe"] == "CWE-926"
    assert f.evidence["taint_chain"] == "Intent extra"


@pytest.mark.asyncio
async def test_bundle_chain_is_medium(memory, context_with_decompiled):
    """getBundleExtra(...).getParcelable(...) → dispatch → MEDIUM."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.BundleRedirect",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class BundleRedirect extends Activity {
    public void onResume() {
        Intent inner = (Intent) getIntent().getBundleExtra("b").getParcelable("p");
        sendBroadcast(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == pytest.approx(0.70)
    assert "via Bundle" in f.evidence["taint_chain"]
    assert f.evidence["sink_method"] == "sendBroadcast"


@pytest.mark.asyncio
async def test_multiple_sinks_in_one_method(memory, context_with_decompiled):
    """A single tainted variable hitting two distinct sinks → two findings."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.DoubleSink",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class DoubleSink extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        startActivity(inner);
        startService(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    sinks = sorted(f.evidence["sink_method"] for f in findings)
    assert sinks == ["startActivity", "startService"]


@pytest.mark.asyncio
async def test_plain_assignment_source_also_taints(memory, context_with_decompiled):
    """Source via assignment (not declaration) is still detected."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.AssignSink",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class AssignSink extends Activity {
    Intent inner;
    public void go() {
        inner = (Intent) getIntent().getParcelableExtra("k");
        startActivity(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["sink_method"] == "startActivity"


# ---------- analyze: sanitisation must suppress ----------

@pytest.mark.asyncio
@pytest.mark.parametrize("sanitiser_call", [
    'inner.setComponent(new android.content.ComponentName("com.x", "com.x.Safe"));',
    'inner.setPackage("com.x");',
    'inner.setClassName("com.x", "com.x.Safe");',
    'inner.setClass(this, com.x.Safe.class);',
])
async def test_sanitised_dispatch_is_suppressed(
    memory, context_with_decompiled, sanitiser_call,
):
    """Any component-pinning call between source and sink suppresses the finding."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.Sanitised",
        f"""
package com.x;
import android.app.Activity;
import android.content.Intent;
public class Sanitised extends Activity {{
    public void go() {{
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        {sanitiser_call}
        startActivity(inner);
    }}
}}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- analyze: negative cases (no taint introduced) ----------

@pytest.mark.asyncio
async def test_no_finding_when_intent_is_locally_constructed(
    memory, context_with_decompiled,
):
    """A locally constructed Intent is not attacker-controlled — no finding."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.LocalIntent",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class LocalIntent extends Activity {
    public void go() {
        Intent i = new Intent("ACTION_FOO");
        startActivity(i);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_extra_used_for_non_dispatch(
    memory, context_with_decompiled,
):
    """Reading an extra and logging it is not a redirect — no finding."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.JustReads",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class JustReads extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        android.util.Log.i("tag", inner.toString());
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_dispatched_var_is_unrelated(
    memory, context_with_decompiled,
):
    """A dispatch whose argument is a different variable does not fire."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.WrongVar",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class WrongVar extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        Intent safe = new Intent(this, com.x.Safe.class);
        startActivity(safe);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- analyze: scope edges ----------

@pytest.mark.asyncio
async def test_dedupes_same_sink_line(memory, context_with_decompiled):
    """Same (file, sink_line, sink_method) appearing via multiple taint flows is reported once."""
    # Two declarations both alias `inner` but only one dispatch line exists.
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.AliasDup",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class AliasDup extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("a");
        inner = (Intent) getIntent().getParcelableExtra("b");
        startActivity(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_finds_across_multiple_files(memory, context_with_decompiled):
    """Each vulnerable class contributes its own finding."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.A",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class A extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        startActivity(inner);
    }
}
""",
    )
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.B",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class B extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        sendBroadcast(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    sinks = sorted(f.evidence["sink_method"] for f in findings)
    assert sinks == ["sendBroadcast", "startActivity"]


@pytest.mark.asyncio
async def test_reassignment_clears_taint(memory, context_with_decompiled):
    """Reassigning the variable from a non-extras source clears its taint."""
    _plant(
        context_with_decompiled.decompiled_dir,
        "com.x.Reassigned",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class Reassigned extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        inner = new Intent(this, com.x.Safe.class);
        startActivity(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- analyze: sources subdir layout ----------

@pytest.mark.asyncio
async def test_walks_sources_subdir(memory, context_with_decompiled):
    """When ``sources/`` exists under decompiled_dir, agent searches it."""
    sources = context_with_decompiled.decompiled_dir / "sources"
    sources.mkdir()
    _plant(
        sources,
        "com.x.Inside",
        """
package com.x;
import android.app.Activity;
import android.content.Intent;
public class Inside extends Activity {
    public void go() {
        Intent inner = (Intent) getIntent().getParcelableExtra("k");
        startActivity(inner);
    }
}
""",
    )
    agent = IntentRedirectAgent(context=context_with_decompiled, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["file"].startswith("com/x/")
