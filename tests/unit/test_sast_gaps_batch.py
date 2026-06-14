"""Smoke tests for the 7 SAST-gap agents + delta + semantic dedup."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sentinel.agents.crossplatform.fl002_method_channel import (
    FlutterMethodChannelAgent,
)
from sentinel.agents.crossplatform.rn002_bridge_taint import (
    ReactNativeBridgeTaintAgent,
)
from sentinel.agents.platform.ui001_activity_graph import ActivityGraphAgent
from sentinel.agents.reflection.refl001_reflection_resolver import (
    ReflectionResolverAgent,
)
from sentinel.agents.ui.gesture001_pattern_lock import PatternLockAgent
from sentinel.core.dedup import dedupe_all, semantic_dedupe
from sentinel.core.delta import compute_changed, hash_tree, should_skip
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


def _apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx(tmp_path: Path) -> tuple[ScanContext, Path]:
    apk = _apk(tmp_path / "t.apk")
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    return ctx, decompiled


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# DELTA (sentinel.core.delta)
# ============================================================

def test_delta_hash_tree(tmp_path):
    (tmp_path / "a.java").write_text("class A {}")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.java").write_text("class B {}")
    (tmp_path / "c.png").write_bytes(b"\x89PNG")  # filtered out by suffix
    h = hash_tree(tmp_path)
    assert set(h.keys()) == {"a.java", "sub/b.java"}
    assert all(len(v) == 64 for v in h.values())  # sha256 hex


def test_delta_compute_changed():
    baseline = {"a.java": "0" * 64, "b.java": "1" * 64}
    current = {"a.java": "0" * 64, "b.java": "9" * 64, "c.java": "2" * 64}
    changed = compute_changed(baseline, current)
    assert changed == {"b.java", "c.java"}


def test_delta_compute_changed_no_baseline_returns_all():
    current = {"a.java": "0", "b.java": "1"}
    assert compute_changed({}, current) == {"a.java", "b.java"}


def test_delta_should_skip_semantics():
    assert should_skip(None, "x.java") is False     # no delta mode
    assert should_skip(set(), "x.java") is True     # empty change set -> skip
    assert should_skip({"x.java"}, "x.java") is False
    assert should_skip({"y.java"}, "x.java") is True


# ============================================================
# SEMANTIC DEDUP
# ============================================================

def _finding(agent_id: str, vuln_class: str, sev: Severity = Severity.HIGH,
             evidence: dict[str, Any] | None = None) -> Finding:
    return Finding(
        agent_id=agent_id, vuln_class=vuln_class, severity=sev,
        confidence=0.9, recommendation="x",
        session_id="sess_dedup0001", evidence=evidence or {},
    )


def test_semantic_dedupe_merges_near_duplicates():
    a = _finding("SG_001", "Insecure WebView (Semgrep)",
                 evidence={"file": "WebView.java", "snippet": "setJavaScriptEnabled(true)"})
    b = _finding("W_001", "Insecure WebView",
                 sev=Severity.MEDIUM,
                 evidence={"file": "WebView.java", "snippet": "setJavaScriptEnabled(true)"})
    # Fake embedder that returns identical vectors for similar text
    def embed(texts):
        return [[1.0, 0.0] if "WebView" in t else [0.0, 1.0] for t in texts]
    out = semantic_dedupe([a, b], threshold=0.95, embed_fn=embed)
    assert len(out) == 1
    assert out[0].agent_id == "SG_001"  # higher severity wins
    assert "_semantic_merged" in (out[0].evidence or {})


def test_semantic_dedupe_keeps_different_categories():
    a = _finding("A_004", "Hardcoded Secret",
                 evidence={"file": "k.java", "snippet": "AKIA..."})
    b = _finding("C_006", "ECB Mode",
                 evidence={"file": "c.java", "snippet": "DES/ECB/NoPadding"})
    def embed(texts):
        return [[1.0, 0.0]] * len(texts)  # identical vectors
    out = semantic_dedupe([a, b], threshold=0.95, embed_fn=embed)
    # Different canonical categories — must NOT merge
    assert len(out) == 2


def test_dedupe_all_disabled_semantic_is_canonical_only():
    a = _finding("SG_001", "Insecure WebView (Semgrep)",
                 evidence={"file": "x.java"})
    b = _finding("W_001", "Insecure WebView",
                 evidence={"file": "x.java"})
    out = dedupe_all([a, b], semantic=False)
    # Canonical dedup merges these by file overlap
    assert len(out) == 1


def test_semantic_dedupe_no_embedder_returns_unchanged():
    a = _finding("A_004", "Hardcoded Secret", evidence={"file": "k.java"})
    b = _finding("A_004", "Hardcoded Secret", evidence={"file": "k.java"})
    # Force the import to fail by passing a bad embed_fn that raises
    def bad_embed(texts):
        raise RuntimeError("oops")
    out = semantic_dedupe([a, b], embed_fn=bad_embed)
    assert len(out) == 2  # unchanged on failure


# ============================================================
# UI_001 Activity Graph
# ============================================================

@pytest.mark.asyncio
async def test_ui001_finds_unguarded_path(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Main.java").write_text(
        "public class Main extends AppCompatActivity {\n"
        "  void go() { startActivity(new Intent(this, AdminActivity.class)); }\n"
        "}\n"
    )
    (root / "AdminActivity.java").write_text(
        "public class AdminActivity extends AppCompatActivity { }\n"
    )
    ctx.manifest = {
        "activities": [
            {"name": "com.x.Main", "exported": True,
             "intent_filters": [{"categories": ["android.intent.category.LAUNCHER"]}]},
            {"name": "com.x.AdminActivity", "exported": False},
        ],
    }
    findings = await ActivityGraphAgent(context=ctx, memory=memory).analyze()
    assert any(f.vuln_class == "Activity Auth-Bypass Path" for f in findings)


@pytest.mark.asyncio
async def test_ui001_skips_when_auth_in_path(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Main.java").write_text(
        "public class Main extends AppCompatActivity {\n"
        "  void go() { startActivity(new Intent(this, LoginActivity.class)); }\n"
        "}\n"
    )
    (root / "LoginActivity.java").write_text(
        "public class LoginActivity extends AppCompatActivity {\n"
        "  void go() { startActivity(new Intent(this, AdminActivity.class)); }\n"
        "}\n"
    )
    (root / "AdminActivity.java").write_text(
        "public class AdminActivity extends AppCompatActivity { }\n"
    )
    ctx.manifest = {
        "activities": [
            {"name": "com.x.Main", "exported": True,
             "intent_filters": [{"categories": ["android.intent.category.LAUNCHER"]}]},
            {"name": "com.x.LoginActivity", "exported": False},
            {"name": "com.x.AdminActivity", "exported": False},
        ],
    }
    findings = await ActivityGraphAgent(context=ctx, memory=memory).analyze()
    # Path is launcher -> Login -> Admin, and Login is auth-gated by name
    assert all(f.vuln_class != "Activity Auth-Bypass Path" for f in findings)


# ============================================================
# REFL_001 Reflection Resolver
# ============================================================

@pytest.mark.asyncio
async def test_refl001_resolves_inline_literal(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "R.java").write_text(
        'class R { void x() { Class.forName("com.app.Internal"); } }\n'
    )
    findings = await ReflectionResolverAgent(context=ctx, memory=memory).analyze()
    targets = [f.evidence.get("resolved_target") for f in findings]
    assert "com.app.Internal" in targets


@pytest.mark.asyncio
async def test_refl001_flags_unresolved_as_dynamic_target(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "R.java").write_text(
        "class R { void x(String input) { Class.forName(input); } }\n"
    )
    findings = await ReflectionResolverAgent(context=ctx, memory=memory).analyze()
    assert any(f.evidence.get("dynamic_target") is True for f in findings)


@pytest.mark.asyncio
async def test_refl001_resolves_concat_via_const_table(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "R.java").write_text(
        'class R {\n'
        '  void x() {\n'
        '    String pkg = "com.app";\n'
        '    String cls = pkg + ".Internal";\n'
        '    Class.forName(cls);\n'
        '  }\n'
        '}\n'
    )
    findings = await ReflectionResolverAgent(context=ctx, memory=memory).analyze()
    resolved = [f.evidence.get("resolved_target") for f in findings]
    assert "com.app.Internal" in resolved


@pytest.mark.asyncio
async def test_refl001_escalates_dangerous_target(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "R.java").write_text(
        'class R { void x() { Class.forName("java.lang.Runtime"); } }\n'
    )
    findings = await ReflectionResolverAgent(context=ctx, memory=memory).analyze()
    assert any(f.severity == Severity.HIGH for f in findings)


# ============================================================
# RN_002
# ============================================================

@pytest.mark.asyncio
async def test_rn002_flags_eval_in_bundle(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    resources = tmp_path / "resources"
    (resources / "assets").mkdir(parents=True)
    (resources / "assets" / "index.android.bundle").write_text(
        'function attack(x) { eval(x); }\n'
    )
    ctx.resources_dir = resources
    findings = await ReactNativeBridgeTaintAgent(context=ctx, memory=memory).analyze()
    assert any("Eval-Family Primitive" in f.vuln_class for f in findings)


@pytest.mark.asyncio
async def test_rn002_flags_dangerous_native_module_method(tmp_path, memory):
    ctx, _ = _ctx(tmp_path)
    resources = tmp_path / "resources"
    (resources / "assets").mkdir(parents=True)
    (resources / "assets" / "index.android.bundle").write_text(
        'NativeModules.FileSystem.writeFile("/sdcard/x", data);\n'
    )
    ctx.resources_dir = resources
    findings = await ReactNativeBridgeTaintAgent(context=ctx, memory=memory).analyze()
    assert any("Dangerous RN Bridge" in f.vuln_class for f in findings)


# ============================================================
# FL_002
# ============================================================

@pytest.mark.asyncio
async def test_fl002_enumerates_channels(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Plugin.java").write_text(
        'class Plugin {\n'
        '  void register() {\n'
        '    new MethodChannel(messenger, "com.x.app/feature").setMethodCallHandler(this);\n'
        '  }\n'
        '  void onMethodCall(MethodCall call) {\n'
        '    if (call.method.equals("ping")) reply();\n'
        '  }\n'
        '}\n'
    )
    resources = tmp_path / "resources"
    (resources / "assets" / "flutter_assets").mkdir(parents=True)
    ctx.resources_dir = resources
    findings = await FlutterMethodChannelAgent(context=ctx, memory=memory).analyze()
    classes = {f.vuln_class for f in findings}
    assert "Flutter MethodChannel Inventory" in classes


@pytest.mark.asyncio
async def test_fl002_flags_handler_without_method_validation(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Plugin.java").write_text(
        'class Plugin {\n'
        '  void register() {\n'
        '    new MethodChannel(messenger, "com.x.app/feature").setMethodCallHandler(h);\n'
        '  }\n'
        '  void handle() { dangerous(); }\n'
        '}\n'
    )
    resources = tmp_path / "resources"
    (resources / "assets" / "flutter_assets").mkdir(parents=True)
    ctx.resources_dir = resources
    findings = await FlutterMethodChannelAgent(context=ctx, memory=memory).analyze()
    classes = {f.vuln_class for f in findings}
    assert "Flutter Channel Handler Without Method Check" in classes


# ============================================================
# GESTURE_001
# ============================================================

@pytest.mark.asyncio
async def test_gesture001_flags_plaintext_storage(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "PatternView.java").write_text(
        "public class PatternView implements View.OnTouchListener {\n"
        "  int[] cellPattern = new int[9];\n"
        "  public boolean onTouch(View v, MotionEvent e) { return true; }\n"
        "  void save(String pat) { prefs.edit().putString(\"unlockPattern\", pat); }\n"
        "}\n"
    )
    findings = await PatternLockAgent(context=ctx, memory=memory).analyze()
    assert any(f.vuln_class == "Pattern Lock Stored In Plaintext" for f in findings)


@pytest.mark.asyncio
async def test_gesture001_flags_weak_hash(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "PatternView.java").write_text(
        "public class PatternView implements View.OnTouchListener {\n"
        "  int[] dotPattern = new int[9];\n"
        "  public boolean onTouch(View v, MotionEvent e) { return true; }\n"
        "  void hash() { MessageDigest.getInstance(\"MD5\"); }\n"
        # attempt-limit token present so the third rule doesn't false-pos
        "  int attempts = 0;\n"
        "}\n"
    )
    findings = await PatternLockAgent(context=ctx, memory=memory).analyze()
    assert any("MD5" in f.vuln_class for f in findings)


# ============================================================
# Rule-based remediation
# ============================================================

def test_rule_based_weak_crypto_swap():
    from sentinel.remediation import patch
    f = Finding(
        agent_id="C_001", vuln_class="Weak Crypto - DES",
        severity=Severity.HIGH, confidence=0.9, recommendation="x",
        session_id="sess_rem00001",
        evidence={"file": "Crypto.java", "snippet": "Cipher.getInstance(\"DES\")"},
    )
    res = patch(f)
    assert res is not None
    assert res.rule_id == "REM_WEAK_CRYPTO"
    assert "AES" in res.diff_body


def test_rule_based_https_upgrade():
    from sentinel.remediation import patch
    f = Finding(
        agent_id="N_001", vuln_class="Cleartext Traffic",
        severity=Severity.MEDIUM, confidence=0.9, recommendation="x",
        session_id="sess_rem00002",
        evidence={"file": "Api.java", "snippet": "String url = \"http://api.example.com/v1\";"},
    )
    res = patch(f)
    assert res is not None
    assert res.rule_id == "REM_HTTPS_UPGRADE"
    assert "https://api.example.com" in res.diff_body


def test_rule_based_returns_none_on_no_match():
    from sentinel.remediation import patch
    f = Finding(
        agent_id="X_999", vuln_class="Some Unknown Vuln",
        severity=Severity.LOW, confidence=0.5, recommendation="x",
        session_id="sess_rem00003",
        evidence={},
    )
    assert patch(f) is None
