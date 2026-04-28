"""Unit tests for Sprint 6 agents: C_007, A_007, C_004, B_002, META_001."""
from __future__ import annotations

import pytest

from sentinel.agents.crypto import WeakCryptoAgent
from sentinel.agents.logging import InsecureLoggingAgent
from sentinel.agents.meta import ObfuscationDetectorAgent
from sentinel.agents.random_gen import InsecureRandomAgent
from sentinel.agents.webview import InsecureWebViewAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def basic_context(tmp_path):
    ws = tmp_path / "ws"
    decompiled = ws / "decompiled"
    decompiled.mkdir(parents=True)
    resources = ws / "resources"
    resources.mkdir(parents=True)

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.resources_dir = resources
    ctx.manifest = {"package": "com.x.test", "exported_components": []}
    return ctx


# ---------- C_007 Weak Crypto ----------

@pytest.mark.asyncio
async def test_c007_no_findings_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Clean.java"
    java.write_text(
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'
    )

    agent = WeakCryptoAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_c007_detects_des_critical(memory, basic_context):
    java = basic_context.decompiled_dir / "OldCrypto.java"
    java.write_text(
        'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");'
    )

    agent = WeakCryptoAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) >= 1
    des_findings = [f for f in findings if f.evidence["primitive"] == "DES"]
    assert len(des_findings) == 1
    assert des_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_c007_detects_md5(memory, basic_context):
    java = basic_context.decompiled_dir / "Hash.java"
    java.write_text(
        'MessageDigest md = MessageDigest.getInstance("MD5");'
    )

    agent = WeakCryptoAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["primitive"] == "MD5"
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_c007_detects_aes_ecb(memory, basic_context):
    java = basic_context.decompiled_dir / "Cipher.java"
    java.write_text(
        'Cipher c = Cipher.getInstance("AES/ECB/NoPadding");'
    )

    agent = WeakCryptoAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].evidence["primitive"] == "AES-ECB"


# ---------- A_007 Insecure Logging ----------

@pytest.mark.asyncio
async def test_a007_no_findings_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Clean.java"
    java.write_text(
        'Log.d("MyApp", "User logged in successfully");'
    )

    agent = InsecureLoggingAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_a007_detects_password_logging(memory, basic_context):
    java = basic_context.decompiled_dir / "Bad.java"
    java.write_text(
        'Log.d("Login", "user=" + username + " password=" + password);'
    )

    agent = InsecureLoggingAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "password" in findings[0].evidence["category"]


@pytest.mark.asyncio
async def test_a007_detects_token_logging(memory, basic_context):
    java = basic_context.decompiled_dir / "Auth.java"
    java.write_text(
        'Log.i("API", "Sending request with auth_token: " + authToken);'
    )

    agent = InsecureLoggingAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


# ---------- C_004 Insecure WebView ----------

@pytest.mark.asyncio
async def test_c004_no_findings_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Web.java"
    java.write_text("public class Web { void hello() { } }")

    agent = InsecureWebViewAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_c004_detects_js_interface_with_js_enabled(memory, basic_context):
    java = basic_context.decompiled_dir / "Wv.java"
    java.write_text(
        'webView.getSettings().setJavaScriptEnabled(true);\n'
        'webView.addJavascriptInterface(new JsBridge(), "android");\n'
    )

    agent = InsecureWebViewAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_c004_critical_when_file_access_too(memory, basic_context):
    java = basic_context.decompiled_dir / "Wv.java"
    java.write_text(
        'webView.getSettings().setJavaScriptEnabled(true);\n'
        'webView.getSettings().setAllowUniversalAccessFromFileURLs(true);\n'
        'webView.addJavascriptInterface(new JsBridge(), "android");\n'
    )

    agent = InsecureWebViewAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


# ---------- B_002 Insecure Random ----------

@pytest.mark.asyncio
async def test_b002_no_findings_on_secure_random(memory, basic_context):
    java = basic_context.decompiled_dir / "Secure.java"
    java.write_text(
        'SecureRandom rng = new SecureRandom();\n'
        'byte[] tok = new byte[32];\n'
        'rng.nextBytes(tok);\n'
    )

    agent = InsecureRandomAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_b002_detects_random_in_security_context(memory, basic_context):
    java = basic_context.decompiled_dir / "Tokens.java"
    java.write_text(
        'public String generateSessionToken() {\n'
        '    Random r = new Random();\n'
        '    return Long.toHexString(r.nextLong());\n'
        '}\n'
    )

    agent = InsecureRandomAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) >= 1
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 1


@pytest.mark.asyncio
async def test_b002_medium_when_no_security_context(memory, basic_context):
    java = basic_context.decompiled_dir / "Game.java"
    java.write_text(
        'int diceRoll = new Random().nextInt(6) + 1;\n'
    )

    agent = InsecureRandomAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


# ---------- META_001 Obfuscation Detector ----------

@pytest.mark.asyncio
async def test_meta001_classifies_unobfuscated(memory, basic_context):
    """Long, readable class names → tier 0."""
    for name in (
        "LoginActivity", "UserRepository", "ApiClient",
        "DatabaseHelper", "SettingsManager",
    ):
        f = basic_context.decompiled_dir / f"com/x/{name}.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"public class {name} {{ }}")

    agent = ObfuscationDetectorAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Tier 0" in findings[0].evidence["tier"]


@pytest.mark.asyncio
async def test_meta001_classifies_proguard(memory, basic_context):
    """Many short class names (a, b, c, ...) → tier 1."""
    for name in "abcdefghijklmnopqrstuvwxyz":
        for sub in "abc":
            f = basic_context.decompiled_dir / f"{name}/{sub}.java"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(f"class {sub} {{ }}")

    # Also add a few long names to make this realistic
    for name in ("MainActivity", "Application", "BuildConfig"):
        f = basic_context.decompiled_dir / f"com/x/{name}.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"public class {name} {{ }}")

    agent = ObfuscationDetectorAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    # Should be tier 1 since most class names are <= 3 chars
    assert "Tier 1" in findings[0].evidence["tier"]


@pytest.mark.asyncio
async def test_meta001_detects_dexguard(memory, basic_context):
    """Files in com/guardsquare/ path → DexGuard."""
    f = basic_context.decompiled_dir / "com/guardsquare/dexguard/Stub.java"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("class Stub {}")

    agent = ObfuscationDetectorAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert "Tier 2" in findings[0].evidence["tier"]
    assert "DexGuard" in findings[0].evidence["detected_obfuscators"]


@pytest.mark.asyncio
async def test_meta001_detects_promon_enterprise(memory, basic_context):
    """Files in com/promon/ → tier 3 enterprise."""
    f = basic_context.decompiled_dir / "com/promon/shield/Antitamper.java"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("class Antitamper {}")

    agent = ObfuscationDetectorAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert "Tier 3" in findings[0].evidence["tier"]
