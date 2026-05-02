"""Unit tests for Sprint 6.7 agents: C_001, C_006, A_001, N_001, P_001."""
from __future__ import annotations

import pytest

from sentinel.agents.auth_storage import InsecureAuthStorageAgent
from sentinel.agents.backup import InsecureBackupAgent
from sentinel.agents.cert_pinning import MissingCertPinningAgent
from sentinel.agents.deep_links import DeepLinkHijackAgent
from sentinel.agents.shared_prefs import InsecureSharedPrefsAgent
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
    ctx.manifest = {
        "package": "com.x.test",
        "exported_components": [],
        "deep_links": [],
    }
    return ctx


# ---------- C_001 Insecure Backup ----------

@pytest.mark.asyncio
async def test_c001_no_finding_when_backup_disabled(memory, basic_context):
    basic_context.manifest["allow_backup"] = False
    agent = InsecureBackupAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_c001_medium_when_backup_enabled(memory, basic_context):
    basic_context.manifest["allow_backup"] = True
    basic_context.manifest["debuggable"] = False
    agent = InsecureBackupAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_c001_high_when_backup_and_debuggable(memory, basic_context):
    basic_context.manifest["allow_backup"] = True
    basic_context.manifest["debuggable"] = True
    agent = InsecureBackupAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_c001_low_when_full_backup_content_set(memory, basic_context):
    basic_context.manifest["allow_backup"] = True
    basic_context.manifest["debuggable"] = False
    basic_context.manifest["full_backup_content"] = "@xml/backup_rules"
    agent = InsecureBackupAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


# ---------- C_006 Insecure SharedPreferences ----------

@pytest.mark.asyncio
async def test_c006_no_finding_on_clean_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Settings.java"
    java.write_text(
        'SharedPreferences prefs = context.getSharedPreferences("settings", 0);\n'
        'prefs.edit().putString("theme", "dark").apply();\n'
    )

    agent = InsecureSharedPrefsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_c006_detects_password_in_prefs(memory, basic_context):
    java = basic_context.decompiled_dir / "Auth.java"
    java.write_text(
        'SharedPreferences prefs = context.getSharedPreferences("auth", 0);\n'
        'prefs.edit().putString("password", userPassword).apply();\n'
    )

    agent = InsecureSharedPrefsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Passwords" in findings[0].evidence["category"]


@pytest.mark.asyncio
async def test_c006_detects_auth_token(memory, basic_context):
    java = basic_context.decompiled_dir / "Token.java"
    java.write_text(
        'prefs.edit().putString("auth_token", token).commit();\n'
    )

    agent = InsecureSharedPrefsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_c006_skips_encrypted_shared_prefs(memory, basic_context):
    java = basic_context.decompiled_dir / "Secure.java"
    java.write_text(
        'EncryptedSharedPreferences prefs = EncryptedSharedPreferences.create(...);\n'
        'prefs.edit().putString("password", token).apply();\n'
    )

    agent = InsecureSharedPrefsAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- A_001 Insecure Auth Storage ----------

@pytest.mark.asyncio
async def test_a001_no_finding_on_unrelated_code(memory, basic_context):
    java = basic_context.decompiled_dir / "Theme.java"
    java.write_text(
        'SharedPreferences prefs = context.getSharedPreferences("ui", 0);\n'
        'prefs.edit().putString("color", "blue").apply();\n'
    )

    agent = InsecureAuthStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_a001_detects_token_to_external_storage(memory, basic_context):
    java = basic_context.decompiled_dir / "BadStorage.java"
    java.write_text(
        'String authToken = response.getAuthToken();\n'
        'File f = new File(Environment.getExternalStorageDirectory(), "tok.txt");\n'
        'FileOutputStream fos = new FileOutputStream(f);\n'
        'fos.write(authToken.getBytes());\n'
    )

    agent = InsecureAuthStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) >= 1
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1


@pytest.mark.asyncio
async def test_a001_detects_token_in_plain_prefs(memory, basic_context):
    java = basic_context.decompiled_dir / "TokenStore.java"
    java.write_text(
        'String authToken = api.login();\n'
        'SharedPreferences prefs = context.getSharedPreferences("auth", 0);\n'
        'prefs.edit().putString("auth_token", authToken).apply();\n'
    )

    agent = InsecureAuthStorageAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) >= 1


# ---------- N_001 Missing Cert Pinning ----------

@pytest.mark.asyncio
async def test_n001_no_finding_when_no_https(memory, basic_context):
    java = basic_context.decompiled_dir / "OfflineApp.java"
    java.write_text(
        'public class OfflineApp { void doWork() { /* local logic */ } }\n'
    )

    agent = MissingCertPinningAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_n001_detects_https_without_pinning(memory, basic_context):
    java = basic_context.decompiled_dir / "Api.java"
    java.write_text(
        'OkHttpClient client = new OkHttpClient.Builder()\n'
        '    .connectTimeout(30, TimeUnit.SECONDS)\n'
        '    .build();\n'
        'String url = "https://api.example.com/v1/data";\n'
    )

    agent = MissingCertPinningAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_n001_no_finding_when_pinning_present(memory, basic_context):
    java = basic_context.decompiled_dir / "PinnedApi.java"
    java.write_text(
        'CertificatePinner pinner = new CertificatePinner.Builder()\n'
        '    .add("api.example.com", "sha256/AAAAA...")\n'
        '    .build();\n'
        'OkHttpClient client = new OkHttpClient.Builder()\n'
        '    .certificatePinner(pinner)\n'
        '    .build();\n'
    )

    agent = MissingCertPinningAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_n001_detects_xml_pin_set(memory, basic_context):
    # HTTPS in code, but pin-set in NetworkSecurityConfig XML
    java = basic_context.decompiled_dir / "Api.java"
    java.write_text(
        'OkHttpClient client = new OkHttpClient.Builder().build();\n'
        'String url = "https://api.example.com";\n'
    )
    xml_dir = basic_context.resources_dir / "res" / "xml"
    xml_dir.mkdir(parents=True)
    xml = xml_dir / "network_security_config.xml"
    xml.write_text(
        '<network-security-config>\n'
        '  <domain-config>\n'
        '    <domain>api.example.com</domain>\n'
        '    <pin-set><pin digest="SHA-256">AAAA</pin></pin-set>\n'
        '  </domain-config>\n'
        '</network-security-config>\n'
    )

    agent = MissingCertPinningAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert findings == []


# ---------- P_001 Deep Link Hijacking ----------

@pytest.mark.asyncio
async def test_p001_no_finding_when_no_deep_links(memory, basic_context):
    basic_context.manifest["deep_links"] = []
    agent = DeepLinkHijackAgent(context=basic_context, memory=memory)
    # Note: is_applicable should return False here; analyze isn't called by
    # production code, but we test the empty path.
    applicable = await agent.is_applicable()
    assert applicable is False


@pytest.mark.asyncio
async def test_p001_detects_custom_oauth_scheme_critical(memory, basic_context):
    basic_context.manifest["deep_links"] = [
        {
            "scheme": "myapp",
            "host": "oauth-callback",
            "auto_verify": False,
            "activity": "com.x.test.OAuthActivity",
        },
    ]
    agent = DeepLinkHijackAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_p001_detects_plain_custom_scheme_high(memory, basic_context):
    basic_context.manifest["deep_links"] = [
        {
            "scheme": "myapp",
            "host": "products",
            "auto_verify": False,
            "activity": "com.x.test.MainActivity",
        },
    ]
    agent = DeepLinkHijackAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_p001_detects_http_without_autoverify(memory, basic_context):
    basic_context.manifest["deep_links"] = [
        {
            "scheme": "https",
            "host": "app.example.com",
            "auto_verify": False,
            "activity": "com.x.test.MainActivity",
        },
    ]
    agent = DeepLinkHijackAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_p001_low_for_autoverify_https(memory, basic_context):
    basic_context.manifest["deep_links"] = [
        {
            "scheme": "https",
            "host": "app.example.com",
            "auto_verify": True,
            "activity": "com.x.test.MainActivity",
        },
    ]
    agent = DeepLinkHijackAgent(context=basic_context, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
