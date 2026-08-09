"""Unit tests for STG_009 BackupRulesAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.shared_prefs import BackupRulesAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, with_resources=True):
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
    if with_resources:
        res = ws / "resources"
        (res / "res" / "xml").mkdir(parents=True, exist_ok=True)
        ctx.resources_dir = res
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant(ctx, name, content):
    f = ctx.resources_dir / "res" / "xml" / name
    f.write_text(content)


@pytest.mark.asyncio
async def test_not_applicable_without_resources(memory, tmp_path):
    ctx = _ctx(tmp_path, with_resources=False)
    agent = BackupRulesAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_credential_path_include_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "backup_rules.xml", """<?xml version="1.0"?>
<full-backup-content>
  <include domain="sharedpref" path="auth_tokens.xml" />
</full-backup-content>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "token" in f.evidence["reason"]


@pytest.mark.asyncio
async def test_wildcard_include_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "data_extraction_rules.xml", """<?xml version="1.0"?>
<data-extraction-rules>
  <cloud-backup>
    <include domain="sharedpref" path="" />
  </cloud-backup>
</data-extraction-rules>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_root_domain_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "backup_rules.xml", """<?xml version="1.0"?>
<full-backup-content>
  <include domain="root" path="." />
</full-backup-content>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["domain"] == "root"


@pytest.mark.asyncio
async def test_credential_exclude_suppresses_keyword(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "backup_rules.xml", """<?xml version="1.0"?>
<full-backup-content>
  <include domain="sharedpref" path="settings.xml" />
  <exclude domain="sharedpref" path="auth_tokens.xml" />
</full-backup-content>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    # No include matches a credential keyword; no wildcard; no root.
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_sharedpref_without_excludes_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "backup_rules.xml", """<?xml version="1.0"?>
<full-backup-content>
  <include domain="sharedpref" path="profile.xml" />
</full-backup-content>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_non_backup_xml_ignored(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "paths.xml", """<?xml version="1.0"?>
<paths>
  <files-path name="shared" path="shared/" />
</paths>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant(ctx, "backup_rules.xml", """<?xml version="1.0"?>
<full-backup-content>
  <include domain="sharedpref" path="auth.xml" />
</full-backup-content>
""")
    agent = BackupRulesAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M9: Insecure Data Storage"
    assert f.masvs == "MSTG-STORAGE-8"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
