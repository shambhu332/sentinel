"""Unit tests for A_001 Hardcoded Credentials Agent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.auth.a_001_hardcoded_creds import (
    A001HardcodedCredsAgent,
    _Match,
    _PATTERNS,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.native_analyzer import shannon_entropy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
    ws.mkdir()
    decompiled = ws / "jadx" / "sources"
    decompiled.mkdir(parents=True)
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    c.decompiled_dir = decompiled
    return c


@pytest.fixture
def agent(ctx, memory):
    return A001HardcodedCredsAgent(context=ctx, memory=memory)


def _java_file(decompiled_dir: Path, name: str, content: str) -> Path:
    p = decompiled_dir / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Shannon entropy (utility, not agent-specific but A_001 depends on it)
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_all_same_chars(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0

    def test_high_entropy_key(self):
        assert shannon_entropy("sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC") > 4.0

    def test_mixed_alphanum(self):
        assert shannon_entropy("abcdefghijklmnopqrstuvwxyz") > 4.0


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

class TestFindSecrets:
    def test_detects_api_key(self, agent, ctx):
        code = 'String apiKey = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";'
        f = _java_file(ctx.decompiled_dir, "A.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "api_key" for m in matches)

    def test_detects_bearer_token(self, agent, ctx):
        code = 'String t = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";'
        f = _java_file(ctx.decompiled_dir, "B.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "bearer_token" for m in matches)

    def test_detects_aws_key(self, agent, ctx):
        code = 'final String KEY = "AKIAIOSFODNN7EXAMPLE";'
        f = _java_file(ctx.decompiled_dir, "C.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "aws_access_key" for m in matches)

    def test_detects_google_api_key(self, agent, ctx):
        code = 'String gKey = "AIzaSyDdI0hiBtDFcKQ6lzH8d7g7YnMkHj1234XY";'
        f = _java_file(ctx.decompiled_dir, "D.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "google_api_key" for m in matches)

    def test_detects_stripe_live_key(self, agent, ctx):
        code = 'String stripe = "sk_live_51HxZ9l2eZvKYlo2CREAL123456";'
        f = _java_file(ctx.decompiled_dir, "E.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "stripe_live_key" for m in matches)

    def test_detects_pem_private_key(self, agent, ctx):
        code = 'String key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK";'
        f = _java_file(ctx.decompiled_dir, "F.java", code)
        matches = agent._find_secrets(f, code)
        assert any(m.pattern_name == "private_key_pem" for m in matches)

    def test_entropy_filter_rejects_low_entropy(self, agent, ctx):
        # "aaaaaaaaaaaaaaaaaa" has zero entropy — must be dropped
        code = 'String apiKey = "aaaaaaaaaaaaaaaaaa";'
        f = _java_file(ctx.decompiled_dir, "G.java", code)
        matches = agent._find_secrets(f, code)
        real = [m for m in matches if not agent._is_fp(m)]
        assert real == []

    def test_line_number_is_correct(self, agent, ctx):
        code = "// header\n\nString apiKey = \"sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC\";\n"
        f = _java_file(ctx.decompiled_dir, "H.java", code)
        matches = agent._find_secrets(f, code)
        api_matches = [m for m in matches if m.pattern_name == "api_key"]
        assert api_matches
        assert api_matches[0].line_number == 3


# ---------------------------------------------------------------------------
# False-positive filtering
# ---------------------------------------------------------------------------

class TestFalsePositiveFilter:
    def test_placeholder_rejected(self, agent):
        m = _make_match("api_key", "YOUR_API_KEY_HERE", entropy=3.6)
        assert agent._is_fp(m) is True

    def test_example_placeholder_rejected(self, agent):
        m = _make_match("api_key", "EXAMPLE_KEY_12345678901234567890", entropy=3.6)
        assert agent._is_fp(m) is True

    def test_template_variable_rejected(self, agent):
        m = _make_match("api_key", "${API_KEY}", entropy=3.6)
        assert agent._is_fp(m) is True

    def test_low_entropy_password_rejected(self, agent):
        m = _make_match("password_assignment", "password123", entropy=1.5)
        assert agent._is_fp(m) is True

    def test_real_key_passes(self, agent):
        m = _make_match("api_key", "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC", entropy=4.5)
        assert agent._is_fp(m) is False

    def test_test_file_excluded(self, agent, ctx):
        test_path = ctx.decompiled_dir / "com" / "example" / "ApiClientTest.java"
        test_path.parent.mkdir(parents=True, exist_ok=True)
        from sentinel.agents.auth.a_001_hardcoded_creds import _TEST_PATH_RE
        assert _TEST_PATH_RE.search(str(test_path))


# ---------------------------------------------------------------------------
# Taint analysis
# ---------------------------------------------------------------------------

class TestTaintAnalysis:
    def test_reaches_network_sink(self, agent):
        content = (
            'String API_KEY = "sk_live_51HxZ9l2eZvKYlo2C";\n'
            'OkHttpClient client = new OkHttpClient();\n'
            'Request req = new Request.Builder().header("X-Key", API_KEY).build();\n'
        )
        m = _make_match("api_key", "sk_live_51HxZ9l2eZvKYlo2C", entropy=4.5, line=1)
        m = _make_match_with_text(m, 'API_KEY = "sk_live_51HxZ9l2eZvKYlo2C"')
        reaches, sink = agent._taint_check(content, m)
        assert reaches is True
        assert sink == "network_send"

    def test_no_sink_returns_false(self, agent):
        content = 'String API_KEY = "sk_live_51HxZ9l2eZvKYlo2C"; // unused\n'
        m = _make_match("api_key", "sk_live_51HxZ9l2eZvKYlo2C", entropy=4.5, line=1)
        reaches, sink = agent._taint_check(content, m)
        assert reaches is False
        assert sink is None

    def test_reaches_file_sink(self, agent):
        content = (
            'String pwd = "SuperSecret99!";\n'
            'FileWriter fw = new FileWriter("out.txt");\n'
            'fw.write(pwd);\n'
        )
        m = _make_match("password_assignment", "SuperSecret99!", entropy=3.8, line=1)
        m = _make_match_with_text(m, 'pwd = "SuperSecret99!"')
        reaches, sink = agent._taint_check(content, m)
        assert reaches is True
        assert sink == "file_write"


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_high_severity_with_sink(self, agent, ctx):
        f = ctx.decompiled_dir / "com" / "example" / "X.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        m = _make_match("api_key", "sk_live_51HxZ9l2eZvKYlo2C", entropy=4.5, file_path=f)
        finding = agent._make_finding(m, True, "network_send", Severity.HIGH)
        assert finding.agent_id == "A_001"
        assert finding.severity == Severity.HIGH
        assert finding.evidence["reaches_dangerous_sink"] is True
        assert finding.evidence["sink_type"] == "network_send"
        assert "CWE-798" in finding.compliance_tags
        assert "CWE-259" in finding.compliance_tags
        assert finding.owasp == "M2"
        assert finding.masvs == "MASVS-STORAGE-2"

    def test_medium_severity_without_sink(self, agent, ctx):
        f = ctx.decompiled_dir / "com" / "example" / "Y.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        m = _make_match("password_assignment", "hunter2", entropy=3.1, file_path=f)
        finding = agent._make_finding(m, False, None, Severity.MEDIUM)
        assert finding.severity == Severity.MEDIUM
        assert finding.evidence["reaches_dangerous_sink"] is False


# ---------------------------------------------------------------------------
# Integration: full analyze() call
# ---------------------------------------------------------------------------

class TestAnalyzeIntegration:
    @pytest.mark.asyncio
    async def test_finds_api_key_reaching_network(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "ApiClient.java", """
package com.example;
public class ApiClient {
    private static final String API_KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";

    public void call() {
        OkHttpClient client = new OkHttpClient();
        Request req = new Request.Builder()
            .header("X-API-Key", API_KEY)
            .build();
        client.newCall(req).execute();
    }
}
""")
        findings = await agent.analyze()
        assert len(findings) >= 1
        api_finding = next((f for f in findings if "api_key" in f.evidence.get("pattern", "")), None)
        assert api_finding is not None
        assert api_finding.severity == Severity.HIGH
        assert api_finding.evidence["reaches_dangerous_sink"] is True

    @pytest.mark.asyncio
    async def test_placeholder_not_reported(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Config.java", """
public class Config {
    private static final String API_KEY = "YOUR_API_KEY_HERE";
}
""")
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_test_file_skipped(self, agent, ctx):
        # File has "Test" in path — must be ignored
        p = ctx.decompiled_dir / "com" / "example" / "ApiClientTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('String KEY = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";')
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_source_returns_empty(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nonexistent"
        a = A001HardcodedCredsAgent(context=ctx, memory=memory)
        findings = await a.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_is_applicable_true_when_sources_exist(self, agent):
        assert await agent.is_applicable() is True

    @pytest.mark.asyncio
    async def test_is_applicable_false_when_no_source(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nope"
        ctx.resources_dir = None
        a = A001HardcodedCredsAgent(context=ctx, memory=memory)
        assert await a.is_applicable() is False

    @pytest.mark.asyncio
    async def test_aws_key_detected(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Aws.java", """
public class Aws {
    static final String KEY = "AKIAIOSFODNN7EXAMPLE";
}
""")
        findings = await agent.analyze()
        assert any("aws_access_key" in f.evidence.get("pattern", "") for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_secrets_in_file(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Multi.java", """
public class Multi {
    String apiKey = "sk_live_51HxZ9l2eZvKYlo2C0xYz9AbC";
    String awsKey = "AKIAIOSFODNN7EXAMPLE";
}
""")
        findings = await agent.analyze()
        patterns = {f.evidence.get("pattern") for f in findings}
        assert "api_key" in patterns
        assert "aws_access_key" in patterns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(
    pattern_name: str,
    secret_value: str,
    entropy: float,
    line: int = 1,
    file_path: Path | None = None,
) -> _Match:
    return _Match(
        pattern_name=pattern_name,
        file_path=file_path or Path("Fake.java"),
        line_number=line,
        matched_text=f'{pattern_name} = "{secret_value}"',
        secret_value=secret_value,
        entropy=entropy,
        context_window=f'String {pattern_name} = "{secret_value}";',
        confidence=0.90,
    )


def _make_match_with_text(m: _Match, matched_text: str) -> _Match:
    return _Match(
        pattern_name=m.pattern_name,
        file_path=m.file_path,
        line_number=m.line_number,
        matched_text=matched_text,
        secret_value=m.secret_value,
        entropy=m.entropy,
        context_window=m.context_window,
        confidence=m.confidence,
    )
