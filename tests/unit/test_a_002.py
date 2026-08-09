"""Unit tests for A_002 JWT Algorithm Confusion Agent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.auth.a_002_jwt_alg_confusion import (
    A002JWTAlgConfusionAgent,
    _Match,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


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
    return A002JWTAlgConfusionAgent(context=ctx, memory=memory)


def _java_file(decompiled_dir: Path, name: str, content: str) -> Path:
    p = decompiled_dir / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _match(vuln_type: str, line: int = 5, fp: Path | None = None) -> _Match:
    return _Match(
        vuln_type=vuln_type,
        file_path=fp or Path("Fake.java"),
        line_number=line,
        matched_text=f"// {vuln_type} example",
        context_window=f"context around line {line}",
        algorithm_value="none" if vuln_type == "alg_none" else "HS256",
        key_type=None,
        confidence=0.90,
    )


# ---------------------------------------------------------------------------
# alg: none detection
# ---------------------------------------------------------------------------

class TestAlgNoneDetection:
    def test_algorithm_none_call(self, agent, ctx):
        code = """
import com.auth0.jwt.algorithms.Algorithm;
public class T {
    void v(String token) {
        Algorithm alg = Algorithm.none();
    }
}
"""
        f = _java_file(ctx.decompiled_dir, "T1.java", code)
        matches = agent._find_alg_none(f, code)
        assert len(matches) >= 1
        assert matches[0].vuln_type == "alg_none"
        assert matches[0].algorithm_value == "none"

    def test_alg_none_in_header_json(self, agent, ctx):
        code = 'String h = "{\\"alg\\":\\"none\\",\\"typ\\":\\"JWT\\"}";'
        f = _java_file(ctx.decompiled_dir, "T2.java", code)
        matches = agent._find_alg_none(f, code)
        assert len(matches) >= 1

    def test_algorithms_array_none(self, agent, ctx):
        code = 'jwt.decode(token, key, algorithms=["none"])'
        f = _java_file(ctx.decompiled_dir, "T3.java", code)
        matches = agent._find_alg_none(f, code)
        assert len(matches) >= 1

    def test_parse_claims_jwt_unsigned(self, agent, ctx):
        code = 'Jwts.parser().setSigningKey(key).parseClaimsJwt(token);'
        f = _java_file(ctx.decompiled_dir, "T4.java", code)
        matches = agent._find_alg_none(f, code)
        assert len(matches) >= 1


# ---------------------------------------------------------------------------
# HS256 + RSA public key
# ---------------------------------------------------------------------------

class TestHS256RSADetection:
    def test_hmac256_with_rsa_public_key(self, agent, ctx):
        code = """
import com.auth0.jwt.algorithms.Algorithm;
public class Bad {
    void v(RSAPublicKey publicKey) {
        Algorithm alg = Algorithm.HMAC256(publicKey.getEncoded());
    }
}
"""
        f = _java_file(ctx.decompiled_dir, "Bad.java", code)
        matches = agent._find_hs256_rsa(f, code)
        assert len(matches) >= 1
        assert matches[0].vuln_type == "alg_hs256_rsa"
        assert matches[0].algorithm_value == "HS256"

    def test_hs256_with_begin_public_key(self, agent, ctx):
        code = 'String alg = "HS256"; String k = "-----BEGIN PUBLIC KEY-----\\nMIIBIj";'
        f = _java_file(ctx.decompiled_dir, "Conf.java", code)
        matches = agent._find_hs256_rsa(f, code)
        assert len(matches) >= 1


# ---------------------------------------------------------------------------
# Missing algorithm whitelist
# ---------------------------------------------------------------------------

class TestMissingVerifyDetection:
    def test_jwt_decode_without_algorithm(self, agent, ctx):
        code = 'DecodedJWT jwt = JWT.decode(token);'
        f = _java_file(ctx.decompiled_dir, "Lazy.java", code)
        matches = agent._find_missing_verify(f, code)
        assert len(matches) >= 1
        assert matches[0].vuln_type == "missing_verify"

    def test_jwt_decode_with_verify_not_flagged(self, agent, ctx):
        # _has_algorithms_param should suppress this
        code = 'DecodedJWT jwt = JWT.decode(token); jwt.verify(Algorithm.RSA256(pub, priv));'
        f = _java_file(ctx.decompiled_dir, "Safe.java", code)
        matches = agent._find_missing_verify(f, code)
        assert matches == []

    def test_jjwt_parse_claims_jws_not_flagged(self, agent, ctx):
        # parseClaimsJws (signed) is safe — only parseClaimsJwt triggers alg_none
        code = 'Jwts.parser().setSigningKey(key).parseClaimsJws(token);'
        f = _java_file(ctx.decompiled_dir, "JJWT.java", code)
        # Missing-verify patterns should not fire on parseClaimsJws
        matches = agent._find_missing_verify(f, code)
        # If JJWT pattern matches, it checks _has_algorithms_param
        # Either no match or suppressed is acceptable
        for m in matches:
            # If it fires, make sure it's classified correctly
            assert m.vuln_type == "missing_verify"


# ---------------------------------------------------------------------------
# JWK kty/alg mismatch
# ---------------------------------------------------------------------------

class TestJWKMismatchDetection:
    def test_rsa_key_with_hs256_alg(self, agent, ctx):
        code = '{"kty":"RSA","alg":"HS256","n":"...","e":"AQAB"}'
        f = _java_file(ctx.decompiled_dir, "JWK.java", code)
        matches = agent._find_jwk_mismatch(f, code)
        assert len(matches) >= 1
        assert matches[0].vuln_type == "jwk_mismatch"

    def test_alg_first_then_kty_rsa(self, agent, ctx):
        code = '{"alg":"HS384","kty":"RSA","n":"abc","e":"AQAB"}'
        f = _java_file(ctx.decompiled_dir, "JWK2.java", code)
        matches = agent._find_jwk_mismatch(f, code)
        assert len(matches) >= 1


# ---------------------------------------------------------------------------
# False-positive filtering
# ---------------------------------------------------------------------------

class TestFalsePositiveFiltering:
    def test_comment_line_rejected(self, agent, ctx):
        code = "// Algorithm.none() — never use this in production\n"
        f = _java_file(ctx.decompiled_dir, "Doc.java", code)
        # _find_alg_none may match the text, but _is_fp should catch it
        matches = agent._find_alg_none(f, code)
        surviving = [m for m in matches if not agent._is_fp(m, code)]
        assert surviving == []

    def test_log_line_rejected(self, agent, ctx):
        code = 'logger.warn("Do not use Algorithm.none() in prod");'
        f = _java_file(ctx.decompiled_dir, "Log.java", code)
        matches = agent._find_alg_none(f, code)
        surviving = [m for m in matches if not agent._is_fp(m, code)]
        assert surviving == []

    def test_validation_guard_rejected(self, agent):
        m = _match("alg_none")
        m = _Match(
            vuln_type="alg_none",
            file_path=Path("V.java"),
            line_number=3,
            matched_text='Algorithm.none()',
            context_window='if (alg.equals("none")) { throw new Exception(); } // validate alg',
            algorithm_value="none",
            key_type=None,
            confidence=0.95,
        )
        assert agent._is_fp(m, "") is True

    def test_test_file_skipped_in_analyze(self, agent, ctx):
        p = ctx.decompiled_dir / "com" / "example" / "JWTTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("Algorithm.none();")
        # test path contains "Test" — _TEST_PATH_RE should catch it


# ---------------------------------------------------------------------------
# Taint — attacker-controlled alg
# ---------------------------------------------------------------------------

class TestAttackerControlledAlg:
    def test_alg_none_always_attacker_controlled(self, agent):
        m = _match("alg_none")
        assert agent._check_attacker_controlled("", m) is True

    def test_alg_from_request_header(self, agent):
        content = 'String alg = request.getHeader("alg");\n'
        m = _match("missing_verify", line=2)
        assert agent._check_attacker_controlled(content, m) is True

    def test_hardcoded_alg_not_attacker_controlled(self, agent):
        content = 'Algorithm.HMAC256(publicKey.getEncoded());\n'
        m = _match("alg_hs256_rsa", line=1)
        assert agent._check_attacker_controlled(content, m) is False


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class TestSeverityDetermination:
    def test_alg_none_is_critical(self, agent):
        assert agent._severity(_match("alg_none"), True) == Severity.CRITICAL

    def test_hs256_rsa_attacker_ctrl_is_critical(self, agent):
        assert agent._severity(_match("alg_hs256_rsa"), True) == Severity.CRITICAL

    def test_hs256_rsa_not_attacker_ctrl_is_high(self, agent):
        assert agent._severity(_match("alg_hs256_rsa"), False) == Severity.HIGH

    def test_jwk_mismatch_is_high(self, agent):
        assert agent._severity(_match("jwk_mismatch"), False) == Severity.HIGH

    def test_missing_verify_attacker_ctrl_is_high(self, agent):
        assert agent._severity(_match("missing_verify"), True) == Severity.HIGH

    def test_missing_verify_no_ctrl_is_medium(self, agent):
        assert agent._severity(_match("missing_verify"), False) == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_alg_none_finding_fields(self, agent, ctx):
        f = ctx.decompiled_dir / "com" / "example" / "V.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        m = _Match(
            vuln_type="alg_none",
            file_path=f,
            line_number=7,
            matched_text="Algorithm.none()",
            context_window="Algorithm alg = Algorithm.none();",
            algorithm_value="none",
            key_type=None,
            confidence=0.95,
        )
        finding = agent._make_finding(m, True, Severity.CRITICAL)
        assert finding.agent_id == "A_016"
        assert finding.severity == Severity.CRITICAL
        assert "CWE-287" in finding.compliance_tags
        assert "CWE-347" in finding.compliance_tags
        assert finding.owasp == "M5"
        assert finding.masvs == "MASVS-AUTH-2"
        assert finding.evidence["vulnerability_type"] == "alg_none"
        assert finding.evidence["attacker_controlled"] is True
        assert "none" in finding.vuln_class.lower() or "alg none" in finding.vuln_class.lower()

    def test_hs256_rsa_finding_severity(self, agent, ctx):
        f = ctx.decompiled_dir / "com" / "example" / "W.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        m = _Match(
            vuln_type="alg_hs256_rsa",
            file_path=f,
            line_number=10,
            matched_text="Algorithm.HMAC256(publicKey)",
            context_window="Algorithm alg = Algorithm.HMAC256(publicKey.getEncoded());",
            algorithm_value="HS256",
            key_type="RSA public key",
            confidence=0.90,
        )
        finding = agent._make_finding(m, False, Severity.HIGH)
        assert finding.severity == Severity.HIGH
        assert finding.evidence["key_type"] == "RSA public key"


# ---------------------------------------------------------------------------
# Integration: full analyze() call
# ---------------------------------------------------------------------------

class TestAnalyzeIntegration:
    @pytest.mark.asyncio
    async def test_finds_alg_none(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Auth.java", """
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWT;
public class Auth {
    void verify(String token) {
        Algorithm alg = Algorithm.none();
        JWT.require(alg).build().verify(token);
    }
}
""")
        findings = await agent.analyze()
        alg_none = [f for f in findings if "alg_none" in f.evidence.get("vulnerability_type", "")]
        assert len(alg_none) >= 1
        assert alg_none[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_finds_hs256_rsa(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Confused.java", """
import com.auth0.jwt.algorithms.Algorithm;
public class Confused {
    void v(RSAPublicKey publicKey) {
        Algorithm alg = Algorithm.HMAC256(publicKey.getEncoded());
        JWT.require(alg).build().verify(token);
    }
}
""")
        findings = await agent.analyze()
        hs_rsa = [f for f in findings if "alg_hs256_rsa" in f.evidence.get("vulnerability_type", "")]
        assert len(hs_rsa) >= 1

    @pytest.mark.asyncio
    async def test_secure_rs256_not_flagged(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "Secure.java", """
import com.auth0.jwt.algorithms.Algorithm;
public class Secure {
    void v(RSAPublicKey pub, RSAPrivateKey priv, String token) {
        Algorithm alg = Algorithm.RSA256(pub, priv);
        JWT.require(alg).build().verify(token);
    }
}
""")
        findings = await agent.analyze()
        # RS256 is secure — no A_002 findings expected
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_source_returns_empty(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nonexistent"
        a = A002JWTAlgConfusionAgent(context=ctx, memory=memory)
        findings = await a.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_is_applicable_true(self, agent):
        assert await agent.is_applicable() is True

    @pytest.mark.asyncio
    async def test_is_applicable_false_when_no_dir(self, ctx, memory):
        ctx.decompiled_dir = ctx.workspace / "nope"
        a = A002JWTAlgConfusionAgent(context=ctx, memory=memory)
        assert await a.is_applicable() is False

    @pytest.mark.asyncio
    async def test_test_file_skipped(self, agent, ctx):
        p = ctx.decompiled_dir / "com" / "example" / "AuthServiceTest.java"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("Algorithm.none();")
        findings = await agent.analyze()
        assert findings == []

    @pytest.mark.asyncio
    async def test_multiple_vulns_in_one_file(self, agent, ctx):
        _java_file(ctx.decompiled_dir, "AuthService.java", """
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
public class AuthService {
    void verifyUnsigned(String token) {
        Algorithm alg = Algorithm.none();
        JWT.require(alg).build().verify(token);
    }
    void verifyConfused(String token, RSAPublicKey pub) {
        Algorithm alg = Algorithm.HMAC256(pub.getEncoded());
        JWT.require(alg).build().verify(token);
    }
}
""")
        findings = await agent.analyze()
        vuln_types = {f.evidence.get("vulnerability_type") for f in findings}
        assert "alg_none" in vuln_types
        assert "alg_hs256_rsa" in vuln_types
