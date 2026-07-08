"""Unit tests for sentinel.monitor.logcat — PII/credential/debug-leak detection."""
from __future__ import annotations

import pytest

from sentinel.core.finding import Severity
from sentinel.monitor.logcat import analyze_logcat

SESSION = "test-session-logcat"

_CLEAN_LOG = (
    "07-08 10:00:01.000  100  101 I App     : Application started\n"
    "07-08 10:00:02.000  100  101 I Network : Request completed with status 200\n"
)


def _make_line(level: str, tag: str, msg: str) -> str:
    return f"07-08 10:00:00.000  1234  1235 {level} {tag}   : {msg}"


class TestCleanLog:
    def test_no_findings_for_clean_log(self):
        assert analyze_logcat(_CLEAN_LOG, SESSION) == []


class TestPIIPatterns:
    def test_detects_email(self):
        log = _make_line("I", "App", "User signed in: alice@example.com")
        findings = analyze_logcat(log, SESSION)
        vuln_classes = [f.vuln_class for f in findings]
        assert any("Email" in v for v in vuln_classes)

    def test_detects_credit_card(self):
        log = _make_line("D", "Payment", "card=4111111111111111 expiry=12/26")
        findings = analyze_logcat(log, SESSION)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("Payment Card" in f.vuln_class for f in findings)

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        log = _make_line("D", "Auth", f"token={jwt}")
        findings = analyze_logcat(log, SESSION)
        assert any("JWT" in f.vuln_class for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_bearer_token(self):
        log = _make_line("I", "HTTP", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456")
        findings = analyze_logcat(log, SESSION)
        assert any("Bearer" in f.vuln_class for f in findings)

    def test_detects_password_value(self):
        log = _make_line("D", "Login", "password=SuperSecret99!")
        findings = analyze_logcat(log, SESSION)
        assert any("Password" in f.vuln_class for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_private_key(self):
        log = _make_line("E", "Crypto", "-----BEGIN PRIVATE KEY-----")
        findings = analyze_logcat(log, SESSION)
        assert any("Private Key" in f.vuln_class for f in findings)

    def test_detects_url_token(self):
        log = _make_line("I", "Network",
                         "GET https://api.example.com/data?access_token=abc123defgh456")
        findings = analyze_logcat(log, SESSION)
        assert any("URL" in f.vuln_class for f in findings)

    def test_detects_api_key(self):
        log = _make_line("D", "Config", "api_key=sk-1234567890abcdefghij")
        findings = analyze_logcat(log, SESSION)
        assert any("API Key" in f.vuln_class for f in findings)

    def test_finding_has_evidence_examples(self):
        log = _make_line("I", "App", "email: user@example.com")
        findings = analyze_logcat(log, SESSION)
        email_findings = [f for f in findings if "Email" in f.vuln_class]
        assert email_findings
        assert "examples" in email_findings[0].evidence
        assert len(email_findings[0].evidence["examples"]) >= 1

    def test_finding_session_id(self):
        log = _make_line("I", "App", "email: bob@test.org")
        findings = analyze_logcat(log, SESSION)
        assert all(f.session_id == SESSION for f in findings)

    def test_finding_tenant_id_propagated(self):
        log = _make_line("I", "App", "email: bob@test.org")
        findings = analyze_logcat(log, SESSION, tenant_id="org-42")
        assert all(f.tenant_id == "org-42" for f in findings)

    def test_deduplicates_pattern_per_class(self):
        # Ten emails → still one finding with match_count=10.
        lines = "\n".join(
            _make_line("I", "App", f"User{i}@example.com signed in")
            for i in range(10)
        )
        findings = analyze_logcat(lines, SESSION)
        email_findings = [f for f in findings if "Email" in f.vuln_class]
        assert len(email_findings) == 1
        assert email_findings[0].evidence["match_count"] == 10


class TestDebugLeaks:
    def test_verbose_auth_tag_flagged(self):
        log = _make_line("V", "Auth", "checking credentials for user 42")
        findings = analyze_logcat(log, SESSION)
        debug_findings = [f for f in findings if "Verbose" in f.vuln_class]
        assert debug_findings
        assert debug_findings[0].severity == Severity.MEDIUM

    def test_debug_crypto_tag_flagged(self):
        log = _make_line("D", "Crypto", "cipher init complete")
        findings = analyze_logcat(log, SESSION)
        assert any("Crypto" in f.vuln_class for f in findings)

    def test_info_level_not_flagged_for_debug_leak(self):
        # I-level lines should not trigger the debug-leak check.
        log = _make_line("I", "Auth", "user logged out")
        findings = analyze_logcat(log, SESSION)
        debug_findings = [f for f in findings if "Verbose" in f.vuln_class]
        assert debug_findings == []

    def test_non_sensitive_tag_not_flagged(self):
        log = _make_line("D", "MainActivity", "onCreate called")
        findings = analyze_logcat(log, SESSION)
        assert findings == []

    def test_multiple_sensitive_tags_separate_findings(self):
        log = "\n".join([
            _make_line("D", "Auth", "token refreshed"),
            _make_line("V", "Crypto", "key derived"),
        ])
        findings = analyze_logcat(log, SESSION)
        debug_tags = {f.evidence.get("tag") for f in findings if "Verbose" in f.vuln_class}
        assert len(debug_tags) == 2


class TestMixedLog:
    def test_combined_pii_and_debug(self):
        log = "\n".join([
            _make_line("I", "App", "User email: test@example.com"),
            _make_line("D", "Auth", "Login attempt started"),
        ])
        findings = analyze_logcat(log, SESSION)
        assert len(findings) >= 2
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_empty_string_returns_empty(self):
        assert analyze_logcat("", SESSION) == []

    def test_unparseable_lines_ignored(self):
        log = "This line does not match the logcat format at all\n12345 garbage"
        assert analyze_logcat(log, SESSION) == []
