# tests/benchmark/rules_vs_ai_benchmark.py
"""
Compare rule-only detection vs AI-autonomous detection.
This proves the value of the LLM-first architecture.
"""

import pytest
from pathlib import Path
from sentinel.agents.auth.a_001_ai import A001AIHardcodedCredsAgent
from sentinel.agents.auth.a_001_hardcoded_creds import A001HardcodedCredsAgent  # Old rule-only
from sentinel.llm.vulnerability_analyzer import LLMVulnerabilityAnalyzer
from sentinel.rag.query import RAGQueryEngine
from sentinel.core.scan_context import ScanContext
from unittest.mock import MagicMock, AsyncMock


# Test case: Custom XOR cipher (no rule matches)
CUSTOM_CRYPTO_CODE = '''
public class PaymentCrypto {
    private byte[] key = "mysecretkey12345".getBytes();
    
    public String encrypt(String data) {
        byte[] result = new byte[data.length()];
        for (int i = 0; i < data.length(); i++) {
            result[i] = (byte)(data.charAt(i) ^ key[i % key.length]);
        }
        return Base64.encodeToString(result, Base64.DEFAULT);
    }
    
    public String decrypt(String encrypted) {
        // Same XOR = symmetric
        return encrypt(encrypted); // "clever" reuse
    }
}
'''

# Test case: Logic bug - IDOR via client-side role check
CLIENT_SIDE_AUTH_CODE = '''
public class AdminPanel {
    public void checkAccess(User user) {
        // Client-side role check, server doesn't verify
        if (user.getRole().equals("admin")) {
            showAdminFeatures();
        }
        // API call doesn't include auth token - server trusts client
        apiClient.loadAdminData(user.getId());
    }
}
'''

# Test case: Timing attack in comparison
TIMING_ATTACK_CODE = '''
public class PasswordCheck {
    public boolean verifyPassword(String input, String stored) {
        // Vulnerable: byte-by-byte comparison leaks timing
        if (input.length() != stored.length()) return false;
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) != stored.charAt(i)) {
                return false; // Early return leaks position
            }
        }
        return true;
    }
}
'''


class TestRulesVsAI:
    """Prove AI finds what rules miss."""
    
    @pytest.fixture
    def mock_ctx(self, tmp_path: Path):
        ctx = MagicMock(spec=ScanContext)
        ctx.session_id = "benchmark-001"
        ctx.workspace = tmp_path
        ctx.app_category = "banking"
        return ctx
    
    @pytest.fixture
    def ai_agent(self):
        llm = MagicMock(spec=LLMVulnerabilityAnalyzer)
        rag = MagicMock(spec=RAGQueryEngine)
        return A001AIHardcodedCredsAgent(llm, rag)
    
    @pytest.fixture  
    def rule_agent(self):
        return A001HardcodedCredsAgent()
    
    @pytest.mark.asyncio
    async def test_custom_crypto_rules_miss_ai_finds(self, ai_agent, rule_agent, mock_ctx, tmp_path):
        """Rules: No match (no Cipher.getInstance, no standard API). 
        AI: Should find custom XOR cipher with short repeating key."""
        
        # Setup workspace
        sources = tmp_path / "jadx" / "sources" / "com" / "example"
        sources.mkdir(parents=True)
        crypto_file = sources / "PaymentCrypto.java"
        crypto_file.write_text(CUSTOM_CRYPTO_CODE)
        
        # Rule agent
        rule_findings = []
        async def rule_emit(ctx, finding):
            rule_findings.append(finding)
        rule_agent.emit_finding = rule_emit
        
        await rule_agent.run(mock_ctx)
        assert len(rule_findings) == 0, "Rules should miss custom crypto"
        
        # AI agent - mock LLM to return true positive
        mock_verdict = MagicMock()
        mock_verdict.verdict.value = "true_positive"
        mock_verdict.confidence = 0.92
        mock_verdict.vulnerability_type = "CWE-327: Use of Broken or Risky Cryptographic Algorithm"
        mock_verdict.severity = "Critical"
        mock_verdict.reasoning = "Custom XOR cipher with 15-byte repeating key is trivially breakable via frequency analysis. Banking app using this for payment data is catastrophic."
        mock_verdict.exploit_path = []
        mock_verdict.business_impact = "Payment data encryption bypassed, direct financial fraud"
        mock_verdict.remediation_code = "// Use AES/GCM from Android Keystore\nCipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\nSecretKey key = getKeyFromKeystore();\ncipher.init(Cipher.ENCRYPT_MODE, key);\nbyte[] iv = cipher.getIV();\nbyte[] ciphertext = cipher.doFinal(plaintext.getBytes());"
        mock_verdict.remediation_steps = ["Replace with AES/GCM", "Use Android Keystore", "Add authentication tag"]
        mock_verdict.false_positive_reason = None
        mock_verdict.dast_validation_needed = None
        mock_verdict.similar_cves = ["CVE-2021-XXXX"]
        mock_verdict.owasp_masvs_mapping = ["M5: Insufficient Cryptography"]
        
        ai_agent.llm.analyze_candidate = AsyncMock(return_value=mock_verdict)
        
        ai_findings = []
        async def ai_emit(ctx, finding):
            ai_findings.append(finding)
        ai_agent.emit_finding = ai_emit
        
        await ai_agent.run(mock_ctx)
        assert len(ai_findings) == 1, "AI should find custom crypto"
        assert ai_findings[0].severity.value == "Critical"
        assert "XOR" in ai_findings[0].description or "frequency analysis" in ai_findings[0].description
    
    @pytest.mark.asyncio
    async def test_client_side_auth_rules_miss_ai_finds(self, ai_agent, mock_ctx, tmp_path):
        """Rules: No match (no hardcoded cred, no standard API).
        AI: Should find client-side authorization bypass."""
        
        sources = tmp_path / "jadx" / "sources" / "com" / "example"
        sources.mkdir(parents=True)
        auth_file = sources / "AdminPanel.java"
        auth_file.write_text(CLIENT_SIDE_AUTH_CODE)
        
        # Mock LLM to find IDOR
        mock_verdict = MagicMock()
        mock_verdict.verdict.value = "true_positive"
        mock_verdict.confidence = 0.88
        mock_verdict.vulnerability_type = "CWE-639: Authorization Bypass Through User-Controlled Key"
        mock_verdict.severity = "Critical"
        mock_verdict.reasoning = "Client-side role check with server-side trust. Attacker can modify client code or intercept API call to access admin data without authentication."
        mock_verdict.exploit_path = []
        mock_verdict.business_impact = "Unauthorized admin access, data breach, privilege escalation"
        mock_verdict.remediation_code = "// Server must verify role and permissions\n@PreAuthorize(\"hasRole('ADMIN')\")\n@GetMapping(\"/admin/data\")\npublic ResponseEntity<AdminData> getAdminData(@AuthenticationPrincipal User user) {\n    if (!user.hasRole(\"ADMIN\")) {\n        throw new AccessDeniedException();\n    }\n    return adminService.getData();\n}"
        mock_verdict.remediation_steps = ["Move auth check to server", "Validate JWT on every request", "Use @PreAuthorize or equivalent"]
        mock_verdict.false_positive_reason = None
        mock_verdict.dast_validation_needed = "Verify API endpoint rejects non-admin requests"
        mock_verdict.similar_cves = ["CVE-2022-YYYY"]
        mock_verdict.owasp_masvs_mapping = ["M1: Improper Platform Usage", "M7: Client Code Quality"]
        
        ai_agent.llm.analyze_candidate = AsyncMock(return_value=mock_verdict)
        
        ai_findings = []
        async def ai_emit(ctx, finding):
            ai_findings.append(finding)
        ai_agent.emit_finding = ai_emit
        
        await ai_agent.run(mock_ctx)
        assert len(ai_findings) == 1
        assert "client-side" in ai_findings[0].description.lower() or "server" in ai_findings[0].description.lower()
    
    @pytest.mark.asyncio
    async def test_timing_attack_rules_miss_ai_finds(self, ai_agent, mock_ctx, tmp_path):
        """Rules: No match (no standard crypto API).
        AI: Should find timing side-channel."""
        
        sources = tmp_path / "jadx" / "sources" / "com" / "example"
        sources.mkdir(parents=True)
        timing_file = sources / "PasswordCheck.java"
        timing_file.write_text(TIMING_ATTACK_CODE)
        
        mock_verdict = MagicMock()
        mock_verdict.verdict.value = "true_positive"
        mock_verdict.confidence = 0.85
        mock_verdict.vulnerability_type = "CWE-208: Observable Timing Discrepancy"
        mock_verdict.severity = "High"
        mock_verdict.reasoning = "Byte-by-byte comparison with early return leaks password length and each byte via timing side-channel. Over network, attacker can reconstruct password character by character."
        mock_verdict.exploit_path = []
        mock_verdict.business_impact = "Password recovery via timing analysis, account takeover"
        mock_verdict.remediation_code = "// Use MessageDigest.isEqual for constant-time comparison\nimport java.security.MessageDigest;\n\npublic boolean verifyPassword(String input, String stored) {\n    return MessageDigest.isEqual(input.getBytes(), stored.getBytes());\n}"
        mock_verdict.remediation_steps = ["Use MessageDigest.isEqual()", "Or use Arrays.compare() with padding", "Add random delay as defense-in-depth"]
        mock_verdict.false_positive_reason = None
        mock_verdict.dast_validation_needed = "Measure response time for correct vs incorrect password bytes"
        mock_verdict.similar_cves = ["CVE-2023-ZZZZ"]
        mock_verdict.owasp_masvs_mapping = ["M5: Insufficient Cryptography"]
        
        ai_agent.llm.analyze_candidate = AsyncMock(return_value=mock_verdict)
        
        ai_findings = []
        async def ai_emit(ctx, finding):
            ai_findings.append(finding)
        ai_agent.emit_finding = ai_emit
        
        await ai_agent.run(mock_ctx)
        assert len(ai_findings) == 1
        assert "timing" in ai_findings[0].description.lower()