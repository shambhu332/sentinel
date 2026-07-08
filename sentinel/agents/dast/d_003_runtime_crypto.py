"""D_003: Validate SAST crypto findings (C_001/C_002) at runtime via Frida hooks."""
from __future__ import annotations

from sentinel.agents.dast.base_dast_agent import BaseDASTAgent, RuntimeEvent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext

_FRIDA_JS = r"""
Java.perform(function() {
    // Hook Cipher.init() — detect ECB and weak key lengths
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            var algorithm = this.getAlgorithm();
            var keyBytes = key ? key.getEncoded() : null;
            var keyLength = keyBytes ? keyBytes.length * 8 : 0;
            send({agent_id:'D_003', event_type:'crypto_init',
                  algorithm: algorithm, opmode: opmode,
                  key_length: keyLength, timestamp: Date.now()});
            if (algorithm && algorithm.indexOf('ECB') !== -1) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'ecb_mode', algorithm: algorithm, timestamp: Date.now()});
            }
            if (keyLength > 0 && keyLength < 128 && algorithm && algorithm.indexOf('AES') !== -1) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'weak_key_length', key_length: keyLength, timestamp: Date.now()});
            }
            return this.init(opmode, key);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'Cipher.init'});
    }

    // Hook IvParameterSpec constructor — detect static/zero IV
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        IvParameterSpec.$init.overload('[B').implementation = function(iv) {
            var allZero = true;
            for (var i = 0; i < iv.length; i++) {
                if (iv[i] !== 0) { allZero = false; break; }
            }
            send({agent_id:'D_003', event_type:'iv_created',
                  iv_length: iv.length, is_all_zero: allZero, timestamp: Date.now()});
            if (allZero) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'static_zero_iv', iv_length: iv.length, timestamp: Date.now()});
            }
            return this.$init(iv);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'IvParameterSpec'});
    }

    // Hook java.util.Random — detect weak PRNG for security operations
    try {
        var Random = Java.use('java.util.Random');
        Random.nextInt.overload('int').implementation = function(bound) {
            send({agent_id:'D_003', event_type:'weak_random',
                  type:'java.util.Random', bound: bound, timestamp: Date.now()});
            return this.nextInt(bound);
        };
        Random.nextBytes.implementation = function(bytes) {
            send({agent_id:'D_003', event_type:'weak_random',
                  type:'java.util.Random', operation:'nextBytes',
                  length: bytes.length, timestamp: Date.now()});
            return this.nextBytes(bytes);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'java.util.Random'});
    }
});
"""


class D003RuntimeCryptoAgent(BaseDASTAgent):
    AGENT_ID = "D_003"
    VULN_CLASS = "Runtime Crypto Weakness"
    _DESCRIPTION = "Validate SAST crypto findings at runtime via Frida — confirms ECB, static IV, weak PRNG"

    def get_frida_script(self) -> str:
        return _FRIDA_JS

    async def analyze_events(
        self, events: list[RuntimeEvent], ctx: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        weaknesses = [e for e in events if e.event_type == "crypto_weakness"]
        weak_randoms = [e for e in events if e.event_type == "weak_random"]

        ecb_events = [w for w in weaknesses if w.data.get("weakness") == "ecb_mode"]
        iv_events = [w for w in weaknesses if w.data.get("weakness") == "static_zero_iv"]
        key_events = [w for w in weaknesses if w.data.get("weakness") == "weak_key_length"]

        if ecb_events:
            algos = list({e.data.get("algorithm", "AES/ECB") for e in ecb_events})
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.97,
                severity_rationale=(
                    f"ECB mode confirmed at runtime ({len(ecb_events)} Cipher.init calls): "
                    f"{', '.join(algos)}"
                ),
                evidence={
                    "weakness": "ecb_mode",
                    "algorithms": algos,
                    "occurrence_count": len(ecb_events),
                    "sast_correlation": "Confirms C_001 finding",
                },
                recommendation=(
                    "Replace AES/ECB with AES/GCM/NoPadding. Generate a random 96-bit IV "
                    "per operation with SecureRandom and prepend it to the ciphertext."
                ),
                compliance_tags=["CWE-327"],
                owasp="M5: Insufficient Cryptography",
                masvs="MASVS-CRYPTO-1",
                finding_category="Static_Tool",
            ))

        if iv_events:
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.96,
                severity_rationale=(
                    f"Static all-zero IV confirmed at runtime ({len(iv_events)} occurrences). "
                    "Identical plaintexts produce identical ciphertext blocks."
                ),
                evidence={
                    "weakness": "static_zero_iv",
                    "occurrence_count": len(iv_events),
                    "sast_correlation": "Confirms C_002 finding",
                },
                recommendation=(
                    "Generate a cryptographically random IV per encryption operation "
                    "using SecureRandom.nextBytes(iv) and transmit it alongside the ciphertext."
                ),
                compliance_tags=["CWE-329", "CWE-330"],
                owasp="M5: Insufficient Cryptography",
                masvs="MASVS-CRYPTO-1",
                finding_category="Static_Tool",
            ))

        if key_events:
            lengths = [e.data.get("key_length", 0) for e in key_events]
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.95,
                severity_rationale=f"Weak AES key confirmed at runtime: {lengths} bits",
                evidence={"weakness": "weak_key_length", "key_lengths_bits": lengths},
                recommendation="Use AES-256 (256-bit key). Never use AES-64 or AES-128 for sensitive data.",
                compliance_tags=["CWE-326"],
                owasp="M5: Insufficient Cryptography",
                masvs="MASVS-CRYPTO-1",
                finding_category="Static_Tool",
            ))

        if weak_randoms:
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.CRITICAL,
                confidence=0.90,
                severity_rationale=(
                    f"java.util.Random used {len(weak_randoms)} times at runtime. "
                    "If used for security tokens or keys, values are predictable."
                ),
                evidence={
                    "weakness": "weak_prng",
                    "occurrence_count": len(weak_randoms),
                    "calls": [e.data for e in weak_randoms[:5]],
                },
                recommendation=(
                    "Replace java.util.Random with java.security.SecureRandom for all "
                    "security-sensitive random number generation."
                ),
                compliance_tags=["CWE-338"],
                owasp="M5: Insufficient Cryptography",
                masvs="MASVS-CRYPTO-2",
                finding_category="Static_Tool",
            ))

        return findings
