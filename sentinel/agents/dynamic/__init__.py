"""Dynamic analysis agents — run during Phase 4.

These agents consume captures from mitmproxy/Frida and produce findings
about runtime behavior. Unlike SAST agents in Phase 2 that read source
code, DAST agents observe the app actually running on a device.

Sprint 8.1 agents:
- N_003 Improper TLS Validation (cert pinning detection via mitmproxy)
- N_004 Sensitive Data In Transit (PII/tokens in network traffic)

Sprint 8.2 agents:
- A_003 Runtime Crypto (weak algorithms in actual use, via Frida)
- N_005 Cert Pinning Bypass (runtime bypass of major pinning libraries)

Sprint 8.3 agents (UX / sensitive-surface):
- D_001 Clipboard Sensitive Data Leak
- D_002 Missing FLAG_SECURE on Sensitive Screens
- D_003 Insecure Biometric Prompt
"""
from sentinel.agents.dynamic.cert_pinning_bypass_agent import CertPinningBypassAgent
from sentinel.agents.dynamic.d001_clipboard_leak_agent import ClipboardLeakAgent
from sentinel.agents.dynamic.d002_flag_secure_missing_agent import (
    FlagSecureMissingAgent,
)
from sentinel.agents.dynamic.d003_biometric_weak_agent import BiometricWeakAgent
from sentinel.agents.dynamic.data_in_transit_agent import DataInTransitAgent
from sentinel.agents.dynamic.improper_tls_agent import ImproperTLSAgent
from sentinel.agents.dynamic.runtime_crypto_agent import RuntimeCryptoAgent

__all__ = [
    "BiometricWeakAgent",
    "CertPinningBypassAgent",
    "ClipboardLeakAgent",
    "DataInTransitAgent",
    "FlagSecureMissingAgent",
    "ImproperTLSAgent",
    "RuntimeCryptoAgent",
]
