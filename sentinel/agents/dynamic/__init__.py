"""Dynamic analysis agents — run during Phase 4.

These agents consume captures from mitmproxy/Frida and produce findings
about runtime behavior. Unlike SAST agents in Phase 2 that read source
code, DAST agents observe the app actually running on a device.

Sprint 8.1 agents:
- N_003 Improper TLS Validation (cert pinning detection)
- N_004 Sensitive Data In Transit (PII/tokens leaking in network traffic)
"""
from sentinel.agents.dynamic.data_in_transit_agent import DataInTransitAgent
from sentinel.agents.dynamic.improper_tls_agent import ImproperTLSAgent

__all__ = [
    "ImproperTLSAgent",
    "DataInTransitAgent",
]
