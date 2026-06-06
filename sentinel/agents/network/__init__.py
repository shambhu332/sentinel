"""Network and communication security agents."""
from sentinel.agents.network.cleartext_traffic_agent import CleartextTrafficAgent
from sentinel.agents.network.n006_api_key_leakage import ApiKeyLeakageAgent
from sentinel.agents.network.n007_graphql_introspection import (
    GraphqlIntrospectionAgent,
)
from sentinel.agents.network.n008_insecure_trust_manager import (
    InsecureTrustManagerAgent,
)
from sentinel.agents.network.n009_webview_debug_flag import (
    WebViewDebugFlagAgent,
)
from sentinel.agents.network.n010_okhttp_logging import OkHttpLoggingAgent
from sentinel.agents.network.n011_graphql_fuzzer import GraphqlFuzzerAgent
from sentinel.agents.network.n012_dns_leak import DnsLeakAgent
from sentinel.agents.network.n013_insecure_websocket import InsecureWebSocketAgent
from sentinel.agents.network.n014_hardcoded_mtls_key import HardcodedMtlsKeyAgent

__all__ = [
    "CleartextTrafficAgent",
    "ApiKeyLeakageAgent",
    "DnsLeakAgent",
    "GraphqlIntrospectionAgent",
    "HardcodedMtlsKeyAgent",
    "InsecureTrustManagerAgent",
    "InsecureWebSocketAgent",
    "WebViewDebugFlagAgent",
    "OkHttpLoggingAgent",
    "GraphqlFuzzerAgent",
]
