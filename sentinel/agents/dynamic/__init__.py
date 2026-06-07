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

Sprint 8.4 agents (resilience / runtime integrity):
- D_004 Anti-Tamper Coverage Observer
- D_005 Dynamic Code Loading
- D_006 Runtime IV / Key Reuse
- D_007 Race-Condition / TOCTOU Candidate

Sprint 8.5 agents (business-logic candidate identifiers):
- D_008 IAP Verification Bypass
- D_009 IDOR / Mass-Assignment Candidate

Sprint 8.6 agents (token + web analysis):
- D_010 JWT Weakness
- D_011 Insecure WebView Runtime Configuration
- D_012 Sensitive Lockscreen Notification
- D_013 Third-Party PII / Credential Leak
- D_014 Cookie Hardening Audit
- D_015 Implicit Intent Sensitive Extras Leak
- D_016 Accessibility / NotificationListener Abuse Pattern
- D_017 GraphQL Persisted-Query Bypass
- D_018 SMS Permission / Retriever-API Abuse
- D_019 Screen Capture / MediaProjection Pipeline
- D_020 Dynamically-Registered Receiver Implicit Export
- D_021 PendingIntent Mutable at Runtime
- D_022 Local-Socket Server Exposed Across App Boundary
- D_023 ContentProvider URI Exposure to Cross-UID Caller
- D_024 FileProvider Path-Traversal / Symlink Escape
"""
from sentinel.agents.dynamic.cert_pinning_bypass_agent import CertPinningBypassAgent
from sentinel.agents.dynamic.d016_accessibility_abuse_agent import (
    AccessibilityAbuseAgent,
)
from sentinel.agents.dynamic.d017_graphql_persisted_query_agent import (
    GraphqlPersistedQueryAgent,
)
from sentinel.agents.dynamic.d018_sms_permission_abuse_agent import (
    SmsPermissionAbuseAgent,
)
from sentinel.agents.dynamic.d019_screen_capture_agent import (
    ScreenCaptureAgent,
)
from sentinel.agents.dynamic.d020_dynamic_receiver_export_agent import (
    DynamicReceiverExportAgent,
)
from sentinel.agents.dynamic.d021_pending_intent_mutable_agent import (
    PendingIntentMutableAgent,
)
from sentinel.agents.dynamic.d022_local_socket_server_agent import (
    LocalSocketServerAgent,
)
from sentinel.agents.dynamic.d023_content_provider_uri_exposure_agent import (
    ContentProviderUriExposureAgent,
)
from sentinel.agents.dynamic.d024_file_provider_traversal_agent import (
    FileProviderTraversalAgent,
)
from sentinel.agents.dynamic.d001_clipboard_leak_agent import ClipboardLeakAgent
from sentinel.agents.dynamic.d002_flag_secure_missing_agent import (
    FlagSecureMissingAgent,
)
from sentinel.agents.dynamic.d003_biometric_weak_agent import BiometricWeakAgent
from sentinel.agents.dynamic.d004_anti_tamper_agent import (
    AntiTamperCoverageAgent,
)
from sentinel.agents.dynamic.d005_dynamic_code_loading_agent import (
    DynamicCodeLoadingAgent,
)
from sentinel.agents.dynamic.d006_static_iv_reuse_agent import (
    StaticIvReuseAgent,
)
from sentinel.agents.dynamic.d007_race_condition_agent import (
    RaceConditionCandidateAgent,
)
from sentinel.agents.dynamic.d008_iap_bypass_agent import IapBypassAgent
from sentinel.agents.dynamic.d009_idor_candidate_agent import IdorCandidateAgent
from sentinel.agents.dynamic.d010_jwt_weakness_agent import JwtWeaknessAgent
from sentinel.agents.dynamic.d011_webview_runtime_agent import (
    WebViewRuntimeAgent,
)
from sentinel.agents.dynamic.d012_notification_leak_agent import (
    NotificationLeakAgent,
)
from sentinel.agents.dynamic.d013_third_party_pii_leak_agent import (
    ThirdPartyPiiLeakAgent,
)
from sentinel.agents.dynamic.d014_cookie_hardening_agent import (
    CookieHardeningAgent,
)
from sentinel.agents.dynamic.d015_implicit_intent_leak_agent import (
    ImplicitIntentLeakAgent,
)
from sentinel.agents.dynamic.data_in_transit_agent import DataInTransitAgent
from sentinel.agents.dynamic.improper_tls_agent import ImproperTLSAgent
from sentinel.agents.dynamic.runtime_crypto_agent import RuntimeCryptoAgent

__all__ = [
    "AccessibilityAbuseAgent",
    "AntiTamperCoverageAgent",
    "BiometricWeakAgent",
    "CertPinningBypassAgent",
    "ClipboardLeakAgent",
    "ContentProviderUriExposureAgent",
    "CookieHardeningAgent",
    "DataInTransitAgent",
    "DynamicCodeLoadingAgent",
    "DynamicReceiverExportAgent",
    "FileProviderTraversalAgent",
    "FlagSecureMissingAgent",
    "GraphqlPersistedQueryAgent",
    "IapBypassAgent",
    "IdorCandidateAgent",
    "ImplicitIntentLeakAgent",
    "ImproperTLSAgent",
    "JwtWeaknessAgent",
    "LocalSocketServerAgent",
    "NotificationLeakAgent",
    "PendingIntentMutableAgent",
    "RaceConditionCandidateAgent",
    "RuntimeCryptoAgent",
    "ScreenCaptureAgent",
    "SmsPermissionAbuseAgent",
    "StaticIvReuseAgent",
    "ThirdPartyPiiLeakAgent",
    "WebViewRuntimeAgent",
]
