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
- D_025 Background Location Request from Non-Foreground Context
- D_026 Insecure Android-Keystore Key Generation
- D_027 Zip-Slip / Archive Path Traversal
- D_028 Insecure RNG in Security Context
- D_029 Custom HostnameVerifier Accepts Mismatched Cert
- D_030 In-App Update Installs Unverified APK
- D_031 Unsafe JSON Deserialization
- D_032 SQLite Command Injection / Unparameterised Query
- D_033 Unsafe Reflection Invocation Chain
- D_034 Exported Activity Returns Sensitive Data Cross-App
- D_035 Sensitive Data Emitted to Log / Local File
- D_036 Background Clipboard Read
- D_037 Receiver Wiretaps Sensitive System Broadcasts
- D_038 Custom X509TrustManager Accepts Invalid Chain
- D_039 OkHttp HttpLoggingInterceptor Logs Body / Headers
- D_040 Biometric Crypto Bypassable via PIN Fallback
- D_041 Notification / Toast Flood
"""
from sentinel.agents.dynamic.cert_pinning_bypass_agent import CertPinningBypassAgent
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
from sentinel.agents.dynamic.d025_background_location_leak_agent import (
    BackgroundLocationLeakAgent,
)
from sentinel.agents.dynamic.d026_insecure_keystore_usage_agent import (
    InsecureKeystoreUsageAgent,
)
from sentinel.agents.dynamic.d027_zip_path_traversal_agent import (
    ZipPathTraversalAgent,
)
from sentinel.agents.dynamic.d028_insecure_random_runtime_agent import (
    InsecureRandomRuntimeAgent,
)
from sentinel.agents.dynamic.d029_insecure_hostname_verifier_agent import (
    InsecureHostnameVerifierAgent,
)
from sentinel.agents.dynamic.d030_in_app_update_insecure_agent import (
    InAppUpdateInsecureAgent,
)
from sentinel.agents.dynamic.d031_unsafe_json_deserialization_agent import (
    UnsafeJsonDeserializationAgent,
)
from sentinel.agents.dynamic.d032_sqlite_command_injection_agent import (
    SqliteCommandInjectionAgent,
)
from sentinel.agents.dynamic.d033_unsafe_reflection_invoke_agent import (
    UnsafeReflectionInvokeAgent,
)
from sentinel.agents.dynamic.d034_exported_activity_result_leak_agent import (
    ExportedActivityResultLeakAgent,
)
from sentinel.agents.dynamic.d035_local_file_log_leak_agent import (
    LocalFileLogLeakAgent,
)
from sentinel.agents.dynamic.d036_clipboard_listener_snoop_agent import (
    ClipboardListenerSnoopAgent,
)
from sentinel.agents.dynamic.d037_broadcast_wiretap_agent import (
    BroadcastWiretapAgent,
)
from sentinel.agents.dynamic.d038_insecure_trust_manager_runtime_agent import (
    InsecureTrustManagerRuntimeAgent,
)
from sentinel.agents.dynamic.d039_okhttp_logging_runtime_agent import (
    OkHttpLoggingRuntimeAgent,
)
from sentinel.agents.dynamic.d040_biometric_device_credential_fallback_agent import (
    BiometricDeviceCredentialFallbackAgent,
)
from sentinel.agents.dynamic.d041_notification_flood_agent import (
    NotificationFloodAgent,
)

# God Mode batch — see God_Mode.md
from sentinel.agents.dynamic.d042_deep_link_bomb import DeepLinkBombAgent
from sentinel.agents.dynamic.d043_hidden_api_hunter import HiddenApiHunterAgent

# Experimental tier batch
from sentinel.agents.dynamic.d044_biometric_replay import BiometricReplayAgent
from sentinel.agents.dynamic.d045_sqlite_prober import SqliteProberAgent
from sentinel.agents.dynamic.d046_race_condition_target import (
    RaceConditionTargetAgent,
)
from sentinel.agents.dynamic.d047_memory_dump import MemoryDumpTargetAgent
from sentinel.agents.dynamic.d048_webview_xss import WebViewXssAgent
from sentinel.agents.dynamic.d049_notification_snoop import (
    NotificationSnoopAgent,
)
from sentinel.agents.dynamic.d050_pinning_stress_test import (
    PinningStressTestAgent,
)
from sentinel.agents.dynamic.d051_service_leaker import ServiceLeakerAgent
from sentinel.agents.dynamic.d052_symbolic_intent import SymbolicIntentAgent
from sentinel.agents.dynamic.d053_side_channel import SideChannelAgent
from sentinel.agents.dynamic.d054_graphql_fuzzer import GraphqlFuzzerAgent
from sentinel.agents.dynamic.d055_native_heap import NativeHeapAgent
from sentinel.agents.dynamic.d056_biometric_timing import BiometricTimingAgent
from sentinel.agents.dynamic.d057_state_poisoner import StatePoisonerAgent
from sentinel.agents.dynamic.d058_websocket_injector import (
    WebSocketInjectorAgent,
)
from sentinel.agents.dynamic.d059_clipboard_hijack import ClipboardHijackAgent
from sentinel.agents.dynamic.d060_sensor_spoofing import SensorSpoofingAgent
from sentinel.agents.dynamic.d061_key_extractor import KeyExtractorAgent
from sentinel.agents.dynamic.d062_binder_bomb import BinderBombAgent
from sentinel.agents.dynamic.d063_provider_sqli import ProviderSqliAgent
from sentinel.agents.dynamic.d064_job_hijacker import JobHijackerAgent
from sentinel.agents.dynamic.d065_file_provider_fuzzer import (
    FileProviderFuzzerAgent,
)
from sentinel.agents.dynamic.d066_a11y_abuser import A11yAbuserAgent
from sentinel.agents.dynamic.d067_split_apk import SplitApkAgent
from sentinel.agents.dynamic.d068_wearable_bridge import WearableBridgeAgent
from sentinel.agents.dynamic.d069_autofill_sniffer import AutofillSnifferAgent
from sentinel.agents.dynamic.d070_pip_spy import PipSpyAgent
from sentinel.agents.dynamic.d071_twa_breaker import TwaBreakerAgent
from sentinel.agents.dynamic.d072_jni_shadow import JniShadowAgent
from sentinel.agents.dynamic.d073_pending_intent_esc import (
    PendingIntentEscalationAgent,
)
from sentinel.agents.dynamic.d074_scheme_confuser import SchemeConfuserAgent
from sentinel.agents.dynamic.d078_biometric_unwrapper import (
    BiometricCryptoUnwrapperAgent,
)
from sentinel.agents.dynamic.d081_backup_extractor import BackupDataExtractorAgent
from sentinel.agents.dynamic.d082_iap_spoofing import IapSpoofingAgent
from sentinel.agents.dynamic.d083_mobile_ssrf import MobileSsrfAgent
from sentinel.agents.dynamic.data_in_transit_agent import DataInTransitAgent
from sentinel.agents.dynamic.improper_tls_agent import ImproperTLSAgent
from sentinel.agents.dynamic.runtime_crypto_agent import RuntimeCryptoAgent

__all__ = [
    "AccessibilityAbuseAgent",
    "AntiTamperCoverageAgent",
    "BackgroundLocationLeakAgent",
    "BackupDataExtractorAgent",
    "BiometricCryptoUnwrapperAgent",
    "BiometricDeviceCredentialFallbackAgent",
    "BiometricWeakAgent",
    "BroadcastWiretapAgent",
    "CertPinningBypassAgent",
    "ClipboardLeakAgent",
    "ClipboardListenerSnoopAgent",
    "ContentProviderUriExposureAgent",
    "CookieHardeningAgent",
    "DataInTransitAgent",
    "DynamicCodeLoadingAgent",
    "DynamicReceiverExportAgent",
    "ExportedActivityResultLeakAgent",
    "FileProviderTraversalAgent",
    "FlagSecureMissingAgent",
    "GraphqlPersistedQueryAgent",
    "IapBypassAgent",
    "IapSpoofingAgent",
    "IdorCandidateAgent",
    "ImplicitIntentLeakAgent",
    "ImproperTLSAgent",
    "InAppUpdateInsecureAgent",
    "InsecureHostnameVerifierAgent",
    "InsecureKeystoreUsageAgent",
    "InsecureRandomRuntimeAgent",
    "InsecureTrustManagerRuntimeAgent",
    "JwtWeaknessAgent",
    "LocalFileLogLeakAgent",
    "LocalSocketServerAgent",
    "MobileSsrfAgent",
    "NotificationFloodAgent",
    "NotificationLeakAgent",
    "OkHttpLoggingRuntimeAgent",
    "PendingIntentMutableAgent",
    "PendingIntentEscalationAgent",
    "A11yAbuserAgent",
    "AutofillSnifferAgent",
    "BinderBombAgent",
    "BiometricReplayAgent",
    "BiometricTimingAgent",
    "ClipboardHijackAgent",
    "DeepLinkBombAgent",
    "FileProviderFuzzerAgent",
    "GraphqlFuzzerAgent",
    "HiddenApiHunterAgent",
    "JobHijackerAgent",
    "KeyExtractorAgent",
    "MemoryDumpTargetAgent",
    "NativeHeapAgent",
    "NotificationSnoopAgent",
    "PinningStressTestAgent",
    "PipSpyAgent",
    "ProviderSqliAgent",
    "RaceConditionCandidateAgent",
    "RaceConditionTargetAgent",
    "SensorSpoofingAgent",
    "ServiceLeakerAgent",
    "SideChannelAgent",
    "SplitApkAgent",
    "SqliteProberAgent",
    "StatePoisonerAgent",
    "JniShadowAgent",
    "TwaBreakerAgent",
    "WearableBridgeAgent",
    "WebSocketInjectorAgent",
    "WebViewXssAgent",
    "RuntimeCryptoAgent",
    "ScreenCaptureAgent",
    "SchemeConfuserAgent",
    "SmsPermissionAbuseAgent",
    "SqliteCommandInjectionAgent",
    "StaticIvReuseAgent",
    "SymbolicIntentAgent",
    "ThirdPartyPiiLeakAgent",
    "UnsafeJsonDeserializationAgent",
    "UnsafeReflectionInvokeAgent",
    "WebViewRuntimeAgent",
    "ZipPathTraversalAgent",
]
