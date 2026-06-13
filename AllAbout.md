# All About SENTINEL

Generated on 2026-06-13 from the current repository state.

SENTINEL is an autonomous, multi-agent Android mobile-application security platform. It can run from a CLI, a FastAPI backend, or a vanilla JS dashboard. The core flow is: ingest an APK, decompile and analyze it, run a large catalog of specialized agents, enrich findings with impact/compliance/learning/swarm context, optionally run dynamic analysis, optionally triage and verify, then produce structured findings and reports.

This document describes the whole project in depth: architecture, pipeline, agents, how agents work, system design, API, CLI, frontend, memory, LLM, verification, reporting, and present limitations.

---

## 1. Executive Summary

SENTINEL is built like a security-scanning operating system:

- **Input:** Android APKs, optional bug-bounty scope, optional profile, optional learning directory.
- **Recon:** JADX, apktool, androguard, manifest parsing, source/resource/native-library extraction.
- **Static agents:** Pattern, AST, manifest, resource, taint, supply-chain, crypto, platform, network, WebView, storage, privacy, business-logic checks.
- **Dynamic agents:** mitmproxy traffic analysis, Frida runtime hooks, ADB-driven app launch/proxy setup, runtime crypto/TLS/UI/IPC/SQLite/biometric/notification checks.
- **Memory:** SQLite findings/events, Chroma vector store, NetworkX graph store; Redis-backed production stub exists.
- **LLM:** Groq/Cerebras/Ollama router, private/local mode, triage, report narrative enrichment, remediation patch generation, swarm red/blue/purple analysis.
- **Enrichment:** financial impact scoring, compliance mapping, high-value-target URL extraction from `strings.xml`, learning feedback loop, exploit-chain correlation.
- **Outputs:** console tables, JSON scan summaries, report artifacts, API responses, frontend cards/tables, diff/regression gates, generated exploit/patch artifacts.

Current code-discovered totals:

- **135 concrete `BaseAgent` subclasses**
- **68 agents registered in the API SAST roster**
- **45 dynamic/DAST agents**
- **No duplicate agent IDs**
- **115 test files**

---

## 2. Repository Map

Important top-level paths:

| Path | Purpose |
|---|---|
| `sentinel/` | Main Python package |
| `sentinel/agents/` | All scanner agents grouped by domain |
| `sentinel/core/` | Orchestrator, scan context, findings, diffing, AST cache |
| `sentinel/api/` | FastAPI application, routes, scan runner |
| `sentinel/cli.py` | Main Click CLI entrypoint |
| `sentinel/tools/` | Wrappers for JADX, apktool, androguard, ADB, Frida, mitmproxy, native analysis |
| `sentinel/memory/` | Lightweight and production memory backends |
| `sentinel/llm/` | LLM providers, router, remediation generator |
| `sentinel/triage/` | LLM triage engine |
| `sentinel/verify/` | Active/passive verification framework |
| `sentinel/rag/` | Local knowledge base for OWASP MASVS/CWE context |
| `sentinel/impact/` | Financial impact scoring |
| `sentinel/compliance/` | Compliance mapping and audit rendering |
| `sentinel/learning/` | Per-app learning profile and feedback loop |
| `sentinel/swarm/` | Red/Blue/Purple adversarial swarm |
| `sentinel/remediation/` | AI patch suggestion workflow |
| `sentinel/exploit/` | Authorized exploit PoC generation |
| `sentinel/profiles/` | Scan profile presets such as banking/ecommerce/edu |
| `frontend/` | Vanilla HTML/CSS/JS dashboard |
| `docs/` | Existing focused technical docs |
| `tests/` | Unit, integration, and evaluation tests |
| `corpus/` | Local APK corpus used for evaluation and E2E tests |

---

## 3. System Architecture

```text
                         ┌─────────────────────────┐
                         │       User Surfaces      │
                         │ CLI / FastAPI / Frontend │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │      Scan Context        │
                         │ APK, workspace, scope,   │
                         │ sources, manifest, flags │
                         └────────────┬────────────┘
                                      │
                                      ▼
┌──────────┐  ┌─────────┐  ┌────────────┐  ┌──────────────┐  ┌─────────────┐
│ JADX     │  │ apktool │  │ androguard │  │ manifest     │  │ native/libs │
│ sources  │  │ res/xml │  │ bytecode   │  │ metadata     │  │ strings/ELF │
└────┬─────┘  └────┬────┘  └─────┬──────┘  └──────┬───────┘  └──────┬──────┘
     └─────────────┴─────────────┴────────────────┴────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │      Orchestrator        │
                         │ phases 0 → 8             │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │      BaseAgent run       │
                         │ applicable → analyze →   │
                         │ scope filter → persist   │
                         └───────┬────────┬────────┘
                                 │        │
                                 ▼        ▼
                    ┌────────────────┐ ┌─────────────────┐
                    │ Memory backend │ │ LLM/RAG/Swarm   │
                    │ events/findings│ │ triage/enrich   │
                    │ vector/graph   │ │ remediation     │
                    └───────┬────────┘ └────────┬────────┘
                            │                   │
                            ▼                   ▼
                    ┌──────────────────────────────────────┐
                    │ JSON, console, reports, API, frontend │
                    └──────────────────────────────────────┘
```

The project separates responsibilities cleanly:

- `ScanContext` is the shared state every phase and agent reads.
- `Orchestrator` controls phase order and error isolation.
- `BaseAgent` standardizes how all agents are started, skipped, failed, scoped, and persisted.
- `MemoryInterface` decouples agents from storage.
- Tool wrappers return structured `ToolResult` objects instead of throwing directly.
- CLI and API both call the same orchestration pipeline, but API uses `sentinel/api/scan_runner.py`.

---

## 4. Core Data Model

### `Finding`

Defined in `sentinel/core/finding.py`.

Each finding contains:

- `agent_id`
- `vuln_class`
- `severity`
- `confidence`
- `evidence`
- optional `cvss_vector`
- optional `owasp`
- optional `masvs`
- optional `poc`
- `recommendation`
- `session_id`
- optional `tenant_id`
- optional `financial_impact_score`
- `compliance_tags`
- `triage`
- `created_at`

`finding_id` is derived from `agent_id`, `vuln_class`, and sorted evidence. That means evidence-changing enrichment can affect identity unless the finding is carefully persisted/replaced. Recent scan-output fixes persist enriched findings and serialize full finding models in CLI JSON output.

### `BountyScope`

Also defined in `sentinel/core/finding.py`.

Scope contains:

- in-scope packages/domains
- out-of-scope packages/domains
- excluded vulnerability classes
- forbidden techniques
- reward ranges

`BaseAgent.run()` drops out-of-scope findings before saving them.

### `ScanContext`

Defined in `sentinel/core/scan_context.py`.

Important fields:

- `session_id`
- `apk_path`
- `workspace`
- `scope`
- `data_sensitivity`
- `apk_sha256`
- `apk_size_bytes`
- `decompiled_dir`
- `resources_dir`
- `manifest`
- `target_sdk`
- `permissions`
- `native_libs`
- `sources`
- `app_profile`
- `ast_cache`
- `active_replay`

`sources` is the shared multi-tool container. Common keys:

- `jadx`
- `androguard`
- `apktool`
- `mitmproxy`
- `frida`

---

## 5. Orchestrator Pipeline

The core pipeline lives in `sentinel/core/orchestrator.py`.

### Phase 0 — Ingestion

What happens:

- validates APK path
- computes SHA-256
- records APK size
- creates per-session workspace
- emits `phase.started` and `phase.completed`

### Phase 0.5 — Learning Profile

Triggered when `--learning-dir` is supplied.

What happens:

- loads or creates per-app learning profile
- attaches it to context
- lets future scans and verification outcomes influence risk/priority

### Phase 1 — Recon

Runs in parallel:

- JADX decompilation
- apktool resource decode
- androguard bytecode analysis
- manifest parsing

Outputs:

- Java/Kotlin-like source tree
- resources and manifest XML
- manifest dictionary
- permissions
- native library list
- tool result objects in `ctx.sources`

### Phase 1.5 — Profile + AST Cache

Main agent:

- `META_005 ProfilerAgent`

What happens:

- profiles framework type
- counts native libs
- estimates obfuscation tier
- detects API styles such as REST
- attaches shared AST cache
- narrows agent roster when profile indicates an agent class is useless

### Phase 2 — Static and Candidate Analysis

Runs the configured agent list concurrently through `BaseAgent.run()`.

Agent behavior:

1. emit `agent.started`
2. call `is_applicable()`
3. run `analyze()`
4. catch exceptions and emit `agent.failed`
5. filter findings by scope
6. save findings
7. emit `finding.emitted`
8. emit `agent.completed`

### Phase 2.5 — Deduplication

Uses `sentinel/core/dedup.py`.

Purpose:

- collapse overlapping bespoke-agent and Semgrep findings
- keep the strongest representative
- preserve merged evidence under dedup metadata

### Phase 2.6 — Visionary Enrichment

Hooks:

- `IMPACT_001`
- `COMPLIANCE_001`
- `LEARN_001`
- `SWARM_001` when enabled

What happens:

- attaches `financial_impact_score`
- attaches evidence `_impact`
- extracts high-value target endpoints from `strings.xml`
- adds compliance tags from YAML mappings
- optionally runs Red/Blue/Purple LLM swarm on High/Critical findings

Flags:

- default impact on
- `--no-impact` disables impact
- default compliance tags on
- `--no-compliance-tags` disables compliance
- `--tenant-plan free|pro|enterprise` changes financial multiplier
- `--learning-dir DIR` enables learning profile
- `--swarm` enables expensive swarm analysis

### Phase 3 — LLM Triage

Enabled unless `--no-triage`.

What happens:

- sends finding context to triage engine
- optionally includes RAG context unless `--no-rag`
- classifies findings into verified/filtered/uncertain/skipped style outcomes
- stores triage detail in finding evidence

Privacy:

- `--private` forces local LLM-only behavior where supported

### Phase 4 — Dynamic Analysis

Enabled by `--dynamic`.

What happens:

- finds connected ADB device
- checks or installs APK
- starts mitmproxy unless `--no-proxy`
- configures Android global proxy
- launches app
- captures traffic
- optionally runs Frida sub-phase
- clears proxy and force-stops app

### Phase 4.5 — Frida Runtime Hooks

Enabled by `--dynamic --frida`.

What happens:

- attaches to or spawns the target app
- injects bundled JS runtime hooks
- collects events such as crypto calls, TLS bypasses, WebView settings, clipboard reads, biometric prompts, SQLite queries, etc.
- stores `FridaCapture` in `ctx.sources["frida"]`

### Phase 7 — Correlation

Main agent:

- `COR_001 ExploitChainAgent`

What happens:

- looks for multi-finding exploit chains
- can turn multiple lower-severity signals into higher-risk correlated findings

### Phase 8 — Reporting

Main agent:

- `R_001 ReportGeneratorAgent`

What happens:

- reads findings from memory
- builds report data
- optionally enriches narrative with LLM
- writes Markdown, HTML, and JSON report artifacts
- emits a report meta-finding

Current behavior:

- report generation is best-effort
- it times out safely after 120 seconds rather than blocking scan completion

---

## 6. How Agents Work Internally

Every concrete agent subclasses `BaseAgent` from `sentinel/agents/base/base_agent.py`.

Required fields:

- `AGENT_ID`
- `VULN_CLASS`
- `PHASE`

Required methods:

- `is_applicable()`
- `analyze()`

Typical agent flow:

```text
agent = Agent(context, memory)
agent.run()
  ├─ publish agent.started
  ├─ if not is_applicable(): publish agent.skipped
  ├─ findings = analyze()
  ├─ filter findings by BountyScope
  ├─ save each finding
  ├─ publish finding.emitted
  └─ publish agent.completed
```

Agent input sources:

- `ctx.manifest`
- `ctx.permissions`
- `ctx.decompiled_dir`
- `ctx.resources_dir`
- `ctx.native_libs`
- `ctx.sources["androguard"]`
- `ctx.sources["mitmproxy"]`
- `ctx.sources["frida"]`
- `ctx.ast_cache`
- `ctx.app_profile`
- optional learning profile

Agent output:

- list of `Finding` objects

Agent failure behavior:

- one failed agent does not fail the scan
- exceptions are caught inside `BaseAgent.run()`
- failure events are stored in memory

---

## 7. Complete Current Agent Inventory

This table is generated from concrete `BaseAgent` subclasses in the codebase. `API SAST` means the agent is included in `sentinel/api/scan_runner.py` for API-launched static scans.

| ID | Category | Phase | Agent class | Vulnerability class | API SAST |
|---|---|---|---|---|---|
| `A_004` | auth | static | `HardcodedSecretsAgent` | Hardcoded Secret | yes |
| `A_008` | auth | Phase 3 | `BiometricBypassAgent` | Biometric Authentication Bypass | yes |
| `A_009` | auth | Phase 2 | `TapJackingAgent` | Tap-Jacking Exposure | yes |
| `A_010` | auth | Phase 2 | `SessionTokenInUrlAgent` | Session Token in URL | yes |
| `A_011` | auth | Phase 2 | `RefreshTokenReuseAgent` | Refresh Token Survives Logout | yes |
| `A_012` | auth | Phase 2 | `SessionFixationAgent` | Session Fixation | yes |
| `A_013` | auth | Phase 2 | `MagicLinkTokenAgent` | Magic Link Token Replay | yes |
| `A_001` | auth_storage | static | `InsecureAuthStorageAgent` | Insecure Auth Token Storage | yes |
| `C_001` | backup | static | `InsecureBackupAgent` | Insecure Backup | yes |
| `B_001` | business | Phase 2 | `RestIdorAgent` | REST API IDOR | yes |
| `B_003` | business | Phase 2 | `RaceConditionAgent` | Race Condition / TOCTOU | yes |
| `B_004` | business | Phase 2 | `IapBypassAgent` | In-App Purchase Bypass | yes |
| `B_005` | business | Phase 2 | `OAuthRedirectUriAgent` | OAuth redirect_uri Hijack | yes |
| `B_006` | business | Phase 2 | `UnsignedUpdateAgent` | Unsigned APK Install | yes |
| `B_007` | business | Phase 2 | `ClientSideAuthzAgent` | Client-Side Authorization Gate | yes |
| `B_008` | business | Phase 2 | `ClientSideTrustAgent` | Client-Side Trust Violation | no |
| `LOGIC_001` | business | Phase 2 | `TemporalLogicAgent` | Temporal / Hidden-Mode Logic | no |
| `N_001` | cert_pinning | static | `MissingCertPinningAgent` | Missing Certificate Pinning | yes |
| `F_001` | cloud | static | `FirebaseMisconfigAgent` | Firebase Misconfiguration | yes |
| `F_002` | cloud | Phase 2 | `FcmTokenDisclosureAgent` | FCM Token Disclosure | yes |
| `COR_001` | correlation | Phase 7 | `ExploitChainAgent` | Exploit Chain | no |
| `FL_001` | crossplatform | Phase 2 | `FlutterAgent` | FLUTTER_LIBAPP_AUDIT | yes |
| `FL_002` | crossplatform | Phase 2 | `FlutterMethodChannelAgent` | Flutter MethodChannel Surface | no |
| `RN_001` | crossplatform | Phase 2 | `ReactNativeAgent` | RN_BUNDLE_AUDIT | yes |
| `RN_002` | crossplatform | Phase 2 | `ReactNativeBridgeTaintAgent` | React Native Bridge Taint Surface | no |
| `C_005` | crypto | Phase 2 | `HardcodedCryptoKeysAgent` | Hardcoded Cryptographic Keys | yes |
| `C_006` | crypto | Phase 2 | `EcbModeAgent` | ECB Cipher Mode | yes |
| `C_007` | crypto | static | `WeakCryptoAgent` | Weak Cryptography | yes |
| `C_010` | crypto | Phase 2 | `SQLCipherKeyDerivationAgent` | Insecure SQLCipher Key Derivation | yes |
| `C_011` | crypto | Phase 2 | `KeystoreMisuseAgent` | Android Keystore Misuse | yes |
| `C_012` | crypto | Phase 2 | `AesGcmNonceReuseAgent` | AES-GCM Nonce Reuse | yes |
| `C_013` | crypto | Phase 2 | `JavaSerializationAgent` | Java Native Deserialization | yes |
| `C_014` | crypto | Phase 2 | `CbcPredictableIvAgent` | AES-CBC Predictable IV | yes |
| `C_015` | crypto | Phase 2 | `WeakPrngSeedAgent` | Weak PRNG Seed | yes |
| `C_016` | crypto | Phase 2 | `HashKdfAgent` | Hash Used as Key Derivation Function | yes |
| `C_017` | crypto | Phase 2 | `HardcodedCertFinderAgent` | Hardcoded Certificate/Key | no |
| `C_018` | crypto | Phase 2 | `CryptoConstantsAgent` | Roll-Your-Own Crypto | no |
| `C_002` | data_storage | static | `WorldReadableStorageAgent` | World-Readable Storage | yes |
| `A_003` | dynamic | dynamic | `RuntimeCryptoAgent` | Runtime Weak Cryptography | no |
| `D_001` | dynamic | dynamic | `ClipboardLeakAgent` | Clipboard Sensitive Data Leak | no |
| `D_002` | dynamic | dynamic | `FlagSecureMissingAgent` | Missing FLAG_SECURE on Sensitive Screen | no |
| `D_003` | dynamic | dynamic | `BiometricWeakAgent` | Insecure Biometric Prompt | no |
| `D_004` | dynamic | dynamic | `AntiTamperCoverageAgent` | Missing Anti-Tamper Coverage | no |
| `D_005` | dynamic | dynamic | `DynamicCodeLoadingAgent` | Dynamic Code Loading | no |
| `D_006` | dynamic | dynamic | `StaticIvReuseAgent` | Runtime IV / Key Reuse | no |
| `D_007` | dynamic | dynamic | `RaceConditionCandidateAgent` | Race-Condition / TOCTOU Candidate | no |
| `D_008` | dynamic | dynamic | `IapBypassAgent` | In-App Purchase Verification Bypass | no |
| `D_009` | dynamic | dynamic | `IdorCandidateAgent` | IDOR / Mass-Assignment Candidate | no |
| `D_010` | dynamic | dynamic | `JwtWeaknessAgent` | JWT Weakness | no |
| `D_011` | dynamic | dynamic | `WebViewRuntimeAgent` | Insecure WebView Runtime Configuration | no |
| `D_012` | dynamic | dynamic | `NotificationLeakAgent` | Sensitive Lockscreen Notification | no |
| `D_013` | dynamic | dynamic | `ThirdPartyPiiLeakAgent` | Sensitive Data Sent to Third-Party Endpoint | no |
| `D_014` | dynamic | dynamic | `CookieHardeningAgent` | Cookie Hardening Weakness | no |
| `D_015` | dynamic | dynamic | `ImplicitIntentLeakAgent` | Implicit Intent Sensitive Extras Leak | no |
| `D_016` | dynamic | dynamic | `AccessibilityAbuseAgent` | Accessibility / NotificationListener Abuse Pattern | no |
| `D_017` | dynamic | dynamic | `GraphqlPersistedQueryAgent` | GraphQL Persisted-Query Bypass | no |
| `D_018` | dynamic | dynamic | `SmsPermissionAbuseAgent` | SMS Permission / Retriever-API Abuse | no |
| `D_019` | dynamic | dynamic | `ScreenCaptureAgent` | Screen Capture / MediaProjection Pipeline | no |
| `D_020` | dynamic | dynamic | `DynamicReceiverExportAgent` | Dynamically-Registered Receiver Implicit Export | no |
| `D_021` | dynamic | dynamic | `PendingIntentMutableAgent` | PendingIntent Mutable at Runtime | no |
| `D_022` | dynamic | dynamic | `LocalSocketServerAgent` | Local-Socket Server Exposed Across App Boundary | no |
| `D_023` | dynamic | dynamic | `ContentProviderUriExposureAgent` | ContentProvider URI Exposure to Cross-UID Caller | no |
| `D_024` | dynamic | dynamic | `FileProviderTraversalAgent` | FileProvider Path-Traversal / Symlink Escape | no |
| `D_025` | dynamic | dynamic | `BackgroundLocationLeakAgent` | Background Location Request | no |
| `D_026` | dynamic | dynamic | `InsecureKeystoreUsageAgent` | Insecure Android-Keystore Key Generation | no |
| `D_027` | dynamic | dynamic | `ZipPathTraversalAgent` | Zip-Slip / Archive Path Traversal | no |
| `D_028` | dynamic | dynamic | `InsecureRandomRuntimeAgent` | Insecure RNG in Security Context | no |
| `D_029` | dynamic | dynamic | `InsecureHostnameVerifierAgent` | Custom HostnameVerifier Accepts Mismatched Cert | no |
| `D_030` | dynamic | dynamic | `InAppUpdateInsecureAgent` | In-App Update Installs Unverified APK | no |
| `D_031` | dynamic | dynamic | `UnsafeJsonDeserializationAgent` | Unsafe JSON Deserialization | no |
| `D_032` | dynamic | dynamic | `SqliteCommandInjectionAgent` | SQLite Command Injection / Unparameterised Query | no |
| `D_033` | dynamic | dynamic | `UnsafeReflectionInvokeAgent` | Unsafe Reflection Invocation Chain | no |
| `D_034` | dynamic | dynamic | `ExportedActivityResultLeakAgent` | Exported Activity Returns Sensitive Data Cross-App | no |
| `D_035` | dynamic | dynamic | `LocalFileLogLeakAgent` | Sensitive Data Emitted to Log / Local File | no |
| `D_036` | dynamic | dynamic | `ClipboardListenerSnoopAgent` | Background Clipboard Read | no |
| `D_037` | dynamic | dynamic | `BroadcastWiretapAgent` | Receiver Wiretaps Sensitive System Broadcasts | no |
| `D_038` | dynamic | dynamic | `InsecureTrustManagerRuntimeAgent` | Custom X509TrustManager Accepts Invalid Chain | no |
| `D_039` | dynamic | dynamic | `OkHttpLoggingRuntimeAgent` | OkHttp HttpLoggingInterceptor Logs Body / Headers | no |
| `D_040` | dynamic | dynamic | `BiometricDeviceCredentialFallbackAgent` | Biometric Crypto Bypassable via PIN Fallback | no |
| `D_041` | dynamic | dynamic | `NotificationFloodAgent` | Notification / Toast Flood | no |
| `N_003` | dynamic | dynamic | `ImproperTLSAgent` | Improper TLS Validation | no |
| `N_004` | dynamic | dynamic | `DataInTransitAgent` | Sensitive Data In Transit | no |
| `N_005` | dynamic | dynamic | `CertPinningBypassAgent` | Certificate Pinning Bypass | no |
| `A_007` | logging | static | `InsecureLoggingAgent` | Insecure Logging | yes |
| `META_001` | meta | static | `ObfuscationDetectorAgent` | Obfuscation Analysis | yes |
| `META_002` | meta | Phase 2 | `DebuggableManifestAgent` | Debuggable Release Build | yes |
| `META_005` | meta | Phase 1.5 | `ProfilerAgent` | Application Profile | no |
| `META_006` | meta | Phase 2 | `NativeInspectorAgent` | Native Library Inspection | no |
| `NL_001` | native | static | `NativeLibraryAgent` | Native Library Exposure | yes |
| `NL_002` | native | Phase 2 | `LoadLibraryTaintAgent` | Attacker-Controlled Native Library Load | yes |
| `K_001` | network | Phase 2 | `GraphQLGrpcAnalyzerAgent` | GraphQL / gRPC Schema Exposure | no |
| `N_002` | network | static | `CleartextTrafficAgent` | Cleartext Traffic | yes |
| `N_006` | network | Phase 4 | `ApiKeyLeakageAgent` | API Key Leakage | yes |
| `N_007` | network | Phase 2 | `GraphqlIntrospectionAgent` | GraphQL Introspection Enabled | yes |
| `N_008` | network | Phase 2 | `InsecureTrustManagerAgent` | Insecure TLS Validation | yes |
| `N_009` | network | Phase 2 | `WebViewDebugFlagAgent` | WebView Remote Debugging Enabled | yes |
| `N_010` | network | Phase 2 | `OkHttpLoggingAgent` | OkHttp Body / Header Logging | yes |
| `N_011` | network | Phase 4 | `GraphqlFuzzerAgent` | GraphQL Authorization Issues | yes |
| `N_012` | network | Phase 2 | `DnsLeakAgent` | DNS Leak | yes |
| `N_013` | network | Phase 2 | `InsecureWebSocketAgent` | Cleartext WebSocket | yes |
| `N_014` | network | Phase 2 | `HardcodedMtlsKeyAgent` | Hardcoded mTLS Client Certificate | yes |
| `N_015` | network | Phase 2 | `InternalEndpointScannerAgent` | Internal Endpoint Exposure | no |
| `IPC_001` | platform | static | `IpcExposureAgent` | Exposed IPC Component | yes |
| `I_001` | platform | Phase 2 | `ComponentCrossRefAgent` | Unprotected Exported Component | no |
| `P_001` | platform | Phase 2 | `DeepLinkHijackAgent` | Deep Link Hijacking | yes |
| `P_004` | platform | static | `ContentProviderIDORAgent` | Exposed Content Provider | yes |
| `P_005` | platform | Phase 2 | `ExcessivePermissionsAgent` | Excessive Manifest Permission | yes |
| `P_006` | platform | Phase 2 | `UnprotectedBroadcastAgent` | Unprotected Broadcast | yes |
| `P_007` | platform | Phase 2 | `ActivityResultLeakAgent` | Activity-Result Sensitive Data Leak | yes |
| `P_010` | platform | Phase 2 | `IntentRedirectAgent` | Intent Redirect | yes |
| `P_011` | platform | Phase 2 | `ReceiverChainHijackAgent` | Receiver Chain Hijack | yes |
| `P_012` | platform | Phase 2 | `MutablePendingIntentAgent` | Mutable PendingIntent | yes |
| `P_015` | platform | Phase 2 | `DeepLinkMapperAgent` | Deep Link Misconfiguration | no |
| `UI_001` | platform | Phase 2 | `ActivityGraphAgent` | Activity Auth-Bypass Path | no |
| `PRIV_001` | privacy | Phase 2 | `DataCollectionAuditorAgent` | Pre-Consent Sensitive Data Collection | no |
| `B_002` | random_gen | static | `InsecureRandomAgent` | Insecure Random | yes |
| `REFL_001` | reflection | Phase 2 | `ReflectionResolverAgent` | Unsafe Reflection | no |
| `R_001` | reporting | Phase 8 | `ReportGeneratorAgent` | VAPT Report Generation | no |
| `RES_001` | resilience | static | `AntiTamperAgent` | Anti-Tamper Posture | yes |
| `RES_002` | resilience | Phase 2 | `ResourceLeakAgent` | Resource Leak | no |
| `SG_001` | semgrep | static | `SemgrepAgent` | Pattern Match | yes |
| `STG_006` | shared_prefs | static | `InsecureSharedPrefsAgent` | Insecure SharedPreferences | yes |
| `STG_007` | shared_prefs | Phase 2 | `InsecureFileProviderAgent` | Insecure FileProvider Path Mapping | yes |
| `STG_008` | shared_prefs | Phase 2 | `ExternalStorageCredentialAgent` | Credential Write to External Storage | yes |
| `STG_009` | shared_prefs | Phase 2 | `BackupRulesAgent` | Insecure Auto-Backup Rules | yes |
| `STG_010` | shared_prefs | Phase 2 | `PlaintextPasswordFileAgent` | Plaintext Password File | yes |
| `STG_011` | shared_prefs | Phase 2 | `SqliteWalLeakAgent` | SQLite WAL / Journal Leak | yes |
| `TEST_001` | special | Phase 2 | `PipelineSmokeTestAgent` | Pipeline Smoke Test | yes |
| `SCA_001` | supply_chain | Phase 2 | `SCAAgent` | VULNERABLE_DEPENDENCY | yes |
| `SCA_002` | supply_chain | Phase 2 | `SDKPrivacyAuditorAgent` | Third-Party SDK Privacy Mismatch | no |
| `SCA_004` | supply_chain | Phase 2 | `MaliciousLibDetectorAgent` | Suspicious Third-Party Library Behavior | no |
| `TAINT_001` | taint | Phase 2 | `TaintAgent` | TAINT_FLOW | yes |
| `GESTURE_001` | ui | Phase 2 | `PatternLockAgent` | Custom Pattern-Lock Weakness | no |
| `C_004` | webview | static | `InsecureWebViewAgent` | Insecure WebView | yes |
| `C_008` | webview | Phase 2 | `JavaScriptInterfaceBridgeAgent` | JavaScript Interface Bridge | no |

---

## 8. Agent Categories and How They Work

### Authentication Agents

These detect weak authentication contracts:

- hardcoded secrets and credentials
- biometric bypass or weak biometric classes
- tapjacking exposure
- token leakage in URLs
- refresh-token reuse after logout
- session fixation
- magic-link replay

They work by scanning decompiled source, manifest metadata, runtime Frida events, shared preferences, and HTTP captures depending on the agent.

### Storage and Crypto Agents

These detect:

- insecure SharedPreferences
- world-readable storage
- backup exposure
- weak crypto primitives
- ECB/CBC misuse
- nonce reuse
- hardcoded keys/certs
- SQLCipher key derivation mistakes
- Java serialization
- weak PRNG seeds
- hash-as-KDF patterns

They use source scanning, tree-sitter/AST where needed, regex/string heuristics, manifest rules, androguard analysis, Semgrep rules, and runtime Frida crypto hooks.

### Platform and IPC Agents

These cover:

- exported components
- content providers
- deep links
- activity-result leaks
- pending intent mutability
- intent redirect
- unprotected broadcasts
- receiver chain hijack
- activity graph auth bypass

They primarily combine manifest metadata with source-level cross-reference. Stronger agents such as `P_010` use tree-sitter AST-style analysis for source-to-sink patterns.

### Network Agents

These cover:

- cleartext traffic
- missing cert pinning
- insecure trust managers
- WebView debug flags
- OkHttp logging
- GraphQL introspection/fuzzing
- DNS leaks
- insecure WebSockets
- hardcoded mTLS client certs
- internal endpoint exposure
- API key leakage

Static network checks inspect source/resources/manifest. Dynamic network checks use `MitmproxyCapture` and runtime events.

### Dynamic/DAST Agents

Dynamic agents consume:

- `ctx.sources["mitmproxy"]`
- `ctx.sources["frida"]`
- Android runtime events
- captured request/response flows

They check runtime-only issues: clipboard leaks, missing `FLAG_SECURE`, biometric fallback, dynamic code loading, runtime IV reuse, IDOR/race candidates, WebView runtime settings, sensitive notification leaks, third-party PII leakage, cookie flags, implicit intent leaks, accessibility abuse, SMS abuse, screen capture, local socket servers, provider URI exposure, FileProvider traversal, insecure Keystore generation, Zip Slip, runtime RNG, unsafe reflection, SQLite command injection, trust-manager behavior, and notification flooding.

### Cross-Platform Agents

React Native and Flutter agents inspect:

- JS bundles
- Hermes indicators
- bridge APIs
- AsyncStorage usage
- cleartext URLs
- embedded secrets
- Flutter `libapp.so` strings
- MethodChannel exposure

Flutter deeper Dart decompilation is not currently represented as a full semantic Dart analysis; existing Flutter analysis is string/surface oriented.

### Supply-Chain Agents

Supply-chain agents detect:

- vulnerable dependencies
- privacy-sensitive SDK/package combinations
- suspicious third-party library behavior graphs

`SCA_004` can emit NetworkX-shaped node-link evidence that can later be visualized in the frontend.

### Meta, Reporting, Correlation, Special Agents

- `META_001` analyzes obfuscation.
- `META_002` flags debuggable builds.
- `META_005` profiles app/framework/API shape and influences agent selection.
- `META_006` inspects native libraries.
- `COR_001` finds exploit chains.
- `R_001` generates VAPT reports.
- `TEST_001` verifies the pipeline can emit and persist a finding.

---

## 9. CLI Features

The CLI is implemented in `sentinel/cli.py`.

Main commands:

| Command | Purpose |
|---|---|
| `sentinel serve` | Start FastAPI backend |
| `sentinel scan APK` | Run a full scan |
| `sentinel scope parse` | Parse bug-bounty scope |
| `sentinel agents` | List available agents |
| `sentinel status` | Print local environment/config status |
| `sentinel diff` | Compare two APK scans for regression gating |
| `sentinel rag build/query/stats` | Build and query local RAG knowledge |
| `sentinel verify` | Verify findings from JSON |
| `sentinel exploit generate` | Generate authorized exploit PoC artifacts |

Important scan flags:

| Flag | Meaning |
|---|---|
| `--static-only` | Refuse dynamic/frida options |
| `--private` | Force local/private LLM behavior |
| `--no-triage` | Disable LLM triage |
| `--no-rag` | Disable RAG context |
| `--dynamic` | Enable ADB/mitmproxy dynamic analysis |
| `--frida` | Enable runtime Frida hooks |
| `--frida-spawn` | Spawn under Frida instead of attaching |
| `--no-proxy` | Skip mitmproxy/device proxy setup |
| `--keep-workspace` | Keep decompiled workspace |
| `--profile` | Use scan profile preset or custom JSON |
| `--active-replay` | Allow live HTTP verification replays |
| `--generate-patch` | Generate AI remediation diff suggestions |
| `--no-impact` | Disable impact scoring |
| `--no-compliance-tags` | Disable compliance tags |
| `--learning-dir` | Enable learning profile |
| `--tenant-plan` | free/pro/enterprise impact multiplier |
| `--swarm` | Run Red/Blue LLM swarm on high-risk findings |

---

## 10. FastAPI Backend

The API app is in `sentinel/api/app.py`.

Routers:

- `auth`
- `scans`
- `agents`
- `scope`
- `reports`

### Auth

Implemented in `sentinel/api/routes/auth.py`, `sentinel/auth/jwt_auth.py`, and `sentinel/auth/api_keys.py`.

Features:

- user registration
- login
- refresh
- `/me`
- API key creation/list/delete
- hashed API keys
- JWT secret configurable through settings
- optional dev auth bypass only when explicitly enabled

### Scans API

Implemented in `sentinel/api/routes/scans.py` and `sentinel/api/scan_runner.py`.

Endpoints:

- `POST /scans`
- `GET /scans`
- `GET /scans/{session_id}`
- `GET /scans/{session_id}/findings`
- `GET /scans/{session_id}/result`
- `DELETE /scans/{session_id}`

Behavior:

- accepts APK upload
- validates options
- bounds dynamic/frida durations
- launches background in-process scan job
- tracks progress in `ScanRegistry`
- expands API SAST roster to 68 static agents
- supports cleanup of uploaded/decompiled artifacts unless retained

### Agents API

Implemented in `sentinel/api/routes/agents.py`.

Endpoints:

- `GET /agents`
- `GET /agents/{agent_id}`

Provides agent metadata for frontend and consumers.

### Scope API

Implemented in `sentinel/api/routes/scope.py` and `sentinel/scope/scope_parser.py`.

Features:

- parse URL/file/text scope
- authenticated API route
- local file mode restricted to workspace
- SSRF protection for URLs
- blocks private/loopback/link-local/multicast/reserved/unspecified IPs
- validates redirects

### Reports API

Implemented in `sentinel/api/routes/reports.py`.

Features:

- authenticated report listing
- report file retrieval
- path traversal protection
- workspace-root enforcement

---

## 11. Memory System

Interface: `sentinel/memory/interface.py`.

### Lightweight Memory

Implemented in `sentinel/memory/lightweight.py`.

Components:

- SQLite for events and findings
- Chroma for semantic search
- NetworkX for graph relationships

Stores:

- events
- findings
- embeddings
- graph nodes
- graph edges

Useful for local CLI and development.

### Production Memory

Implemented in `sentinel/memory/production.py`.

Intended components:

- Redis for event/finding working memory
- Qdrant for vector memory
- Neo4j for graph memory

The production backend has partial/stubbed behavior and tests around Redis behavior.

### Memory as Event Bus

The scan emits structured events:

- `scan.started`
- `phase.started`
- `phase.completed`
- `phase.failed`
- `agent.started`
- `agent.skipped`
- `agent.failed`
- `agent.completed`
- `finding.emitted`
- `scan.completed`

These events power status, progress, debugging, and future UI streaming.

---

## 12. Tooling Layer

Tool wrappers are in `sentinel/tools/`.

| Tool wrapper | Purpose |
|---|---|
| `jadx.py` | Decompile APK into Java-like source |
| `apktool.py` | Decode resources and manifest XML |
| `androguard_analyzer.py` | Bytecode/string/class analysis |
| `manifest.py` | Manifest parsing and normalized metadata |
| `adb_runner.py` | Device discovery, install, proxy, app launch, force-stop |
| `mitmproxy_runner.py` | HTTP/HTTPS capture through mitmproxy |
| `frida_runner.py` | USB Frida attach/spawn, JS hook loading, event capture |
| `native_analyzer.py` | Native ELF/string analysis |
| `result.py` | Standard `ToolResult` success/failure object |

Tool wrappers are intentionally crash-proof. They return data/error objects so one failing tool does not kill a scan.

---

## 13. LLM, RAG, Triage, Swarm, and Remediation

### LLM Router

Implemented in `sentinel/llm/router.py`.

Providers:

- Groq
- Cerebras
- Ollama

The router supports:

- fallback between providers
- circuit-breaker style handling
- private/local mode where local-only behavior is required

### RAG

Implemented in `sentinel/rag/`.

Data includes:

- OWASP Mobile
- MASVS
- CWE subset

RAG is used to improve triage/report context and can be built/query/stats from CLI.

### Triage

Implemented in `sentinel/triage/`.

Purpose:

- reduce false positives
- add explanations
- attach `_triage` evidence
- classify findings for report visibility

### Swarm

Implemented in `sentinel/swarm/`.

Modes:

- Red agent: attacker/exploitation narrative
- Blue agent: defensive rule/signature/remediation perspective
- Purple agent: business-impact narrative, affected stakeholders, blast radius

Triggered by:

- `--swarm`

Purple support exists in the swarm model/UI; CLI exposure for explicitly toggling Purple can be further refined if cost control is needed.

### Remediation

Implemented in:

- `sentinel/llm/remediation.py`
- `sentinel/remediation/`

Feature:

- `--generate-patch`
- generates unified diff suggestions for verified findings
- never auto-applies patches
- intended for human review

---

## 14. Verification and Exploit Generation

### Verification

Implemented in `sentinel/verify/`.

Key idea:

- a candidate finding can be checked by a verifier
- verifiers can use static context, mitmproxy captures, Frida captures, and optional active replay
- active replay is opt-in through `--active-replay`

Verifiers include:

- static verification
- mitm verification
- Frida verification
- active replay verification

`sentinel verify findings.json --learning-dir DIR` can record outcomes into the feedback loop.

### Exploit Generation

Implemented in `sentinel/exploit/`.

Purpose:

- generate authorized exploit PoC artifacts from verified findings
- support target package/finding filtering
- require explicit user authorization context

---

## 15. Frontend Architecture

Frontend lives in `frontend/`.

It is a vanilla HTML/CSS/JS single-page app:

- `frontend/index.html` landing page
- `frontend/app.html` dashboard shell
- `frontend/js/router.js` hash router
- `frontend/js/api.js` backend API wrapper
- `frontend/js/app-shell.js` shell bootstrap
- `frontend/js/pages/` route pages
- `frontend/js/components/` reusable UI components
- `frontend/css/` styling

Main pages:

- dashboard
- scans
- scan detail
- projects
- agents
- reports
- RAG
- verify
- exploit
- settings
- docs
- history

Important frontend components:

- findings table
- impact badge/card
- compliance panel
- profile summary
- scan modal
- severity badge
- swarm panel
- code block
- sidebar/topbar

The frontend supports:

- upload scan modal
- API-backed scan listing/details
- findings expansion
- compliance badges
- impact badges
- swarm Red/Blue/Purple display
- static mock data fallback/demo surfaces

---

## 16. SAST Design

SAST uses several layers:

1. **Manifest checks**
   - permissions
   - exported components
   - backup/debuggable flags
   - deep links

2. **Source scanning**
   - regex/string heuristics
   - source context extraction
   - class/file-level evidence

3. **AST/Tree-sitter checks**
   - taint flow
   - intent redirect
   - Java structural analysis

4. **Semgrep**
   - YAML rules under `sentinel/agents/semgrep/rules/`
   - WebView, TLS, crypto, storage, SQL, command execution, pending intent checks

5. **Androguard**
   - bytecode/string/class metadata
   - fallback when source decompilation is incomplete

6. **Supply chain**
   - dependency/library detection
   - CVE/offline OSV-style metadata
   - suspicious behavior graph evidence

7. **Cross-platform scanning**
   - React Native JS bundle
   - Flutter `libapp.so` string audit

API SAST currently registers 68 static agents. CLI static scan includes a broader orchestration path and optional profile-based narrowing.

---

## 17. DAST Design

DAST has two runtime sources:

### mitmproxy

Captured into `MitmproxyCapture`:

- request method
- URL
- scheme
- host/path
- request headers/body
- response status/headers/body
- TLS failure indicator
- timestamps

Used by agents such as:

- `N_003`
- `N_004`
- `D_007`
- `D_009`
- `D_013`
- `D_014`
- `D_017`

### Frida

Captured into `FridaCapture`:

- hook events
- target package
- target PID
- script errors
- duration

Runtime hook kinds cover:

- crypto cipher/digest/key generation
- TLS pinning checks/bypasses
- clipboard reads/writes
- window flags
- biometric prompts
- root/emulator/debugger/signature checks
- dynamic code loading
- billing/IAP
- WebView settings
- notifications
- intents
- accessibility
- SMS
- screen capture
- dynamic receivers
- pending intents
- local sockets
- content providers
- FileProvider paths
- location
- Keystore
- zip entries
- RNG
- hostname verifier
- package installer
- JSON deserialization
- SQLite
- reflection
- logs
- trust managers
- OkHttp logging

DAST is intentionally opt-in because it changes device state and can touch live backends.

---

## 18. Scope and Security Controls

Security hardening currently present:

- authenticated scan/scope/report API routes
- configurable JWT secret
- API keys stored hashed, displayed masked after creation
- restricted local file scope parsing
- SSRF-safe scope URL parsing
- strict CORS origin list from settings
- path traversal checks on report retrieval
- bounded dynamic/frida duration options
- cleanup of uploaded APK/decompiled artifacts for web scans
- private mode can prevent cloud LLM usage
- scope filtering before findings persist
- pydantic `extra="forbid"` models

Important privacy note:

- Dynamic captures, decompiled source, mitmproxy flows, and Frida logs can contain secrets. Use `--private`, short dynamic durations, and cleanup defaults when scanning sensitive apps.

---

## 19. Reports and Outputs

Output channels:

- Rich console summary
- Rich findings table
- JSON file from `--output`
- API `/scans/{id}/result`
- API `/scans/{id}/findings`
- report markdown/html/json artifacts from `R_001`
- frontend scan detail pages
- diff/regression gate output
- remediation patch files
- exploit PoC artifacts

The CLI JSON writer serializes full `Finding` models and includes `finding_id`, so downstream automation can access:

- `financial_impact_score`
- `compliance_tags`
- `triage`
- `evidence._impact`
- `evidence._swarm`
- all standard finding fields

---

## 20. Profiles

Profiles live in `sentinel/profiles/`.

Built-in profile data:

- `banking.json`
- `ecommerce.json`
- `edu.json`

Profiles can reorder/prioritize agent execution without changing fundamental coverage. They let the same scanner lean harder into relevant risks for banking, ecommerce, or education apps.

---

## 21. Compliance System

Implemented in `sentinel/compliance/`.

Features:

- YAML mapping from agent/vulnerability classes to controls
- compliance tags attached to findings
- audit markdown rendering
- framework order includes GDPR, HIPAA, PCI-DSS, SOC2, ISO27001, DPDP, CCPA

The mapping is intentionally deterministic and offline.

---

## 22. Impact System

Implemented in `sentinel/impact/`.

Features:

- financial impact estimates
- tenant-plan multiplier
- high-value target endpoint extraction from `strings.xml`
- `_impact` evidence block
- asset-category augmentation

Impact score is advisory. It should guide triage priority, not replace human severity review.

---

## 23. Learning System

Implemented in `sentinel/learning/`.

Features:

- per-app profile store
- scan-start recording
- verify-outcome feedback loop
- repeated scans can become smarter over time

CLI integration:

- `sentinel scan app.apk --learning-dir ./data/learning`
- `sentinel verify scan.json --learning-dir ./data/learning`

---

## 24. Testing and Validation

The repository currently has 115 test files.

Important suites:

- core model tests
- API tests
- scope parser tests
- CLI scan tests
- SAST agent tests
- DAST agent tests
- Frida loader tests
- RAG tests
- triage tests
- verification tests
- exploit tests
- remediation tests
- profile tests
- visionary wiring/delta tests
- integration real-APK phase tests

Recent validations performed in this working tree:

- agent registry smoke: 135 concrete agents, no duplicate IDs
- API SAST roster: 68 agents
- SAST suite: 350 tests passed
- DAST suite: 288 tests passed
- visionary/orchestrator affected tests: 46 tests passed
- real APK scan against `corpus/InsecureBankv2.apk`: completed, 153 findings, 153 impact scores in JSON output

---

## 25. Current Known Gaps and Practical Limits

Known gaps from current code/design:

- Full iOS support is not implemented.
- Dynamic scans require a configured Android device, ADB, mitmproxy certificate trust, and optionally Frida server.
- Report generation can be slow because narrative enrichment may call LLMs; it is now timeout-bounded.
- Purple swarm exists in model/UI, but CLI exposure for separate Purple toggling is not yet its own dedicated flag.
- SCA_004 graph evidence is generated as data, but full force-directed visualization is not implemented in the frontend.
- Production memory backend is not as mature as the local SQLite/Chroma/NetworkX backend.
- Flutter analysis is mostly `libapp.so` string-level audit, not full Dart semantic recovery.
- Semgrep/SAST coverage is strong but still pattern-driven; false positives and false negatives require human review.
- Live active replay must only be used with explicit authorization.
- Some frontend data files still include mock/demo data while API-backed paths exist.

---

## 26. How to Read or Extend the Project

Start here:

1. `sentinel/core/orchestrator.py` — pipeline control
2. `sentinel/core/finding.py` — finding/scope schema
3. `sentinel/core/scan_context.py` — shared state
4. `sentinel/agents/base/base_agent.py` — agent contract
5. `sentinel/cli.py` — user-facing CLI
6. `sentinel/api/scan_runner.py` — API scan job runner
7. `sentinel/tools/` — external tool wrappers
8. `sentinel/memory/lightweight.py` — local persistence
9. `sentinel/agents/` — actual detection logic
10. `tests/unit/` — expected behavior

To add a new agent:

1. create a subclass of `BaseAgent`
2. set `AGENT_ID`, `VULN_CLASS`, and `PHASE`
3. implement `is_applicable()`
4. implement `analyze()`
5. emit `Finding` objects through `_make_finding()`
6. add unit tests
7. register it in CLI/API roster if it should run by default
8. add compliance/impact mappings if appropriate
9. add frontend metadata if needed

Good agent design rules:

- fail closed and return `[]` when input source is absent
- cap file scanning and finding counts
- provide precise evidence with file/path/line/context when possible
- avoid network calls unless explicit and authorized
- use `ctx.sources` instead of invoking tools repeatedly
- keep evidence small enough for pydantic limits and UI rendering
- do not leak secrets in recommendations/logs

---

## 27. Feature Checklist

Present features:

- APK ingestion
- SHA-256 hashing
- per-session workspace
- JADX decompilation
- apktool resource decode
- androguard analysis
- manifest parsing
- AST cache
- app profiling
- static SAST agents
- Semgrep rule agent
- tree-sitter taint agent
- supply-chain scanning
- cross-platform React Native scanning
- cross-platform Flutter string audit
- dynamic mitmproxy capture
- Frida runtime hooks
- ADB device control
- LLM triage
- RAG build/query/stats
- financial impact scoring
- compliance tagging
- learning profiles
- Red/Blue/Purple swarm data model
- exploit-chain correlation
- report generation
- JSON output
- API scan lifecycle
- API auth and API keys
- report download API
- scope parsing API
- agent catalogue API
- web dashboard
- scan upload modal
- findings table
- impact/compliance/swarm UI components
- diff/regression gate
- remediation patch generation
- verification engine
- exploit PoC generation
- profile presets
- local memory backend
- production memory scaffolding
- CI workflow

---

## 28. Bottom Line

SENTINEL is not just a script that greps APKs. It is a structured mobile-security platform with:

- a phase-based orchestrator
- a broad agent ecosystem
- static and dynamic analysis
- LLM-assisted triage/reporting/remediation
- memory and learning primitives
- compliance and business-impact enrichment
- API and frontend surfaces
- a growing verification/exploit-generation layer

The strongest parts today are the Android static/dynamic agent catalog, orchestration, local memory, CLI workflow, and unit coverage. The main areas to keep hardening are production backend maturity, long-running report performance, visual graph UX, deeper Flutter/Dart semantics, and real-device DAST ergonomics.
