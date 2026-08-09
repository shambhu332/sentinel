# SENTINEL — Complete Technical Reference

> Generated from source inspection on 2026-07-21.
> Every claim in this document is grounded in a specific file path and line
> number. When you disagree with a claim, open the referenced file and
> reconcile the two; do not trust the prose over the code.

---

## 1. Executive Summary

**SENTINEL** is an autonomous Android APK security scanner built as a
10-phase pipeline that fuses static (JADX + Androguard + apktool + Semgrep
+ ~200 bespoke agents), dynamic (mitmproxy + Frida + ADB + optional UI
driver), symbolic/fuzz (AFL++ over JNI harnesses), and LLM-assisted layers
(RAG-backed triage, deterministic narrative enrichment, proof-gate
classification). It runs from a CLI (`sentinel/cli.py`), a FastAPI service
(`sentinel/api/app.py`), or a Dockerised worker, and emits VAPT-grade
Markdown, HTML, JSON and SARIF 2.1.0 reports along with runnable PoC
artifacts (`sentinel/agents/reporting/r001_report_agent.py:162`).

**Maturity level.** Production-beta.
* The core pipeline is defensively crash-proofed — every phase is wrapped
  in `try/except` with warnings surfaced to `ScanResult.warnings`
  (`sentinel/core/orchestrator.py:222-437`), and duplicate `AGENT_ID`s
  hard-fail at construction to prevent silent finding collisions
  (`sentinel/core/orchestrator.py:167-187`).
* Real production concerns are wired in: Postgres RLS-based tenant
  isolation on `Finding.tenant_id` (`sentinel/core/finding.py:118-121`),
  circuit-breaker LLM router with local-first priority
  (`sentinel/llm/router.py:59-118, 382-478`), Redis-backed determinism
  cache, JWT + API key auth (`sentinel/auth/`), Alembic migrations, a
  device pool (`sentinel/devices/pool.py`), credential manager, scope
  parser (`sentinel/scope/scope_parser.py`), and dedup + delta stores.
* Known limitations: several agents have duplicate IDs across dirs (e.g.
  `C_001` in both `crypto/c_001_ecb_mode.py` and `crypto/c005_hardcoded_keys.py`
  variants — see §4), a "\_ai" duplicate wave still lives alongside the
  canonical ID (`sentinel/agents/auth/a_001_ai.py` vs
  `a_001_hardcoded_creds.py`); the smoke `TEST_001` agent (`special/`)
  is still the default when no explicit list is passed
  (`sentinel/core/orchestrator.py:148`); the fuzz phase is opt-in and
  degrades silently if AFL++ is not installed
  (`sentinel/core/orchestrator.py:1993-2030`).

**Volumetric snapshot.**
* Python LOC (excluding worktrees / caches): **~123,663** across
  **612** `.py` files (`find` + `wc -l` on the tracked tree).
* Agent files: **209** across **31** category directories
  (`sentinel/agents/*`), of which ~183 declare a canonical `AGENT_ID`
  (the rest are base classes, drivers, or duplicated `_ai` variants).
* Tests: **178** Python test modules under `tests/` (unit +
  integration + parity).
* Orchestrator size: **2,134 LOC** in one file
  (`sentinel/core/orchestrator.py`) — the single largest module.
* Report enrichment recipes: **2,187 LOC** of deterministic template
  overrides in `sentinel/agents/reporting/enrich.py`.

---

## 2. Complete System Architecture

### 2.1 Component diagram

```
                            ┌──────────────────────┐
                            │       Frontend       │  frontend/js/*
                            │  (vanilla ESM SPA)   │
                            └─────────┬────────────┘
                                      │ REST/SSE
┌───────────────────────────────────────────────────────────────────────┐
│                          FastAPI HTTP layer                           │
│  sentinel/api/app.py  →  routes: auth, scans, reports, agents,        │
│                                  devices, scope                       │
│                        middleware: rate_limit, JWT, RBAC              │
└───────────────────────────────────────────────────────────────────────┘
              │                        │                       │
              ▼                        ▼                       ▼
     ┌────────────────┐       ┌────────────────┐      ┌────────────────┐
     │   CLI runner   │       │  Scan runner   │      │  Report server │
     │  sentinel/cli  │       │  api/scan_...  │      │  api/routes/…  │
     └───────┬────────┘       └───────┬────────┘      └────────────────┘
             └────────────┬───────────┘
                          ▼
              ┌────────────────────────┐
              │      Orchestrator      │  sentinel/core/orchestrator.py
              │   (10-phase pipeline)  │  Orchestrator.run() :189
              └───────┬────────────────┘
                      │ dispatches
        ┌─────────────┼────────────┬──────────────┬────────────┐
        ▼             ▼            ▼              ▼            ▼
     Recon tools   Agents       Triager       Exploit       Report
     (jadx,       (~200        LLMTriager    ExploitDriver R_001
      androguard, BaseAgent     +HON_001     PoCGenerator  builder,
      apktool,    subclasses)   +RAG         drivers.py    enrich,
      manifest)                                             templates
        │             │             │              │            │
        └─────────────┴──────┬──────┴──────────────┴────────────┘
                             ▼
                    ┌─────────────────┐    ┌──────────────────┐
                    │  MemoryInterface│───►│  T1: in-proc     │
                    │  interface.py   │    │  T2: SQLite/PG   │
                    │                 │    │  T3: Qdrant/N4j  │
                    └─────────────────┘    └──────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  LLM Router     │  local-vllm → groq → cerebras
                    │  llm/router.py  │  → ollama, circuit-broken
                    └─────────────────┘
```

### 2.2 Data flow

```
APK  ─►  Phase 0 Ingestion (hash, workspace)
       ─►  Phase 1 Recon (JADX ∥ Androguard ∥ apktool ∥ manifest)   [parallel]
       ─►  Phase 1.5 Profile + AST cache (META_005 → skip_prefixes)
       ─►  Phase 4 DAST (mitmproxy → device proxy → UI driver ∥ Frida hooks)
       ─►  Phase 2 Agents (parallel, ~200 registered)
             │
             ├─►  Phase 2.5 Dedup (per-cluster survivor)
             └─►  Phase 2.6 Enrich (IMPACT_001 → COMPLIANCE_001 → SWARM_001?)
       ─►  Phase 4.6 SAST→DAST replay (ADB verifiers + legacy Frida)
       ─►  Phase 4.7 AFL++ fuzz over JNI harnesses     [opt-in]
       ─►  Phase 3 LLM triage (verify | filter | uncertain | skipped)
       ─►  Phase 7 Correlation (COR_001 chain detection)
       ─►  Phase 7.5 Active exploitation (ExploitDriver + PoCGenerator)
       ─►  Phase 7.6 Proof gate (candidate → runtime_verified → bounty_ready)
       ─►  Phase 8 Report (R_001 → md + html + json + sarif + PoC studio)
       ─►  ScanResult persisted + `scan.completed` event published
```

### 2.3 Three-tier memory architecture

`sentinel/memory/interface.py:18` defines the `MemoryInterface`
(`save_finding`, `get_findings`, `publish_event`, `subscribe`,
embeddings). Implementations:

| Tier | Purpose                           | Dev backend                             | Prod backend                                     |
|------|------------------------------------|------------------------------------------|--------------------------------------------------|
| T1   | Hot per-session state, event bus  | `memory/lightweight.py` (in-proc dict + asyncio.Queue) | Redis Streams inside `memory/production.py`      |
| T2   | Durable finding storage           | SQLite via `memory/postgres.py` fallback | Postgres with RLS on `tenant_id` (`core/finding.py:118`) |
| T3   | Vector / graph memory             | none (no-op)                            | Qdrant (`memory/qdrant_backend.py`) + Neo4j (`memory/neo4j_backend.py`) |

`memory/composite.py` glues the three tiers under a single interface;
`memory/production.py:62` wires them up for cloud deployments.
Embeddings are produced by `memory/embedding.py`.

### 2.4 LLM router failover chain & circuit breaker

Order enforced in `sentinel/llm/router.py:400-405`:

1. **local-vllm** — OpenAI-compatible endpoint at
   `SENTINEL_LOCAL_LLM_URL`, model `SENTINEL_LOCAL_LLM_MODEL`
   (`router.py:122-183`).
2. **groq** — Llama 3.3 70B, `GROQ_API_KEY` (`router.py:185-256`).
3. **cerebras** — Llama 3.3 70B, `CEREBRAS_API_KEY`
   (`router.py:258-329`).
4. **ollama** — always-on local fallback at `OLLAMA_HOST`, default model
   `qwen2.5-coder:7b-instruct-q4_K_M` (`router.py:331-378`).

Circuit breaker thresholds (`router.py:59-60`):
`CIRCUIT_BREAK_THRESHOLD = 3` consecutive failures trips the breaker;
`CIRCUIT_RESET_SECONDS = 120`. A hard `disable_for_session()`
(`router.py:115-117`) pushes the breaker out 86,400s (24h) for
categorically-broken providers (e.g. Cerebras "Model Not Available"
404). `_eligible_providers()` (`router.py:414-425`) filters providers
whose breaker is open or that fail `is_enabled()`; `--private` mode
excludes cloud entirely.

Deterministic (`temperature=0.0`) calls are cached in Redis via
`sentinel/cache/redis_cache.py` — the router hashes the message list +
model + temperature and short-circuits identical repeat calls
(`router.py:444-449, 463`).

### 2.5 Crash-proof design principles

* **Tool wrappers return `ToolResult`, never raise.** See
  `sentinel/tools/result.py:29` and every `_run_*` in the orchestrator
  (e.g. `_run_jadx` `orchestrator.py:589-595` catches `Exception` and
  returns `None`).
* **Every recon tool runs in parallel via
  `asyncio.gather(return_exceptions=True)`** (`orchestrator.py:506-509`).
* **Every optional phase is `try/except`ed** — see phases 3, 4, 4.6,
  4.7, 7, 7.5, 7.6, 8 all wrapping their body and appending to
  `result.warnings` instead of propagating.
* **Duplicate AGENT_ID startup check** (`orchestrator.py:167-187`)
  turns a silent data-loss bug into a loud crash.
* **Phase 8 has a wall-clock timeout** — default 600 s, overridable
  via `SENTINEL_REPORT_TIMEOUT_SECONDS` (`orchestrator.py:68-80`).
* **DAST teardown always runs in `finally`** (`orchestrator.py:897-977`):
  force-stop, clear proxy, stop mitmproxy, release device pool lease.

---

## 3. The 10-Phase Pipeline

The canonical entrypoint is `Orchestrator.run()`
(`sentinel/core/orchestrator.py:189-453`).

### Phase 0 — Ingestion
* **Method:** `_phase0_ingestion` (`orchestrator.py:457-486`).
* **Trigger:** always.
* **Produces:** `ctx.apk_sha256`, `ctx.apk_size_bytes`, session
  workspace at `<workspace>/<session_id>/`.
* **Failure mode:** raises `OrchestratorError` if the APK doesn't
  exist (line 466) — this is the only fatal phase.

### Phase 0.5 — Learning profile load
* **Method:** `_maybe_load_learning_profile` (`orchestrator.py:1461-1481`).
* **Trigger:** `--learning-dir` set.
* **Produces:** `ctx.learning_profile` (per-APK priors from
  `sentinel/learning/profile_store.py:AppProfileStore`).
* **Failure mode:** warning only.

### Phase 1 — Parallel Recon
* **Method:** `_phase1_recon` (`orchestrator.py:490-587`).
* **Trigger:** always.
* **Produces:** `ctx.sources["jadx"|"androguard"|"apktool"|"mitmproxy"]`,
  `ctx.decompiled_dir`, `ctx.resources_dir`, `ctx.manifest`,
  `ctx.target_sdk`, `ctx.permissions`.
* **How:** `asyncio.gather(_run_jadx, _run_androguard, _run_apktool,
  _run_manifest, return_exceptions=True)` (`orchestrator.py:506-509`).
* **Failure mode:** each tool independent — a JADX crash still lets
  Androguard produce output; every failure is appended to
  `scan_result.warnings`.

### Phase 1.5 — Profile + AST cache
* **Method:** `_phase15_profile` (`orchestrator.py:1587-1657`).
* **Trigger:** always.
* **Produces:** shared `AstCache` on `ctx.ast_cache`
  (`sentinel/core/ast_cache.py:AstCache:46`), META_005 profile
  (frameworks, native libs, API types, obfuscation) and the
  advisory `skip_agents` prefix list from
  `_resolve_skip_prefixes` (`orchestrator.py:1659-1678`).
* **Skip rules:**
  * `_HARD_SKIP_HYBRID = ("TAINT_",)` when Flutter / React Native /
    Xamarin / Unity is detected (`orchestrator.py:1584, 1670-1672`).
  * `_HARD_SKIP_NO_NATIVE = ("NL_", "META_006")` when no `.so` present
    (`orchestrator.py:1585, 1674-1676`).

### Phase 4 — Dynamic (DAST)
* **Method:** `_phase4_dynamic` (`orchestrator.py:632-977`).
* **Trigger:** `dynamic_enabled=True` (CLI `--dynamic`).
* **Sub-flow:** device lease → `is_installed` → install if missing →
  `mitmproxy.start()` unless `--no-proxy` → `adb.set_global_proxy` →
  `adb.start_app` → capture window (UI driver: `off | monkey | appium`)
  → Phase 4.5 Frida sub-phase → teardown always in `finally`.
* **Produces:** `ctx.sources["mitmproxy"]` (flow capture),
  `scan_result.tool_health["dynamic"]`.
* **Failure mode:** every step best-effort; the phase can be entirely
  skipped and SAST still produces findings.

### Phase 4.5 — Frida sub-phase
* **Method:** `_run_frida_subphase` (`orchestrator.py:981-1138`).
* **Trigger:** `frida_enabled=True` and Phase 4 already running.
* **Produces:** `ctx.sources["frida"]` (Frida capture) and
  `ctx.sources["frida_screenshots"]`. Hooks injected via
  `ALL_RUNTIME_HOOKS` (`tools/frida_runner.py`) — covers
  `Cipher.getInstance`, `MessageDigest.getInstance`,
  `KeyGenerator.getInstance`, `okhttp.CertificatePinner`,
  `X509TrustManager`, `WebViewClient`, TrustKit, Conscrypt,
  `HostnameVerifier`.
* **Cancellation safety:** `asyncio.CancelledError` triggers
  `frida.detach()` before re-raising (`orchestrator.py:1085-1087`).

### Phase 2 — Agents
* **Method:** `_phase2_agents` (`orchestrator.py:1682-1743`).
* **Trigger:** always.
* **Produces:** `list[Finding]` collated from every registered
  `BaseAgent` running in `asyncio.gather` with
  `return_exceptions=True`.
* **Phase 2.1 planner advisory:** `_run_planner_advisory`
  (`orchestrator.py:1745-1783`) when `ctx.planner_enabled` — writes
  decisions to `ctx.sources["planner_log"]` (advisory only in current
  release).

### Phase 2.5 — Dedup
* **Inlined** in `run()` (`orchestrator.py:249-257`).
* **Trigger:** always after Phase 2.
* **Implementation:** `sentinel/core/dedup.py:dedupe` — highest-severity
  per `(canonical_class, file)` cluster wins; losers folded into
  `_deduped_from` on the survivor's evidence.

### Phase 2.6 — Enrichment (IMPACT + COMPLIANCE + SWARM)
* **Method:** `_phase26_enrich` (`orchestrator.py:1485-1575`).
* **IMPACT_001** (`sentinel/impact/`) — deterministic financial-impact
  score attached to `Finding.financial_impact_score`, augmented with
  HVT endpoints from `strings.xml`.
* **COMPLIANCE_001** (`sentinel/compliance/`) — YAML-driven tag
  attach onto `Finding.compliance_tags`.
* **SWARM_001** (`sentinel/swarm/`) — opt-in, LLM-heavy, only fires
  on High/Critical findings; `swarm_llm_query` callable required.

### Phase 4.6 — SAST→DAST dispatch (hybrid replay)
* **Method:** `_phase46_dynamic_target_dispatch`
  (`orchestrator.py:1140-1431`).
* **Trigger:** `dynamic_enabled=True` and any finding carries a
  `dynamic_target` dict or legacy `evidence.dynamic_target=True` +
  `frida_payload` dict.
* **ADB target types:** `deep_link`, `component`, `permission_check`
  (`orchestrator.py:1242-1352`). Each converts static evidence into
  live `adb.verify_*` calls. Result maps through
  `sentinel.verify.proof_gate.apply_runtime_result`
  (`orchestrator.py:1363-1370`).
* **Auth handling:** `_target_requires_auth` (`orchestrator.py:1434-1442`)
  triggers `CredentialManager`-driven login and returns `auth_gated`
  when the probe was blocked at the login screen.

### Phase 4.7 — AFL++ fuzz
* **Method:** `_phase4_7_fuzz` (`orchestrator.py:1993-2030`).
* **Trigger:** `ctx.fuzz_enabled=True`.
* **Produces:** D_072 follow-up findings from `sentinel/fuzz/run_for_session`.
* **Failure mode:** logs "skipped" reason when toolchain missing.

### Phase 3 — LLM triage
* **Method:** `_phase3_triage` (`orchestrator.py:1787-1821`).
* **Trigger:** `triager is not None` and `len(findings) > 0`.
* **Produces:** `verified | filtered | uncertain | skipped` outcomes
  stored under `Finding.evidence["_triage"]` (see `sentinel/triage/`).

### Phase 7 — Correlation
* **Method:** `_phase7_correlation` (`orchestrator.py:1825-1842`).
* **Trigger:** `len(findings) >= 2`.
* **Produces:** COR_001 chain findings from
  `sentinel/agents/correlation/cor001_chain_agent.py`.

### Phase 7.5 — Active exploitation
* **Method:** `_phase7_5_active_exploitation`
  (`orchestrator.py:1846-1950`).
* **Trigger:** any finding present.
* **Produces:** per-finding `exploitation_status`, `exploit_proof`,
  `api_replay_logs`, `severity_rationale`, and `poc_artifacts`
  written under `<workspace>/<session>/poc_artifacts/` by
  `PoCGenerator.generate_for()` (`sentinel/exploit/poc_generator.py`
  called from `orchestrator.py:1907`).
* **Category promotion:** any finding the driver enriched gets
  `finding_category="AI-Powered"` (`orchestrator.py:1896-1904`).

### Phase 7.6 — Proof gate
* **Method:** `_phase7_6_proof_gate` (`orchestrator.py:1954-1989`).
* **Trigger:** any finding present.
* **Produces:** `Finding.proof_status`, `.proof_summary`,
  `.proof_requirements`, `.proof_missing`, `.duplicate_key`
  via `sentinel/verify/proof_gate.py:apply_proof_gate`. Metadata
  only — no runtime action.

### Phase 7.5b — PoC Studio
* **Method:** `_phase7_5_poc_studio` (`orchestrator.py:2034-2064`),
  invoked from `_phase8_report` (`orchestrator.py:2079-2085`).
* **Trigger:** always, before report render.
* **Produces:** runnable or markdown-only PoC artifacts in
  `<workspace>/poc/` via `sentinel/exploit/poc_studio.emit_for_scan`.
  `ctx.allow_live_poc` gates runnable emission.

### Phase 8 — Report generation
* **Method:** `_phase8_report` (`orchestrator.py:2068-2112`) →
  `ReportGeneratorAgent` (`sentinel/agents/reporting/r001_report_agent.py`).
* **Trigger:** any finding present.
* **Produces:** `VAPT_Report_<session>.md|html|json|sarif` under
  `<workspace>/reports/`, plus a single INFO meta-finding whose
  `evidence` carries the artifact paths (`r001_report_agent.py:230-255`).
* **Timeout:** `_REPORT_TIMEOUT_SECONDS` (600 s default),
  `asyncio.wait_for` around the call (`orchestrator.py:404-407`).

**Dependency map:** 0 → 0.5 → 1 → 1.5 → 4 (opt) → 2 → 2.5 → 2.6 →
4.6 (opt) → 4.7 (opt) → 3 (opt) → 7 (opt) → 7.5 → 7.6 → 8. Every
optional phase logs to `scan.warnings` on failure; only Phase 0 can
kill the run.

---

## 4. Complete Agent Registry

Extracted programmatically from `sentinel/agents/` — 209 agent files
across 31 category directories. Legend:
`ID` = `AGENT_ID` constant; `Class` = `VULN_CLASS`;
`Ph` = declared `PHASE`; `DT` = emits `dynamic_target` for the
Phase 4.6 replayer (T = yes).

### api_security (5 files, sentinel/agents/api_security/)

| ID       | Class                                       | Ph      | DT | File                        |
|----------|---------------------------------------------|---------|----|-----------------------------|
| API_001  | Mobile Backend API Security                 | Phase 4 | -  | openapi_inferrer.py         |
| API_002  | Broken Object Level Authorization (BOLA/IDOR) | -     | -  | api_002_bola_idor.py        |
| API_003  | Mass Assignment                             | Phase 4 | -  | mass_assignment.py          |
| API_004  | Excessive Data Exposure                     | Phase 4 | -  | data_exposure.py            |
| API_005  | Broken Object Level Authorization           | Phase 4 | -  | bola_verifier.py            |

### auth (11 files, sentinel/agents/auth/)

| ID     | Class                              | Ph      | DT | File                              |
|--------|------------------------------------|---------|----|-----------------------------------|
| A_001  | Hardcoded Credentials              | -       | -  | a_001_hardcoded_creds.py          |
| A_002  | JWT Algorithm Confusion            | -       | -  | a_002_ai.py                       |
| A_004  | Hardcoded Secret                   | static  | -  | hardcoded_secrets_agent.py        |
| A_008  | Biometric Authentication Bypass    | Phase 3 | -  | a008_biometric_bypass.py          |
| A_009  | Tap-Jacking Exposure               | Phase 2 | -  | a009_tap_jacking.py               |
| A_010  | Session Token in URL               | Phase 2 | -  | a010_session_token_in_url.py      |
| A_011  | Refresh Token Survives Logout      | Phase 2 | -  | a011_refresh_token_reuse.py       |
| A_012  | Session Fixation                   | Phase 2 | -  | a012_session_fixation.py          |
| A_013  | Magic Link Token Replay            | Phase 2 | -  | a013_magic_link_token.py          |
| A_015  | Hardcoded Credentials (LLM variant)| -       | -  | a_001_ai.py                       |
| A_016  | JWT Algorithm Confusion (canonical)| -       | -  | a_002_jwt_alg_confusion.py        |

> Note: `A_001/A_002` and their `_ai` twins `A_015/A_016` produce
> overlapping findings by design (deterministic vs LLM path). See §9
> discrepancies.

### auth_storage (1)
| A_014 | Insecure Auth Token Storage | static | - | insecure_auth_storage_agent.py |

### backup (1)
| BAK_001 | Insecure Backup | static | - | insecure_backup_agent.py |

### base (2 — infrastructure)
`base_agent.py:BaseAgent:23` — lifecycle: `is_applicable`, `analyze`,
`run` (deduped `save_finding` + event emit).
`ai_autonomous_agent.py:AIAutonomousAgent` — LLM-driven variant with
tool-loop support (emits `dynamic_target`).

### business (8, sentinel/agents/business/)

| ID         | Class                          | Ph      | DT | File                          |
|------------|--------------------------------|---------|----|-------------------------------|
| B_001      | REST API IDOR                  | Phase 2 | -  | b001_rest_idor.py             |
| B_003      | Race Condition / TOCTOU        | Phase 2 | -  | b003_race_condition.py        |
| B_004      | In-App Purchase Bypass         | Phase 2 | -  | b004_iap_bypass.py            |
| B_005      | OAuth redirect_uri Hijack      | Phase 2 | -  | b005_oauth_redirect_uri.py    |
| B_006      | Unsigned APK Install           | Phase 2 | -  | b006_unsigned_update.py       |
| B_007      | Client-Side Authorization Gate | Phase 2 | -  | b007_client_side_authz.py     |
| B_008      | Client-Side Trust Violation    | Phase 2 | -  | b008_client_side_trust.py     |
| LOGIC_001  | Temporal / Hidden-Mode Logic   | Phase 2 | -  | logic001_temporal_detector.py |

### cert_pinning (1)
| N_002 | Missing Certificate Pinning | static | - | missing_cert_pinning_agent.py |

### cloud (2)
| F_001 | Firebase Misconfiguration | static  | - | firebase_agent.py                 |
| F_002 | FCM Token Disclosure      | Phase 2 | - | f002_fcm_token_disclosure.py      |

### correlation (1)
| COR_001 | Exploit Chain | Phase 7 | - | cor001_chain_agent.py |

### crossplatform (4)
| FL_001 | FLUTTER_LIBAPP_AUDIT               | Phase 2 | - | flutter_agent.py       |
| FL_002 | Flutter MethodChannel Surface      | Phase 2 | - | fl002_method_channel.py|
| RN_001 | RN_BUNDLE_AUDIT                    | Phase 2 | - | rn_agent.py            |
| RN_002 | React Native Bridge Taint Surface  | Phase 2 | - | rn002_bridge_taint.py  |

### crypto (15)

| ID    | Class                                       | Ph      | DT | File                             |
|-------|---------------------------------------------|---------|----|----------------------------------|
| C_001 | Insecure Cipher Mode — AES/ECB              | -       | -  | c_001_ecb_mode.py                |
| C_002 | Static or Predictable IV                    | -       | -  | c_002_static_iv.py               |
| C_005 | Hardcoded Cryptographic Keys                | Phase 2 | -  | c005_hardcoded_keys.py           |
| C_006 | ECB Cipher Mode                             | Phase 2 | -  | c006_ecb_mode.py                 |
| C_007 | Weak Cryptography                           | static  | -  | weak_crypto_agent.py             |
| C_010 | Insecure SQLCipher Key Derivation           | Phase 2 | -  | c010_sqlcipher_key_derivation.py |
| C_011 | Android Keystore Misuse                     | Phase 2 | -  | c011_keystore_misuse.py          |
| C_012 | AES-GCM Nonce Reuse                         | Phase 2 | -  | c012_aes_gcm_nonce_reuse.py      |
| C_013 | Java Native Deserialization                 | Phase 2 | -  | c013_java_serialization.py       |
| C_014 | AES-CBC Predictable IV                      | Phase 2 | -  | c014_cbc_predictable_iv.py       |
| C_015 | Weak PRNG Seed                              | Phase 2 | -  | c015_weak_prng_seed.py           |
| C_016 | Hash Used as Key Derivation Function        | Phase 2 | -  | c016_hash_kdf.py                 |
| C_017 | Hardcoded Certificate/Key                   | Phase 2 | -  | c017_hardcoded_cert_finder.py    |
| C_018 | Roll-Your-Own Crypto                        | Phase 2 | -  | c018_crypto_constants.py         |
| C_019 | Missing Key Attestation Challenge           | static  | -  | c019_missing_key_attestation.py  |

### dast (5)
`base_dast_agent.py` is the abstract; concrete DAST agents:

| DAST_001 | Anti-Tampering Detection | - | - | d_001_anti_frida.py    |
| DAST_002 | SSL Pinning Bypass       | - | - | d_002_ssl_bypass.py    |
| DAST_003 | Runtime Crypto Weakness  | - | - | d_003_runtime_crypto.py|
| DAST_004 | Runtime Taint Flow       | - | - | d_004_runtime_taint.py |

### data_storage (1)
| STG_001 | World-Readable Storage | static | - | world_readable_agent.py |

### dynamic (86 files, sentinel/agents/dynamic/ — the largest family)

Runtime / Frida / ADB / API-replay agents. Every "(Dynamic Testing
Target)" entry emits a `dynamic_target` (DT=T) for Phase 4.6 replay.

| ID    | Class                                                | Ph       | DT | File                              |
|-------|------------------------------------------------------|----------|----|-----------------------------------|
| N_003 | Improper TLS Validation                              | dynamic  | -  | improper_tls_agent.py             |
| N_004 | Sensitive Data In Transit                            | dynamic  | -  | data_in_transit_agent.py          |
| N_005 | Certificate Pinning Bypass                           | dynamic  | -  | cert_pinning_bypass_agent.py      |
| D_001 | Clipboard Sensitive Data Leak                        | dynamic  | -  | d001_clipboard_leak_agent.py      |
| D_002 | Missing FLAG_SECURE on Sensitive Screen              | dynamic  | -  | d002_flag_secure_missing_agent.py |
| D_003 | Insecure Biometric Prompt                            | dynamic  | -  | d003_biometric_weak_agent.py      |
| D_004 | Missing Anti-Tamper Coverage                         | dynamic  | -  | d004_anti_tamper_agent.py         |
| D_005 | Dynamic Code Loading                                 | dynamic  | -  | d005_dynamic_code_loading_agent.py|
| D_006 | Runtime IV / Key Reuse                               | dynamic  | -  | d006_static_iv_reuse_agent.py     |
| D_007 | Race-Condition / TOCTOU Candidate                    | dynamic  | -  | d007_race_condition_agent.py      |
| D_008 | In-App Purchase Verification Bypass                  | dynamic  | -  | d008_iap_bypass_agent.py          |
| D_009 | IDOR / Mass-Assignment Candidate                     | dynamic  | -  | d009_idor_candidate_agent.py      |
| D_010 | JWT Weakness                                         | dynamic  | -  | d010_jwt_weakness_agent.py        |
| D_011 | Insecure WebView Runtime Configuration               | dynamic  | -  | d011_webview_runtime_agent.py     |
| D_012 | Sensitive Lockscreen Notification                    | dynamic  | -  | d012_notification_leak_agent.py   |
| D_013 | Sensitive Data Sent to Third-Party Endpoint          | dynamic  | -  | d013_third_party_pii_leak_agent.py|
| D_014 | Cookie Hardening Weakness                            | dynamic  | -  | d014_cookie_hardening_agent.py    |
| D_015 | Implicit Intent Sensitive Extras Leak                | dynamic  | -  | d015_implicit_intent_leak_agent.py|
| D_016 | Accessibility / NotificationListener Abuse Pattern   | dynamic  | -  | d016_accessibility_abuse_agent.py |
| D_017 | GraphQL Persisted-Query Bypass                       | dynamic  | -  | d017_graphql_persisted_query_agent.py |
| D_018 | SMS Permission / Retriever-API Abuse                 | dynamic  | -  | d018_sms_permission_abuse_agent.py|
| D_019 | Screen Capture / MediaProjection Pipeline            | dynamic  | -  | d019_screen_capture_agent.py      |
| D_020 | Dynamically-Registered Receiver Implicit Export      | dynamic  | -  | d020_dynamic_receiver_export_agent.py |
| D_021 | PendingIntent Mutable at Runtime                     | dynamic  | -  | d021_pending_intent_mutable_agent.py |
| D_022 | Local-Socket Server Exposed Across App Boundary      | dynamic  | -  | d022_local_socket_server_agent.py |
| D_023 | ContentProvider URI Exposure to Cross-UID Caller     | dynamic  | -  | d023_content_provider_uri_exposure_agent.py |
| D_024 | FileProvider Path-Traversal / Symlink Escape         | dynamic  | -  | d024_file_provider_traversal_agent.py |
| D_025 | Background Location Request                          | dynamic  | -  | d025_background_location_leak_agent.py |
| D_026 | Insecure Android-Keystore Key Generation             | dynamic  | -  | d026_insecure_keystore_usage_agent.py |
| D_027 | Zip-Slip / Archive Path Traversal                    | dynamic  | -  | d027_zip_path_traversal_agent.py  |
| D_028 | Insecure RNG in Security Context                     | dynamic  | -  | d028_insecure_random_runtime_agent.py |
| D_029 | Custom HostnameVerifier Accepts Mismatched Cert      | dynamic  | -  | d029_insecure_hostname_verifier_agent.py |
| D_030 | In-App Update Installs Unverified APK                | dynamic  | -  | d030_in_app_update_insecure_agent.py |
| D_031 | Unsafe JSON Deserialization                          | dynamic  | -  | d031_unsafe_json_deserialization_agent.py |
| D_032 | SQLite Command Injection / Unparameterised Query     | dynamic  | -  | d032_sqlite_command_injection_agent.py |
| D_033 | Unsafe Reflection Invocation Chain                   | dynamic  | -  | d033_unsafe_reflection_invoke_agent.py |
| D_034 | Exported Activity Returns Sensitive Data Cross-App   | dynamic  | -  | d034_exported_activity_result_leak_agent.py |
| D_035 | Sensitive Data Emitted to Log / Local File           | dynamic  | -  | d035_local_file_log_leak_agent.py |
| D_036 | Background Clipboard Read                            | dynamic  | -  | d036_clipboard_listener_snoop_agent.py |
| D_037 | Receiver Wiretaps Sensitive System Broadcasts        | dynamic  | -  | d037_broadcast_wiretap_agent.py   |
| D_038 | Custom X509TrustManager Accepts Invalid Chain        | dynamic  | -  | d038_insecure_trust_manager_runtime_agent.py |
| D_039 | OkHttp HttpLoggingInterceptor Logs Body / Headers    | dynamic  | -  | d039_okhttp_logging_runtime_agent.py |
| D_040 | Biometric Crypto Bypassable via PIN Fallback         | dynamic  | -  | d040_biometric_device_credential_fallback_agent.py |
| D_041 | Notification / Toast Flood                           | dynamic  | -  | d041_notification_flood_agent.py  |
| D_042 | Deep-Link Crash / Bypass Fuzz                        | Phase 2  | T  | d042_deep_link_bomb.py            |
| D_043 | Hidden Internal Endpoint                             | Phase 2  | T  | d043_hidden_api_hunter.py         |
| D_044 | Biometric Callback Replay                            | Phase 2  | T  | d044_biometric_replay.py          |
| D_045 | Local SQLite SQLi                                    | Phase 2  | T  | d045_sqlite_prober.py             |
| D_046 | Race-Condition Candidate                             | Phase 2  | T  | d046_race_condition_target.py     |
| D_047 | Heap Snapshot Target                                 | Phase 2  | T  | d047_memory_dump.py               |
| D_048 | WebView XSS Injection                                | Phase 2  | T  | d048_webview_xss.py               |
| D_049 | Notification OTP Leak                                | Phase 2  | T  | d049_notification_snoop.py        |
| D_050 | TLS Pinning Defense-in-Depth Map                     | Phase 2  | T  | d050_pinning_stress_test.py       |
| D_051 | Exported Service Bind / Probe                        | Phase 2  | T  | d051_service_leaker.py            |
| D_052 | Reachable Intent Auth-Bypass Path                    | Phase 2  | T  | d052_symbolic_intent.py           |
| D_053 | Hidden Native Crypto via Side-Channel                | Phase 2  | T  | d053_side_channel.py              |
| D_054 | GraphQL Endpoint Fuzz Target                         | Phase 2  | T  | d054_graphql_fuzzer.py            |
| D_055 | Native Heap Memory-Safety Probe                      | Phase 2  | T  | d055_native_heap.py               |
| D_056 | Biometric Timing Side-Channel                        | Phase 2  | T  | d056_biometric_timing.py          |
| D_057 | Deep-Link State Poisoning                            | Phase 2  | T  | d057_state_poisoner.py            |
| D_058 | WebSocket Frame Injection                            | Phase 2  | T  | d058_websocket_injector.py        |
| D_059 | Clipboard Paste-Poisoning                            | Phase 2  | T  | d059_clipboard_hijack.py          |
| D_060 | Sensor / Location Spoof                              | Phase 2  | T  | d060_sensor_spoofing.py           |
| D_061 | Memory Key Extraction                                | Phase 2  | T  | d061_key_extractor.py             |
| D_062 | Binder Transaction DoS Probe                         | Phase 2  | T  | d062_binder_bomb.py               |
| D_063 | ContentProvider SQLi                                 | Phase 2  | T  | d063_provider_sqli.py             |
| D_064 | JobScheduler Extras Hijack                           | Phase 2  | T  | d064_job_hijacker.py              |
| D_065 | FileProvider Active Traversal Probe                  | Phase 2  | T  | d065_file_provider_fuzzer.py      |
| D_066 | Accessibility Service Click Hijack                   | Phase 2  | T  | d066_a11y_abuser.py               |
| D_067 | Split APK Hijack                                     | Phase 2  | T  | d067_split_apk.py                 |
| D_068 | WearOS DataLayer Bridge Leak                         | Phase 2  | T  | d068_wearable_bridge.py           |
| D_069 | Sensitive Field Leaked to Autofill                   | Phase 2  | -  | d069_autofill_sniffer.py          |
| D_070 | Picture-in-Picture Clickjack                         | Phase 2  | T  | d070_pip_spy.py                   |
| D_071 | TWA Session Hijack                                   | Phase 2  | T  | d071_twa_breaker.py               |
| D_072 | Native RCE Candidate                                 | Phase 2  | T  | d072_jni_shadow.py                |
| D_073 | PendingIntent Privilege Escalation Probe             | Phase 2  | T  | d073_pending_intent_esc.py        |
| D_074 | Deep Link Scheme Confusion Probe                     | Phase 2  | T  | d074_scheme_confuser.py           |
| D_075 | Runtime Weak Cryptography                            | dynamic  | -  | runtime_crypto_agent.py           |
| D_078 | Biometric CryptoObject Unwrapper Probe               | Phase 2  | T  | d078_biometric_unwrapper.py       |
| D_081 | Backup Data Extraction Probe                         | Phase 2  | T  | d081_backup_extractor.py          |
| D_082 | IAP Spoofing                                         | Phase 2  | T  | d082_iap_spoofing.py              |
| D_083 | Mobile SSRF                                          | Phase 2  | T  | d083_mobile_ssrf.py               |
| D_084 | WebView Universal XSS                                | Phase 2  | T  | d084_webview_xss.py               |
| D_085 | ContentProvider LFI                                  | Phase 2  | T  | d085_provider_lfi.py              |
| D_086 | Intent Injection XSS                                 | Phase 2  | T  | d086_intent_xss.py                |
| D_090 | Auth-Gated Intent Handler                            | dynamic  | -  | d090_intent_auth_verifier.py      |

### logging (2)
| LOG_001 | PII Leakage via Logcat | -      | - | log_001_pii_logs.py         |
| LOG_002 | Insecure Logging       | static | - | insecure_logging_agent.py   |

### meta (4)
| META_001 | Obfuscation Analysis     | static     | - | obfuscation_detector.py    |
| META_002 | Debuggable Release Build | Phase 2    | - | meta002_debuggable_manifest.py |
| META_005 | Application Profile      | Phase 1.5  | - | meta005_profiler.py        |
| META_006 | Native Library Inspection| Phase 2    | T | meta006_native_inspector.py|

### native (2)
| NL_001 | Native Library Exposure               | static  | - | native_lib_agent.py         |
| NL_002 | Attacker-Controlled Native Library Load| Phase 2| - | nl002_load_library_taint.py |

### network (14, sentinel/agents/network/)

| ID    | Class                             | Ph      | DT | File                          |
|-------|-----------------------------------|---------|----|-------------------------------|
| N_001 | Cleartext Traffic                 | static  | -  | cleartext_traffic_agent.py    |
| K_001 | GraphQL / gRPC Schema Exposure    | Phase 2 | -  | k001_graphql_grpc_analyzer.py |
| N_006 | API Key Leakage                   | Phase 4 | -  | n006_api_key_leakage.py       |
| N_007 | GraphQL Introspection Enabled     | Phase 2 | -  | n007_graphql_introspection.py |
| N_008 | Insecure TLS Validation           | Phase 2 | -  | n008_insecure_trust_manager.py|
| N_009 | WebView Remote Debugging Enabled  | Phase 2 | -  | n009_webview_debug_flag.py    |
| N_010 | OkHttp Body / Header Logging      | Phase 2 | -  | n010_okhttp_logging.py        |
| N_011 | GraphQL Authorization Issues      | Phase 4 | -  | n011_graphql_fuzzer.py        |
| N_012 | DNS Leak                          | Phase 2 | -  | n012_dns_leak.py              |
| N_013 | Cleartext WebSocket               | Phase 2 | -  | n013_insecure_websocket.py    |
| N_014 | Hardcoded mTLS Client Certificate | Phase 2 | -  | n014_hardcoded_mtls_key.py    |
| N_015 | Internal Endpoint Exposure        | Phase 2 | -  | n015_internal_endpoint_scanner.py |
| N_016 | Cleartext HTTP Transmission       | -       | -  | n_001_cleartext_http.py       |
| N_017 | Missing Certificate Pinning       | -       | -  | n_002_missing_pinning.py      |

### platform (15, sentinel/agents/platform/)

| ID       | Class                             | Ph      | DT | File                              |
|----------|-----------------------------------|---------|----|-----------------------------------|
| P_001    | Exported Deep Link Handler        | -       | T  | p_001_deep_link_hijack.py         |
| P_002    | Deep Link Hijacking               | Phase 2 | T  | p001_deep_link_hijack.py          |
| P_004    | Exposed Content Provider          | static  | -  | content_provider_agent.py         |
| P_005    | Excessive Manifest Permission     | Phase 2 | T  | p005_excessive_permissions.py     |
| P_006    | Unprotected Broadcast             | Phase 2 | -  | p006_unprotected_broadcast.py     |
| P_007    | Activity-Result Sensitive Data Leak| Phase 2| -  | p007_activity_result_leak.py      |
| P_010    | Intent Redirect                   | Phase 2 | -  | intent_redirect_agent.py          |
| P_011    | Receiver Chain Hijack             | Phase 2 | -  | p011_receiver_chain_hijack.py     |
| P_012    | Mutable PendingIntent             | Phase 2 | -  | p012_mutable_pending_intent.py    |
| P_015    | Deep Link Misconfiguration        | Phase 2 | T  | p015_deep_link_mapper.py          |
| P_016    | Recent-Task Hijack (StrandHogg)   | static  | -  | p016_task_hijack.py               |
| P_017    | Foreground-Service Privilege Drift| static  | -  | p017_foreground_service_drift.py  |
| I_001    | Unprotected Exported Component    | Phase 2 | -  | i001_component_cross_ref.py       |
| IPC_001  | Exposed IPC Component             | static  | -  | ipc_exposure_agent.py             |
| UI_001   | Activity Auth-Bypass Path         | Phase 2 | -  | ui001_activity_graph.py           |

### privacy (1)
| PRIV_001 | Pre-Consent Sensitive Data Collection | Phase 2 | - | priv001_data_collection_auditor.py |

### random_gen (1)
| RNG_001 | Insecure Random | static | - | insecure_random_agent.py |

### reflection (1)
| REFL_001 | Unsafe Reflection | Phase 2 | T | refl001_reflection_resolver.py |

### reporting (5)
| R_001 | VAPT Report Generation | Phase 8 | - | r001_report_agent.py |

Plus `builder.py`, `enrich.py`, `models.py`, `templates/{markdown,html}.py`.

### resilience (2)
| RES_001 | Anti-Tamper Posture | static  | - | anti_tamper_agent.py |
| RES_002 | Resource Leak       | Phase 2 | - | res002_resource_leak.py |

### semgrep (1)
| SG_001 | Pattern Match | static | - | semgrep_agent.py |

### shared_prefs (6)
| STG_006 | Insecure SharedPreferences        | static  | - | insecure_prefs_agent.py         |
| STG_007 | Insecure FileProvider Path Mapping| Phase 2 | - | stg007_insecure_file_provider.py|
| STG_008 | Credential Write to External Storage| Phase 2| - | stg008_external_storage_credential.py |
| STG_009 | Insecure Auto-Backup Rules        | Phase 2 | - | stg009_backup_rules.py          |
| STG_010 | Plaintext Password File           | Phase 2 | - | stg010_plaintext_password_file.py |
| STG_011 | SQLite WAL / Journal Leak         | Phase 2 | - | stg011_sqlite_wal_leak.py       |

### special (1)
| TEST_001 | Pipeline Smoke Test | Phase 2 | - | test_agent.py |

`TEST_001` is the default agent used when the orchestrator is
constructed with an empty agent list (`orchestrator.py:148`).

### supply_chain (3)
| SCA_001 | VULNERABLE_DEPENDENCY                | Phase 2 | - | sca_agent.py                  |
| SCA_002 | Third-Party SDK Privacy Mismatch     | Phase 2 | - | sca002_sdk_privacy_auditor.py |
| SCA_004 | Suspicious Third-Party Library Behavior| Phase 2| - | sca004_malicious_lib_detector.py |

### taint (3)
| TAINT_001 | TAINT_FLOW | Phase 2 | - | taint_agent.py |

Plus `taint_config.py` and `tracer.py` (support modules).

### ui (1)
| GESTURE_001 | Custom Pattern-Lock Weakness | Phase 2 | - | gesture001_pattern_lock.py |

### webview (3)
| WV_001 | WebView JavaScript Bridge Exposure | -       | - | wv_001_js_bridge.py             |
| WV_002 | Insecure WebView                   | static  | - | insecure_webview_agent.py       |
| WV_003 | JavaScript Interface Bridge        | Phase 2 | - | js_interface_bridge_agent.py    |

**Summary count by category:**

| Category      | Files | Category       | Files |
|---------------|-------|----------------|-------|
| dynamic       | 86    | platform       | 15    |
| crypto        | 15    | network        | 14    |
| auth          | 11    | business       | 8     |
| shared_prefs  | 6     | api_security   | 5     |
| reporting     | 5     | dast           | 5     |
| crossplatform | 4     | meta           | 4     |
| supply_chain  | 3     | taint          | 3     |
| webview       | 3     | logging        | 2     |
| cloud         | 2     | native         | 2     |
| base          | 2     | (13× 1-agent)  | 13    |

---

## 5. Finding Data Model — Complete Schema

Defined in `sentinel/core/finding.py` (358 LOC). Strict Pydantic
`ConfigDict(str_max_length=10_000, extra="forbid", validate_assignment=True)`
(`finding.py:98-102`) — malicious APK strings cannot smuggle extra
fields.

### 5.1 Fields (in declaration order)

| Field | Type | Constraints | Line |
|-------|------|-------------|------|
| `agent_id` | `str` | must match `^[A-Z]+_\d{3}$` | 104, 226-231 |
| `vuln_class` | `str` | 1–200 chars | 105 |
| `severity` | `Severity` enum | Critical/High/Medium/Low/Info | 106, 82-87 |
| `confidence` | `float` | 0.0–1.0 | 107 |
| `evidence` | `dict[str, Any]` | ≤50 keys | 108, 240-245 |
| `cvss_vector` | `str?` | ≤200 chars | 109 |
| `cvss_score` | `float?` | 0.0–10.0 | 110 |
| `owasp` | `str?` | ≤50 | 111 |
| `masvs` | `str?` | ≤20 | 112 |
| `poc` | `str?` | — | 113 |
| `recommendation` | `str` | required, ≥1 char | 114 |
| `session_id` | `str` | must match `^[a-zA-Z0-9_-]{8,64}$` | 115, 233-238 |
| `tenant_id` | `str?` | ≤64; enforced by Postgres RLS on `sentinel.tenant_id` GUC | 118-121 |
| `financial_impact_score` | `float?` | ≥0.0 | 125 |
| `compliance_tags` | `list[str]` | ≤50 | 130 |
| `screenshots` | `list[str \| dict]?` | ≤40; dicts must have `path` key | 136, 247-260 |
| `code_snippet` | `dict?` | keys: file/line/start_col/end_col/content | 141 |
| `code_snippets` | `list[dict]?` | ≤20 | 146 |
| `context_factors` | `dict[str,str]?` | free-form (exposure/controls/impact/likelihood) | 151 |
| `severity_rationale` | `str?` | ≤4000 | 155 |
| `verification_status` | `str?` | free-form, default `"Code_Only"` | 160 |
| `verification_state` | `VerificationState?` | enum: verified/auth_gated/code_only/runtime_failed | 166 |
| `blocking_state_screenshot` | `str?` | ≤500 | 171 |
| `test_credentials_used` | `bool` | default False | 176 |
| `reproduction_commands` | `list[str]` | ≤20 | 180 |
| `observed_result` | `str?` | ≤4000 | 184 |
| `source_tags` | `list[str]` | ≤20 | 188 |
| `dynamic_target` | `dict?` | SAST→DAST handoff descriptor (`type`, `scheme`, `path`, `param`, `component`, `action`, `requires_auth` …) | 194 |
| `exploitation_status` | `ExploitationStatus` | Verified_Exploited / Auth_Gated / Code_Only / Runtime_Failed / Unverified | 198, 61-67 |
| `poc_artifacts` | `list[str]?` | ≤10 (workspace-relative paths) | 201 |
| `api_replay_logs` | `list[dict]?` | ≤50 | 206 |
| `exploit_proof` | `str?` | ≤4000 | 209 |
| `proof_status` | `ProofStatus?` | candidate / code_only / runtime_verified / verified_exploited / bounty_ready / auth_gated / runtime_failed / duplicate | 213, 41-50 |
| `proof_summary` | `str?` | ≤1000 | 214 |
| `proof_requirements` | `dict[str,bool]?` | — | 215 |
| `proof_missing` | `list[str]?` | ≤20 | 216 |
| `duplicate_key` | `str?` | ≤500 | 217 |
| `finding_category` | `FindingCategory` | AI-Powered / Static_Tool | 222, 74 |
| `triage` | `TriageState` | Unreviewed / TruePositive / FalsePositive / NeedsVerification | 223, 90-94 |
| `created_at` | `datetime` | UTC default | 224 |

### 5.2 Computed properties

* `finding_id` (`finding.py:262-265`) — first 16 hex chars of
  `sha256("<agent_id>|<vuln_class>|<sorted evidence items>")`. This is
  why duplicate `AGENT_ID`s cause silent collisions and the
  orchestrator hard-fails on them.

### 5.3 `finding_category` determination

`Static_Tool` by default (`finding.py:222`). Promoted to `AI-Powered`
by any of:

* Phase 7.5 ExploitDriver enriched the finding with
  `severity_rationale`, `exploit_proof`, `api_replay_logs`, or the
  driver reported `outcome.exploited` (`orchestrator.py:1896-1904`).
* Phase 4.6 `permission_check` ADB verifier promoted the finding on
  successful runtime observation (`orchestrator.py:1329`).

The report layer's `bucket_for_section` (`agents/reporting/models.py`)
uses `finding_category` to split findings into the two report
buckets rendered by R_001.

### 5.4 Proof gate statuses

Defined in `finding.py:41-50`. `apply_proof_gate`
(`sentinel/verify/proof_gate.py`) requires ALL of: in-scope target,
reachability, evidence quality, runtime verification, PoC/exploit
proof, impact score, and no same-scan `duplicate_key` to reach
`bounty_ready`. Any missing item lands the finding at the highest
partially-met tier (`runtime_verified`, `code_only`, or `candidate`)
with `proof_missing` populated for the report.

### 5.5 BountyScope

`BountyScope` (`finding.py:268-308`) enforces scope on
`package_in_scope`, `domain_in_scope` (with `*.example.com`
suffix-wildcard matching via `_matches_host` `finding.py:311-318`),
`technique_allowed`, and `excluded_vuln_classes`. Consumed by the
exploit driver and proof gate.

---

## 6. Dynamic Analysis & Exploitation Engine

### 6.1 ADB Truth Engine

`sentinel/tools/adb_runner.py:AdbRunner:48` (1,638 LOC). Every method
returns a `ToolResult` (`tools/result.py:29`) — success + data or
success=False + error string; nothing raises through to the
orchestrator.

Public verifiers used by Phase 4.6:

* `get_first_device()` — discovers connected devices via
  `adb devices -l`.
* `is_installed(package, serial=)`
* `install_apk(apk_path, serial=, replace=True)`
* `set_global_proxy(host, port, serial=)` /
  `clear_global_proxy(serial=)`
* `start_app(package, serial=)` / `force_stop(package, serial=)`
* `verify_deep_link(package, scheme, host_or_url, params_or_session,
   …, require_auth=, credential_manager=, frida=)` — fires
   `adb shell am start -a android.intent.action.VIEW -d …` and
   records screenshots + logcat + auth-gate detection.
* `verify_component(package, component, …, action=, data_uri=,
   require_auth=, credential_manager=, frida=)` — analogous for
   activities / services / receivers.
* `verify_permissions(package, serial=)` — dumps
   `dumpsys package … requested permissions`.
* `capture_evidence(session_id, workspace, …)` — screenshots +
  logcat snippets; returns a `dict` for the `screenshots` field.

### 6.2 Frida hook event types

`sentinel/tools/frida_runner.py:FridaRunner:150` (1,123 LOC).
Hook bundle `ALL_RUNTIME_HOOKS` combines JavaScript agents from
`frida_agent/src/` and covers:

* `crypto.cipher_get_instance`, `crypto.message_digest`,
  `crypto.key_generator` — from A_003 recipes.
* `tls.pinning_bypass_okhttp`, `tls.pinning_bypass_trustkit`,
  `tls.pinning_bypass_conscrypt`, `tls.trust_manager_relaxed`,
  `tls.hostname_verifier_relaxed`, `tls.webview_client_ssl_error`.
* `webview.js_bridge_call`, `runtime.dyn_code_load`,
  `runtime.reflection_invoke`, `runtime.clipboard_read`, etc.

Session shape: `FridaCapture(events: list[FridaEvent], script_errors:
list[str])`; each `FridaEvent` has `kind`, `args`, `stack`, and
optional `screenshot_path`.

The runner supports `spawn=True` (start-paused → resume after script
injection) so hooks fire before app main runs, and streams events over
Frida RPC into the workspace `evidence/` directory.

### 6.3 mitmproxy integration

`sentinel/tools/mitmproxy_runner.py:MitmproxyRunner` starts mitmproxy
in headless mode on `--dynamic-port` (default 8082), writes flows to
`<workspace>/dynamic/`, and returns a `MitmCapture(flows, flow_count,
duration_seconds)` populated with per-flow `scheme`, `host`, `path`,
`request/response`, and `tls_failed` flags. Phase 4 emits the counts
(`orchestrator.py:938-967`) as `phase.completed` event metadata.

### 6.4 ExploitDriver — authorization model

`sentinel/exploit/driver.py:ExploitDriver:77` (581 LOC).

* Per-finding `_within_active_scope` (`driver.py:504-528`) blocks any
  action against out-of-scope packages / domains — reads
  `ctx.bounty_scope` (a `BountyScope`).
* `_extract_package` (`driver.py:491-502`) resolves target package
  from finding evidence + context.
* Loopback exfil listener (`_LoopbackListener` `driver.py:372-442`)
  used by deep-link and webview drivers to catch exfiltrated tokens
  without ever talking to the real internet.
* Auth injection defers to `CredentialManager` (`tools/credential_manager.py`).
* Result: `ExploitOutcome(finding, exploited, poc_kind, poc_metadata)`
  (`driver.py:64-75`) — the orchestrator uses this to update category
  and generate PoC artifacts.

### 6.5 Concrete drivers

`sentinel/exploit/drivers.py`:

| Class               | Handles agents                   | File line |
|---------------------|----------------------------------|-----------|
| `RaceConditionDriver` | B_003, D_007, D_046           | 61        |
| `IdorDriver`          | B_001, API_002/005, D_009     | 178       |
| `DeepLinkDriver`      | P_001/002/015, D_042/057/074  | 312       |

Registered via `_register()` (`drivers.py:506`); resolved by
`driver_for(agent_id)` (`drivers.py:514`).

### 6.6 PoCGenerator artifact types

`sentinel/exploit/poc_generator.py:PoCGenerator`. Produces:

* `.sh` — ADB / curl repro scripts.
* `.md` — human-readable reproduction guide (always emitted, even in
  `allow_live_poc=False` mode).
* Frida `.js` — hook payload for repro against a device.

Each artifact returns `ExploitArtifact(relative_path, kind, notes)`,
recorded in `Finding.poc_artifacts` (`orchestrator.py:1911-1916`).

### 6.7 Phase 7.5 flow

```
for finding in findings:
    outcome = await driver.exploit(finding, context=ctx)
    if outcome adds rationale/proof/replay/exploited:
        finding.finding_category = "AI-Powered"
    if outcome.exploited or outcome.poc_kind:
        artifacts = poc.generate_for(finding, driver_hint=outcome.poc_metadata)
        finding.poc_artifacts = [a.relative_path for a in artifacts]
    memory.save_finding(finding)   # best-effort upsert
```

(source: `orchestrator.py:1885-1932`)

---

## 7. LLM & RAG Integration

### 7.1 Provider priority & circuit breaker (recap)

Fully described in §2.4. Key thresholds:
`CIRCUIT_BREAK_THRESHOLD=3`, `CIRCUIT_RESET_SECONDS=120`,
`TIMEOUT_LOCAL=300`, `TIMEOUT_CLOUD=60`, `MAX_RETRIES=2`,
`RETRY_BACKOFF=[1.0, 3.0]` (all `sentinel/llm/router.py:54-60`).

### 7.2 Triage prompt & flow

`sentinel/triage/triager.py:LLMTriager:53` (478 LOC). Prompt template
lives at the top of the module and asks the LLM to return JSON with
`{outcome: verified|filtered|uncertain|skipped, confidence: 0..1,
reasoning: str}`. Outcome persisted at
`Finding.evidence["_triage"]`. The orchestrator counts outcomes into
the `phase.completed` event for Phase 3
(`orchestrator.py:1811-1820`).

### 7.3 HON_001 calibration

`sentinel/calibration/hon_001.py` (201 LOC) tracks per-provider
outcome distributions across scans and adjusts triage confidence
so a systematically-over-confident provider (Groq answering
`verified` at 0.95 confidence on obvious false positives) has its
scores discounted. Called from within the triager before writing
outcomes back to findings.

### 7.4 RAG corpus

`sentinel/rag/`:
* `knowledge_base.py` — corpus registry (MASVS, OWASP MSTG, PCI-DSS,
  GDPR excerpts, CWE / CAPEC).
* `passage.py` — passage schema.
* `ingester.py` — ingests markdown / YAML sources into vector store.
* `retriever.py` — semantic retrieval per finding class.
* `enricher.py` — attaches `_rag_mapping` (control IDs) and
  `_rag_passage_ids` to `Finding.evidence`, later consumed by R_001
  when rendering the standards-references block
  (`r001_report_agent.py:11-14`).
* Data at `sentinel/rag/data/`.

### 7.5 Where the LLM is used vs banned

**Uses LLM:**
* Phase 3 LLMTriager (`triager.py`).
* Phase 7.5 severity rationale (called from `ExploitDriver`).
* Phase 8 narrative enrichment (`enrich_sections` in
  `agents/reporting/enrich.py:152` → router calls at
  `enrich.py:125-197`).
* SWARM_001 in Phase 2.6 when `swarm_llm_query` is provided.
* AI-family agents `A_015` / `A_016` in `sentinel/agents/auth/*_ai.py`.

**Banned:**
* Phase 0, 1, 1.5, 2 SAST agents (except the two `_ai` variants).
  Every deterministic detector reads AST / manifest / strings and
  returns immediately, so results are reproducible across runs.
* Phase 2.5 dedup (`sentinel/core/dedup.py`) — pure clustering.
* Phase 2.6 IMPACT and COMPLIANCE — YAML / heuristic only.
* Phase 4/4.5/4.6 verifiers — every ADB/Frida call is deterministic.
* Phase 7.6 proof gate (`sentinel/verify/proof_gate.py`) — pure
  metadata classifier.
* CVSS stamping (`sentinel/reports/cvss.py`, called from
  `r001_report_agent.py:64-65`).

### 7.6 Deterministic overrides in enrich.py

`sentinel/agents/reporting/enrich.py` (2,187 LOC). Even when the LLM
is available, several detectors have "strict template fallbacks" that
override LLM prose to keep findings truthful:

* `_strict_template_fallback` (`enrich.py:1158-1205`) — canonical
  narrative when the finding matches a known recipe by AGENT_ID +
  evidence shape.
* `render_deep_link_auth_gated` (`enrich.py:1100`),
  `render_permission_verified` (`enrich.py:1118`),
  `render_auth_gated_description` (`enrich.py:1130`) — Djini-style
  vulnerability-specific templates for the most common runtime
  outcomes.
* `_has_runtime_locked_template` (`enrich.py:1206`) gates when the
  strict template wins over the LLM's answer.
* `_evidence_matched_recipe` (`enrich.py:1365`) — pattern-match
  against evidence dict to select the right recipe.
* `_coerce_narrative` (`enrich.py:197-238`) — validates the LLM's
  JSON, drops keys that don't match schema, backfills defaults.

The upshot: for every high-signal vulnerability class, the report
prose is deterministic regardless of which LLM answered, and LLM
hallucinations cannot invent reproduction steps that aren't grounded
in evidence.

---

## 8. Reporting & Frontend

### 8.1 R_001 report generation flow

`sentinel/agents/reporting/r001_report_agent.py:53-97`:

```
all_findings = memory.get_findings(session_id)
stamp_all(all_findings)                         # CVSS 3.1 vector + score
report_findings = _select_report_findings(...)  # drop INFO + FalsePositive
data = build_report_data(...)                   # ReportData
router = _get_router()
await enrich_sections(data.sections, router)    # narrative + LLM
_write_artifacts(data)                          # md + html + json + sarif
return [_meta_finding(data, artifacts)]         # single INFO finding
```

Filter rules in `_select_report_findings` (`r001_report_agent.py:113-129`):
* Drop `Severity.INFO`.
* Drop `TriageState.FALSE_POSITIVE`.
* Keep everything else (including `UNREVIEWED` and `NEEDS_VERIFICATION`).

### 8.2 AI-Powered vs Static_Tool classification

`sentinel/agents/reporting/models.py:bucket_for_section` is the
canonical predicate — the report agent re-exposes it as
`ReportGeneratorAgent._classify_section`
(`r001_report_agent.py:180-182`). The predicate reads
`Finding.finding_category` (see §5.3). The JSON payload
(`_json_payload` `r001_report_agent.py:184-228`) splits findings into
`findings_by_bucket.ai_powered` and `.static_tool` with parallel
`bucket_counts`; the HTML and Markdown templates iterate the two
buckets separately so the client sees the AI-narrated findings
above the pattern-matched ones.

### 8.3 Djini-style detail structure

For `finding_category="AI-Powered"` sections, the renderer expects:

1. Vulnerability description (LLM narrative or template).
2. Severity rationale (`Finding.severity_rationale`).
3. Context factors table (`Finding.context_factors`).
4. Evidence — `code_snippets`, `screenshots`,
   `blocking_state_screenshot`.
5. Reproduction — `reproduction_commands` + `observed_result`.
6. Exploit proof — `exploit_proof`, `api_replay_logs`,
   `poc_artifacts`.
7. Standards mapping — `_rag_mapping` + `_rag_passage_ids` from
   evidence, plus `compliance_tags`, `owasp`, `masvs`.

For `Static_Tool` findings only description + evidence + repro
commands are shown.

### 8.4 Deterministic template overrides

See §7.6 — every runtime-locked / auth-gated / permission-verified
outcome routes through a strict template in `enrich.py` and only
falls back to LLM prose when no template matches.

### 8.5 Frontend components

`frontend/js/`:

| File                                    | Role                                       |
|-----------------------------------------|--------------------------------------------|
| `app-shell.js`                          | Router + main layout.                      |
| `api.js`                                | Thin REST wrapper over `/api/*` endpoints. |
| `utils.js`                              | DOM helpers (`el`, `refreshIcons`).        |
| `pages/agents.js`                       | Agent registry browser.                    |
| `pages/*.js`                            | Scans / reports / devices / scope pages.   |
| `components/findings-table.js`          | Sortable + filterable findings list.       |

Vanilla ES modules — no framework, no build step. The findings table
reads the JSON payload from `/api/reports/{session}/json` and renders
the two buckets separately when `finding_category` splits are
present.

### 8.6 Export formats

Produced under `<workspace>/<session>/reports/`:

| Extension | Renderer                                      | Consumer                     |
|-----------|-----------------------------------------------|------------------------------|
| `.md`     | `agents/reporting/templates/markdown.py`      | GitHub / HackerOne submission|
| `.html`   | `agents/reporting/templates/html.py`          | Client-facing deliverable    |
| `.json`   | `ReportGeneratorAgent._json_payload`          | Frontend + machine ingest    |
| `.sarif`  | `sentinel/reports/sarif.py:render_sarif_json` | GitHub Code Scanning / Azure DevOps |

Plus `<workspace>/<session>/poc/*` and `.../poc_artifacts/*` for
runnable exploits served via `/reports/{session}/poc/…`.

---

## 9. Security & Production Readiness

### 9.1 Tenant isolation

* `Finding.tenant_id` (`core/finding.py:118-121`) — nullable in OSS
  mode; set by the API from the JWT before persisting.
* Postgres RLS on `sentinel.tenant_id` GUC refuses INSERT/UPDATE when
  the value disagrees with the session variable — enforcement is at
  the database layer, not the app layer. Migrations under
  `migrations/` install the RLS policies.
* `sentinel/tenancy/` provides the per-request GUC setter.

### 9.2 Credential / secret handling

* `sentinel/tools/credential_manager.py:CredentialManager.from_env`
  reads DAST login credentials from env vars, scoped by package.
* `sentinel/core/crypto.py` provides Fernet-style symmetric encrypt
  used for at-rest secret storage.
* `sentinel/auth/api_keys.py` — hashed API-key store with revocation
  (`auth/revocation.py`).
* `sentinel/auth/jwt_auth.py` — HS256/RS256 JWT verification for the
  API layer.
* Every LLM key (`GROQ_API_KEY`, `CEREBRAS_API_KEY`) is read via
  `sentinel/core/config.py:get_settings:77` from `SecretStr` fields
  and never echoed to logs.

### 9.3 Scope enforcement

* `sentinel/scope/scope_parser.py:parse_scope:388` reads a bounty
  scope file (YAML) into a `BountyScope`.
* `ExploitDriver._within_active_scope` (`driver.py:504-528`) blocks
  any exploit attempt against out-of-scope packages/domains.
* Frontend `pages/scope.js` allows uploading/inspecting the current
  scope.

### 9.4 SSRF prevention

* Exploit exfil listener is a bound loopback socket
  (`driver.py:372-442`) — payloads never leave the host.
* `_build_exfil_url` (`driver.py:530-548`) hardcodes `127.0.0.1`.
* mitmproxy binds to loopback by default; the device proxy config
  points at the host bridge only.

### 9.5 Ranked risk table

| Risk                                              | Mitigation                                          | Residual |
|---------------------------------------------------|-----------------------------------------------------|----------|
| Duplicate `AGENT_ID` collisions                   | Startup hard-fail (`orchestrator.py:167-187`)       | Low      |
| LLM prompt injection from APK strings             | Strict Pydantic `extra="forbid"`, deterministic templates override LLM prose | Medium |
| Runaway Phase 8 render                            | 600s asyncio wait_for                                | Low      |
| Frida hook orphaning on cancel                    | `try/finally` detach + release lease                 | Low      |
| Cross-tenant data leak                            | Postgres RLS on `tenant_id` GUC                      | Low      |
| Out-of-scope exploit attempt                      | `_within_active_scope` gate before driver runs       | Low      |
| Untrusted APK crashes tool chain                  | Every tool wrapper returns `ToolResult`; per-agent gather with `return_exceptions=True` | Low |
| SSRF via exploit payload                          | Loopback-only exfil listener                         | Low      |
| Legacy Frida targets left with stale hooks        | `credential_manager.aclose()` + `frida.detach()` in `finally` (`orchestrator.py:1425-1431`) | Low |
| Duplicate `A_001/A_015` etc. producing overlapping findings | Phase 2.5 dedup collapses per canonical class | Medium  |

### 9.6 Dev vs Prod configuration differences

| Concern          | Dev default                                         | Prod                                                |
|------------------|-----------------------------------------------------|-----------------------------------------------------|
| Memory T1        | in-proc dict (`memory/lightweight.py`)              | Redis Streams (`memory/production.py`)              |
| Memory T2        | SQLite                                              | Postgres with RLS + Alembic (`migrations/`)         |
| Memory T3        | none                                                | Qdrant + Neo4j                                      |
| LLM              | Ollama or Groq free tier                            | Local vLLM/TensorRT-LLM at `SENTINEL_LOCAL_LLM_URL` |
| Determinism cache| None                                                | Redis via `sentinel/cache/redis_cache.py`           |
| Device access    | first attached device (`AdbRunner.get_first_device`)| Device pool with leases (`devices/pool.py`, `devices/redis_pool.py`) |
| Auth             | Optional (CLI)                                      | JWT + API-key required, RBAC (`auth/rbac.py`)       |
| Rate limit       | None                                                | `api/middleware/rate_limit.py`                      |
| Fuzz             | disabled                                             | opt-in `ctx.fuzz_enabled` per scan                  |

`docker-compose.yml`, `Dockerfile`, and `.env.example` at the repo
root document the production Redis + Postgres + Qdrant + Neo4j
stack.

---

## 10. Development Workflow

### 10.1 Add a new SAST agent

1. Create `sentinel/agents/<category>/<xxx_nnn>_<slug>.py`.
2. Subclass `BaseAgent` (`sentinel/agents/base/base_agent.py:23`).
3. Set class attributes:
   ```python
   AGENT_ID = "X_NNN"       # must match [A-Z]+_\d{3}, unique across registry
   VULN_CLASS = "Human-readable class"
   PHASE = "Phase 2"        # or "static"
   ```
4. Implement `async def is_applicable(self) -> bool` — return False
   when required context sources are missing (e.g. `ctx.has_jadx()`).
5. Implement `async def analyze(self) -> list[Finding]` — read
   `self.context`, walk `self.context.sources["jadx"|"androguard"|…]`,
   use `self._make_finding(...)` to construct findings.
6. Reuse `self.context.ast_cache` when parsing Java trees so Phase 2
   agents share a single parse pass.
7. Register the agent class in
   `sentinel/agents/<category>/__init__.py` and add it to the CLI's
   `_default_agents()` / API's agent registry.
8. Write a unit test under `tests/unit/agents/<category>/`.

### 10.2 Add a new DAST/Frida agent

1. Same base skeleton, but read `ctx.sources["mitmproxy"]` (flows) or
   `ctx.sources["frida"]` (Frida capture events).
2. Emit `dynamic_target={"type": "…", …}` when the finding needs a
   Phase 4.6 replay. Types supported today: `deep_link`,
   `component`, `permission_check` — extending requires a new
   branch in `_phase46_dynamic_target_dispatch`
   (`orchestrator.py:1242-1359`).
3. Set `PHASE = "dynamic"` or `"Phase 2"` (with DT=T for hybrid).

### 10.3 Add a new Frida TypeScript hook

1. Add a `.ts` module under `frida_agent/src/`.
2. Register the hook name in the exported bundle so
   `ALL_RUNTIME_HOOKS` (`tools/frida_runner.py`) includes it.
3. Emit events with a stable `kind` (e.g. `"crypto.new_hook"`) so
   downstream agents can filter (`e.kind.startswith("crypto.")`
   pattern per `orchestrator.py:1110-1115`).
4. If evidence needs screenshots, call the runner's screenshot RPC —
   the file paths surface via `ctx.sources["frida_screenshots"]`.

### 10.4 Add a deterministic report recipe

1. Open `sentinel/agents/reporting/enrich.py`.
2. Add an `_evidence_matched_recipe` branch (`enrich.py:1365`) or a
   new `render_*` function following
   `render_deep_link_auth_gated` (`enrich.py:1100`).
3. Extend `_strict_template_fallback` (`enrich.py:1158-1205`) to
   route to your new renderer when the AGENT_ID + evidence shape
   match.
4. Wire the recipe into `_has_runtime_locked_template`
   (`enrich.py:1206`) so it wins over the LLM narrative.

### 10.5 Testing conventions

* Layout: `tests/unit/…` (fast, no I/O), `tests/integration/…`
  (real tools), `tests/parity/…` (Djini-parity vs reference outputs).
* Framework: pytest + `pytest-asyncio` (see `pyproject.toml`).
* Fixtures: session-scoped `MemoryInterface` fake at
  `tests/conftest.py`.
* Every agent should have at minimum: applicability test,
  positive-detection test, negative test (no false positive on
  benign fixture), Finding-schema validation test.
* Golden reports live under `tests/golden/` — regenerate with the
  `scripts/dump_reports.py` helper.

### 10.6 CLI reference

Entrypoint `sentinel/cli.py:_run_scan:333`. Common flags:

| Flag                       | Effect                                              |
|----------------------------|-----------------------------------------------------|
| `<apk_path>`               | Positional — APK to scan.                           |
| `--dynamic`                | Enable Phase 4 (mitmproxy + ADB).                   |
| `--no-proxy`               | Skip mitmproxy inside Phase 4 (anti-MITM apps).     |
| `--frida`                  | Enable Phase 4.5 Frida sub-phase.                   |
| `--frida-spawn`            | Start app paused so hooks load before app main.     |
| `--dynamic-duration N`     | Seconds for the DAST capture window.                |
| `--frida-duration N`       | Seconds for the Frida capture window.               |
| `--ui-driver monkey\|appium` | Autonomous UI driver during Phase 4.              |
| `--triage`                 | Enable Phase 3 LLM triage.                          |
| `--private`                | Force local LLM only (skip Groq + Cerebras).        |
| `--learning-dir DIR`       | Enable per-app learning profile.                    |
| `--fuzz`                   | Enable Phase 4.7 AFL++ fuzz.                        |
| `--keep-workspace`         | Preserve `<workspace>/<session>/` after cleanup.    |
| `--scope FILE`             | Load BountyScope YAML.                              |
| `--device-serial S`        | Pin a specific device serial.                       |
| `--report-timeout N`       | Override `SENTINEL_REPORT_TIMEOUT_SECONDS`.         |

Reports land at `<workspace>/<session_id>/reports/VAPT_Report_<session>.{md,html,json,sarif}`
plus PoC artifacts at `<workspace>/<session_id>/poc/` and
`<workspace>/<session_id>/poc_artifacts/`.

---

*End of SENTINEL Complete Technical Reference.*
