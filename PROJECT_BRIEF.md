# SENTINEL — Complete Project Brief

> Prepared for external LLM ingestion (Kimi / GPT / etc.).
> Everything you need to understand what SENTINEL is, how it works, and where it is today, in one file.

---

## Table of contents
1. Elevator pitch
2. Why it exists
3. Design principles
4. Tech stack
5. High-level architecture
6. The 10-phase pipeline (phases 4.5 and 7.5 included)
7. Agent catalogue (detection agents)
8. Core data model
9. Memory bus (3 tiers)
10. LLM router state machine
11. FastAPI endpoints
12. CLI reference
13. Exploit driver end-to-end
14. Autonomous UI driver (Phase 4.5)
15. Verification & anti-hallucination
16. Correlation & attack chains
17. Reporting subsystem
18. Frontend
19. Security hardening
20. Repository layout
21. Testing / dev workflow
22. Recent milestones
23. Roadmap & known gaps
24. Legal

---

## 1. Elevator pitch
**SENTINEL** is an open-source, autonomous, multi-agent **mobile-application security platform**. You feed it an Android APK; it runs a **10-phase pipeline** combining decompilation, SAST, DAST, Frida instrumentation, LLM reasoning, verification, correlation, active exploitation and report generation — and emits scope-filtered, severity-rated, bug-bounty-ready findings.

- **detection agents** across 14 categories, dispatched dynamically
- **Local-first LLM stack** (local vLLM → Groq → Cerebras → Ollama) with circuit-breaker failover
- **Sprint-driven**: framework + core agents shipped; category agents landing sprint-by-sprint
- **CLI + FastAPI + web UI** — single source of truth for both terminals and browsers

## 2. Why it exists
Mobile pen-testing today is a manual, expensive, expert-only workflow. SENTINEL's thesis: a **swarm of narrow, purpose-built agents** — each a small Python program with an LLM co-pilot — can automate ~80 % of that workflow with no cloud dependency in `--private` mode. Target users:

- Solo bug-bounty hunters who want production-grade output
- Security teams that need a CI regression gate on their own apps (`sentinel diff`)
- Educators and students studying mobile app security

## 3. Design principles

1. **Local-first.** Local vLLM/TensorRT-LLM primary → Groq → Cerebras → Ollama `qwen2.5-coder:7b-instruct-q4_K_M` fallback. Circuit breaker per provider. Community tier requires local GPU; Pro/Enterprise include managed inference.
2. **Autonomous but auditable.** Every phase, agent, LLM call, and decision is logged as an event on the memory bus. Nothing is a black box.
3. **Scope-first.** Every finding is validated against a parsed `BountyScope` **before** it reaches storage. Out-of-scope drops silently inside `BaseAgent.run` — you can never accidentally ship an out-of-scope H1 report.
4. **Pluggable memory.** Same `MemoryInterface` works for a laptop (SQLite / Chroma / NetworkX) and a SaaS (Redis / Qdrant / Neo4j).
5. **Hardened by construction.** Pydantic `extra="forbid"`, `str_max_length=10_000`, `SecretStr` API keys, SSRF-safe URL fetches, CORS locked, 600 MB request cap, no stack traces leaked.
6. **Sprint-driven skeleton.** Core framework + orchestrator + memory + LLM router are done. Detection agents land category-by-category each sprint.

## 4. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12 (>=3.12, <3.13) | pinned in `pyproject.toml` |
| Web API | FastAPI 0.115 + Uvicorn (uvloop) | async, docs-for-free |
| CLI | Click 8 + Rich 13 | typed commands, colour output |
| Config | pydantic-settings 2, `.env` | typed config, per-env override |
| Data model | Pydantic 2 (`extra="forbid"`, `SecretStr`) | strict validation |
| Async I/O | httpx 0.27, aiofiles 25 | HTTP + FS |
| Decompilation | JADX, apktool, androguard 4.1.2 | Android RE toolchain |
| SAST | Semgrep 1.163 + tree-sitter 0.23 (+ tree-sitter-java 0.23.5) | AST + backward-slice taint |
| DAST | Frida **16.5.7** SDK (frida-server 17.6.1 binary shipped), mitmproxy 12.2.3 | runtime hooks + MITM |
| LLM | local vLLM → Groq → Cerebras → Ollama | local-first with cloud fallback |
| Memory — light | SQLite (aiosqlite), ChromaDB 0.5, NetworkX 3.4 | default install |
| Memory — prod | Redis 5 (extra), Qdrant, Neo4j | via `production` extra |
| Auth | python-jose (JWT, cryptography), passlib+bcrypt | API auth |
| Frontend | vanilla JS + web components (served at `/ui/`) | zero build step |
| Symbolic exec | z3-solver (`symbolic` extra) | for `D_052 SymbolicIntentAgent` |
| Diff / patches | unidiff 0.7.5 | `--generate-patch` mode |
| Testing | pytest 8, pytest-asyncio, pytest-cov, fakeredis 2.26 | full async suite |
| Lint | ruff 0.7, mypy 1.13, pre-commit 4 | strict |
| Packaging | Poetry, entry point `sentinel = "sentinel.cli:main"` | slim default install |

Poetry extras:
- `production` — installs `redis` for the prod memory backend
- `symbolic` — installs `z3-solver` (~80 MB) for `D_052`

## 5. High-level architecture

```
┌───────────┐   ┌───────────────────────────────────────────┐
│ CLI       │   │           FastAPI gateway                 │
│ Web GUI   │──▶│ /scans /agents /scope /reports /health    │
│           │   │ /status /auth /devices /ui                │
└───────────┘   └────────────────────┬──────────────────────┘
                                     ▼
                     ┌───────────────────────────────┐
                     │       Orchestrator            │
                     │  Phase 0 → 9, per session_id  │
                     └──┬───────┬────────┬───────┬───┘
                        ▼       ▼        ▼       ▼
                   Decompile Agents   Memory   LLM
                   (JADX,    (88     3-tier   Router
                   apktool,  agents, T1 SQLite (Cerebras
                   andro-    dynamic T2 vector  → Groq
                   guard)    dispatch T3 graph) → Ollama)
```

A scan = one **`session_id`**. Every event, finding, embedding, and graph node is keyed by it — parallel scans never crosstalk.

Key files:

- `sentinel/api/app.py` — FastAPI app + audit-log middleware (pure ASGI, safe on shutdown)
- `sentinel/api/routes/{scans,agents,scope,reports,auth,devices}.py` — endpoint modules
- `sentinel/core/orchestrator.py` — `Orchestrator`, `ScanResult`, `OrchestratorError`, phase driver
- `sentinel/core/finding.py` — `Finding`, `BountyScope`, `Severity`, `TriageState`, host matcher, `derive_verification_state`
- `sentinel/core/scan_context.py` — per-session shared state
- `sentinel/core/dynamic_dispatch.py` — agent-registry dispatcher
- `sentinel/core/diff.py`, `sentinel/core/dedup.py`, `sentinel/core/baseline_store.py` — regression gate
- `sentinel/core/ast_cache.py` — tree-sitter AST cache
- `sentinel/cli.py` — Click entry point

## 6. The 10-phase pipeline (with 4.5 and 7.5)

Each phase emits `phase.started` / `phase.completed` events plus per-agent `agent.started` / `agent.completed` / `agent.failed` events on the memory bus.

| # | Phase | State | Detail |
|---|---|---|---|
| 0 | **Ingestion** | ✅ | SHA-256, size cap (600 MB), per-session workspace, APK fingerprint |
| 1 | **Recon** | ✅ | JADX decompile + apktool decode + androguard manifest / permissions / components / cert chain |
| 2 | **Static (SAST)** | 🚧 (framework + `TEST_001` + `SG_001` + `TAINT_001`) | Pattern + LLM detection on decompiled code |
| 3 | **Dynamic (DAST)** | 🚧 | Frida hooks, runtime taint, instrumented APK execution |
| 4 | **Behavioural / traffic** | 🚧 | mitmproxy capture, REST/GraphQL fuzzing, OpenAPI inference |
| 4.5 | **Autonomous UI driver** | ✅ | `UIDriver` protocol (`NoOp`, `Monkey`) exercises the app to generate traffic for Phase 4 |
| 5 | **Verification** | 🚧 | `VER_001` re-runs the actual tooling to kill LLM hallucinations; `HON_001` injects fake bugs to calibrate confidence |
| 6 | **Triage** | 🚧 | Severity recalibration, dedup, finding-cluster analysis |
| 7 | **Correlation** | 🚧 | NetworkX / Neo4j chain builder — low + low → critical |
| 7.5 | **Active exploitation** | ✅ | `ExploitDriver` promotes API findings; PoC generator emits API-replay + deep-link templates; replay logs surfaced to UI |
| 8 | **Reporting** | 🚧 (`R_001` wired, 600 s timeout guard) | HackerOne / Bugcrowd-formatted markdown |
| 9 | **Meta-exploration** | 🚧 | `M_001` — time-bounded autonomous research for novel issues |

## 7. Agent catalogue

Registry is the source of truth at `GET /agents`. Prefixes:

| Prefix | Category | Count | Sample agents |
|---|---|---|---|
| `A_*` | Authentication | 12 | hardcoded creds, JWT alg confusion, biometric bypass |
| `C_*` | Crypto / Storage | 14 | ECB, static IV, hardcoded keys, Keystore misuse |
| `N_*` | Network | 11 | cleartext HTTP, missing pinning, hostname verifier off |
| `F_*` | Firebase | 1 | public RTDB / Firestore / Storage |
| `B_*` | Business logic | 5 | IDOR, mass assignment, TOCTOU, receipt forgery |
| `P_*` | Platform / IPC | 4 | `P_001` deep-link hijack, `P_004` content-provider IDOR, `P_010` intent redirect (CWE-926, tree-sitter AST), `IPC_001` exported-component exposure |
| `API_*` | Backend API | 4 | `API_001` OpenAPI inference, `API_002` BOLA replay (mutates IDs ±1 / canary), `API_003` mass-assignment fuzzer (`is_admin`, `role`, `price`, `balance`, `dob`), `API_004` excessive data exposure (SAST↔DAST cross-ref) |
| `SG_*` | Semgrep AST SAST | 1 | 18 YAML rules: WebView, crypto, TLS, storage, SQLi, cmd injection |
| `SCA_*` | Supply chain | 1 | offline OSV.dev Maven CVE scanner |
| `TAINT_*` | Data-flow taint | 1 | tree-sitter backward-slice, 3-hop IPA, sanitizer-aware, full source→sink traces |
| `RN_*` | React Native | 1 | JS bundle audit, Hermes-magic detection + short-circuit, AsyncStorage, cleartext, secrets, WebView, `dangerouslySetInnerHTML` |
| `FL_*` | Flutter (experimental) | 1 | `libapp.so` string-level audit; emits `FLUTTER_ANALYSIS_EXPERIMENTAL` notice |
| `S_*` | Scope | 1 | `S_001` bounty-scope ingestion (5 platforms) |
| Meta | `R_*`, `M_*`, `VER_*`, `HON_*`, `TEST_*` | 5 | report gen, meta-exploration, hallucination killer, honeypot, smoke test |

On-disk subdirectories under `sentinel/agents/`:
`auth/ crypto/ network/ firebase/ business/ logic/ platform/ api_security/ dynamic/ deep_links/ webview/ taint/ semgrep/ supply_chain/ crossplatform/ cert_pinning/ cloud/ ai/ native/ wireless/ deserialization/ privacy/ reflection/ reporting/ resilience/ random_gen/ data_storage/ shared_prefs/ auth_storage/ backup/ correlation/ meta/ special/ logging/ ui/ base/`.

**All agents extend `BaseAgent`** (`sentinel/agents/base/base_agent.py`), which enforces:
- `session_id` and `agent_id` validation
- Scope check on every emitted finding
- Automatic event emission on the memory bus
- Structured error capture

## 8. Core data model

### `Finding` (Pydantic 2, `extra="forbid"`)

Fields:
- `id`, `agent_id`, `session_id`
- `severity` — `Info | Low | Medium | High | Critical`
- `category`, `title`, `description`
- `evidence[]`, `remediation`, `cwe[]`, `cvss`, `owasp_mobile[]`
- `triage_state` — `New | Verified | False | Duplicate`
- `finding_category` — enum for dual UI rendering (API vs code vs runtime)
- **Exploitation fields (added Sprint recent):**
  - `exploitation_status`
  - `exploit_context`
  - `exploit_artifacts[]`
  - `api_replay_logs[]`

Helpers: `derive_verification_state(finding)` folds `triage_state` + verification agents' output into a single UI-facing state.

### `BountyScope`

Parses HackerOne / Bugcrowd / Intigriti / YesWeHack / Immunefi program pages. `_matches_host(host, pattern)` gates every finding at the `BaseAgent` boundary. URL fetches are **SSRF-safe** — no localhost, no RFC1918, no `file://`.

### `ScanContext` / `ScanResult`

`ScanContext` is a per-session dataclass carried through all 10 phases: workspace path, decompiled roots, agent registry, memory handle, LLM router handle, scope, `ScanResult` accumulator.
`ScanResult` bundles final findings, timings, phase events, and generated report paths.

## 9. Memory bus (3 tiers)

| Tier | Purpose | Lightweight | Production |
|---|---|---|---|
| **T1** | Events + findings + audit log | SQLite (aiosqlite) | Redis + Postgres |
| **T2** | Vector search (LLM RAG) | ChromaDB | Qdrant |
| **T3** | Attack-graph correlation | NetworkX | Neo4j |

Both backends implement the same `MemoryInterface` (`sentinel/memory/interface.py`). Files:
- `sentinel/memory/lightweight.py` — default
- `sentinel/memory/production.py` — stubbed for Sprint 11

Data flow inside a scan:
1. Orchestrator writes `phase.started` → T1
2. Agent emits `agent.started` → T1
3. Agent produces raw evidence → T2 (embedding) for later RAG queries by verification / correlation / report agents
4. Agent produces `Finding` → T1 (persisted) + T3 (graph node, edges to related findings)
5. On `phase.completed`, Orchestrator advances

Correlation phase queries T3 for chains: e.g. `Finding(A_003 hardcoded API key)` → node → edge to `Finding(N_002 cleartext /login)` → chain severity elevated Medium → Critical.

## 10. LLM router state machine

`sentinel/llm/router.py` + helpers `remediation.py`, `severity_rationale.py`.

**Providers (in order):**
1. **Local vLLM/TensorRT-LLM** — `SENTINEL_LOCAL_LLM_URL` (preferred)
2. **Groq** — Llama 3.3 70B (if key set)
3. **Cerebras** — Llama 3.3 70B (if key set)
4. **Ollama** — local `qwen2.5-coder:7b-instruct-q4_K_M` (always-on fallback)

**Circuit breaker per provider (per session):**

```
                ┌──── CLOSED ────┐
                │  provider live │
                └────┬────┬──────┘
     429 rate limit  │    │  hard error (auth, model-missing)
     ≤ 3 attempts    │    │
                     ▼    ▼
              ┌── HALF-OPEN ──┐
              │ retry, exp    │
              │ backoff       │
              └──────┬────────┘
                     │  fail again
                     ▼
              ┌──── OPEN ─────┐
              │ session-perm  │
              │ disabled      │
              └──────┬────────┘
                     │
                     ▼
              next provider in chain
```

Observed real-world events (from your recent scan logs):
- `Groq 429 (rate limit), attempt 1/2/3` — soft transient, retries
- `[cerebras] permanently disabled this session: model 'llama-3.3-70b' not available on this account` — hard, permanent for session, falls through to Groq / Ollama
- `Ollama error (ReadTimeout @ http://127.0.0.1:11434, model=qwen2.5-coder:7b-instruct-q4_K_M): ReadTimeout` — bubble up, agent marks LLM inconclusive

## 11. FastAPI endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service info + legal disclaimer |
| GET | `/health` | Liveness |
| GET | `/status` | Runtime stats |
| GET | `/agents` | Full multi-agent registry |
| POST | `/scope` | Ingest bounty-scope URL, return parsed `BountyScope` |
| POST | `/scans` | Start scan |
| GET | `/scans` | List scans |
| GET | `/scans/{id}` | Scan state + timing |
| GET | `/scans/{id}/findings` | Emitted findings |
| GET | `/scans/{id}/result` | Full `ScanResult` |
| GET | `/reports` | List generated reports |
| `/auth/*` | Registration, login, JWT | JOSE / bcrypt |
| `/devices/*` | Connected physical / emulated devices | Frida target discovery |
| GET | `/ui/*` | Static frontend (cache-busted) | |

Docs auto-generated at `/docs`.

## 12. CLI reference

Entry point: `sentinel = "sentinel.cli:main"`.

```
sentinel serve                          # start FastAPI gateway
sentinel scan <apk> \
              [--scope <url>] \
              [--private] \             # skip cloud LLM, force Ollama
              [--generate-patch] \      # AI-suggested unified diffs per VERIFIED finding
              [--ui-driver noop|monkey] # Phase 4.5 driver

sentinel scope <url>                    # parse bounty-scope page → BountyScope JSON
sentinel agents                         # list registry
sentinel status                         # runtime info

sentinel diff --base OLD.apk \
              --head NEW.apk \
              [--fail-on critical,high] \
              [--format markdown|json]  # CI regression gate; non-zero on any new finding
```

## 13. Exploit driver end-to-end (Phase 7.5)

Files: `sentinel/exploit/{driver,drivers,poc_generator,poc_studio,models,prompts,safety}.py`.

**Data model** (`models.py`):
- `ExploitFormat` — enum (`api_replay`, `deeplink_intent`, `frida_python`, `shell_curl`, `html_xss`, `markdown`)
- `ExploitContext` — target, finding ref, credentials, scope, technique
- `ExploitArtifact` — file path, format, provenance

**Safety gate** (`safety.py`):
- `ensure_authorized(ctx)` → `AuthorizationError` unless scope permits the technique
- `_is_blanket(scope)` — recognises "test anything owned by X" scopes
- `_technique_for(ctx)` — maps finding category → technique class

**Sub-drivers** (`drivers.py`):
- `RaceConditionDriver` — TOCTOU exploit
- `IdorDriver` — perturbs IDs (±1, canary token) via `_perturb_id()`
- `DeepLinkDriver` — crafts intent that hits a hijackable component
- Registered via `_register()`; retrieved by finding via `driver_for(agent_id)`; enumerable via `supported_agent_ids()`

**Main driver** (`driver.py`):
- `ExploitDriver` — top-level orchestrator for a single finding
- `ExploitOutcome` — dataclass wrapping `success`, `evidence[]`, `artifacts[]`, `notes`
- `_LoopbackListener` — spins a local HTTP listener to catch redirect / callback payloads
- `_NoAuth` — sentinel indicating unauthenticated technique

**PoC generator** (`poc_generator.py`):
- `PoCGenerator` — high-level; picks format via `_is_deeplink_finding()` and `_is_token_or_storage_finding()`
- Emits `PoCArtifact` per finding
- Helpers: `_slug`, `_fallback_deeplink`, `_redact_and_placeholder` (redacts secrets and inserts placeholders), `_pyquote / _jsquote / _shquote` (safe embedding into Python / JS / shell PoCs)

**PoC studio** (`poc_studio.py`) — legacy/higher-level façade:
- `studio_can_handle(finding)` — capability check
- `_pick_format(finding)` — heuristic
- Format writers: `_write_frida_python`, `_write_shell_curl`, `_write_html_xss`, `_write_markdown_only`
- Top-level: `emit_for_finding(finding, ...)`, `emit_for_scan(scan, ...)`

**Prompts** (`prompts.py`):
- `render_user_prompt(ctx)` — builds LLM prompt from `ExploitContext`

**End-to-end flow inside orchestrator's `_phase7_5_active_exploitation()`:**

1. Iterate `scan.findings` where `finding_category in {api, deeplink, ...}` and `triage_state == Verified`
2. `ensure_authorized(ctx)` — bail if out-of-scope
3. `driver = driver_for(finding.agent_id)`; if none, fall through to PoC-only
4. `outcome = driver.execute(ctx)` — actual replay attempt (BOLA ID perturbation, deep-link fire, etc.)
5. Attach `outcome.evidence` to `finding.api_replay_logs`
6. Update `finding.exploitation_status` (`attempted / succeeded / blocked / not_applicable`)
7. `PoCGenerator().emit(finding)` — writes PoC file to `output/poc/<finding_id>.<ext>`
8. Store `PoCArtifact` in `finding.exploit_artifacts`
9. Emit `phase.completed` with counts

Result: the report can render a **live** "Exploitation Proof" section with the actual HTTP round-trip that succeeded, plus a runnable PoC file the triager can execute.

## 14. Autonomous UI driver (Phase 4.5)

Files: `sentinel/monitor/` (contains `UIDriver` protocol + implementations).

**Protocol:** `UIDriver.start(session_ctx)`, `.step()`, `.stop()`.

**Implementations:**
- `NoOp` — default; assumes traffic is generated externally (e.g. tester driving app manually)
- `Monkey` — invokes Android's `monkey` tool with a bounded seed / event count; catches `IntentReceiver` crashes as evidence

**Wired into orchestrator Phase 4:** the mitmproxy capture window starts, the UI driver runs concurrently for a bounded time, then stops → captured traffic feeds Phase 4 fuzzers and `API_001` OpenAPI inference.

CLI flag: `--ui-driver noop|monkey`.

## 15. Verification & anti-hallucination

- `VER_001` (verification agent) re-runs the **actual tooling** that would confirm a finding — e.g. for a "hardcoded API key" finding, it fires a real request to the corresponding API with the extracted key and observes the response. Only findings that survive re-verification are marked `Verified`.
- `HON_001` (honeypot) injects synthetic "obvious fake" findings into the input stream to calibrate LLM confidence. If the model calls a honeypot `Verified`, its scores are down-weighted for the session.
- Every LLM call includes the finding evidence context; the router logs the raw prompt + response for post-hoc review.

## 16. Correlation & attack chains

`sentinel/correlation/` builds a directed graph on T3:
- Node = `Finding`
- Edge = derived relationship (`same-host`, `same-component`, `secret-leaks-into`, `token-authorises`)

Chain rules (simplified):
- `A_003 (secret) + N_002 (cleartext channel)` → severity elevated
- `B_001 (IDOR) + A_004 (weak session)` → account takeover chain
- `P_001 (deep-link hijack) + WebView-JS-bridge finding` → RCE chain

Emitted chains appear as **synthetic findings** with links back to their constituent findings, which the reporter renders as a numbered attack narrative.

## 17. Reporting subsystem

`sentinel/reports/` — `R_001` report generator.

- Format: HackerOne / Bugcrowd-flavoured markdown per finding + a top-level scan summary
- Includes: severity, CVSS, CWE, OWASP MASVS mapping, evidence excerpts, exploitation proof, remediation
- Attaches PoC file references and API-replay logs
- 600 s timeout per report — orchestrator logs `[<sid>] Phase 8 report generation timed out after 600s` if exceeded and cancels safely
- Persisted under `reports/` and surfaced via `GET /reports`

## 18. Frontend

`frontend/` — vanilla JS + web components, no build step.

Key components under `frontend/ui/js/components/`:
- `finding-detail-view.js` — canonical finding view; renders exploitation-proof section, API-replay table, screenshots
- `screenshot-carousel.js`
- `compliance-panel.js` — MASVS / OWASP mapping
- `impact-badge.js` — severity + business impact
- `repro-recipes.js` — steps to reproduce
- `swarm-panel.js` — live per-agent progress

Cache-busted via the middleware (`Cache-Control: no-store, max-age=0` on `/ui/*`) so edits are always fresh.

## 19. Security hardening

- **Scope enforcement** at `BaseAgent.run` — cannot bypass
- **SSRF-safe scope ingestion** — pre-validates URLs (no localhost, no RFC1918, no `file://`)
- **Pydantic hardening** — `extra="forbid"`, `str_max_length=10_000`, validator-checked agent + session IDs; blocks malicious APK content from poisoning reports
- **CORS locked** to configured origins (default localhost) — prevents victim-browser-driven scanner abuse
- **600 MB request body cap** — APK upload DoS guard
- **API secrets as `SecretStr`** — never appear in logs, `repr`, or tracebacks
- **Global exception handler** — swallows stack traces, clients get `{"error":"internal_error","detail":"see server logs"}`
- **Audit-log middleware** rewritten as **pure ASGI** (`_AuditLogMiddleware`) to eliminate Starlette `BaseHTTPMiddleware` shutdown races (`anyio.WouldBlock` → `CancelledError` tracebacks on CTRL+C)
- **Cache-busting headers** on `/ui/*`
- **Exploit driver safety gate** — `ensure_authorized()` blocks any technique against out-of-scope hosts
- **PoC secret redaction** — `_redact_and_placeholder` replaces real credentials with placeholders in shared PoC files
- **Legal disclaimer** on `GET /` — authorised testing only

## 20. Repository layout

```
sentinel/
├── sentinel/                            # Main Python package
│   ├── api/                             # FastAPI app
│   │   ├── app.py                       # gateway + pure-ASGI audit-log middleware
│   │   └── routes/{scans,agents,scope,reports,auth,devices}.py
│   ├── cli.py                           # Click entry point
│   ├── core/                            # orchestrator + models
│   │   ├── orchestrator.py              # 10-phase driver
│   │   ├── finding.py                   # Finding, BountyScope, Severity, TriageState
│   │   ├── scan_context.py
│   │   ├── config.py                    # Settings
│   │   ├── dynamic_dispatch.py          # agent registry
│   │   ├── ast_cache.py                 # tree-sitter cache
│   │   ├── diff.py / dedup.py / baseline_store.py / delta.py
│   ├── agents/                          # detection agents (35 category subdirs)
│   │   ├── base/base_agent.py           # contract
│   │   ├── auth/ crypto/ network/ firebase/ business/ logic/
│   │   ├── platform/ api_security/ dynamic/ deep_links/ webview/
│   │   ├── taint/ semgrep/ supply_chain/ crossplatform/
│   │   ├── cert_pinning/ cloud/ ai/ native/ wireless/
│   │   ├── deserialization/ privacy/ reflection/ reporting/
│   │   ├── resilience/ random_gen/ data_storage/ shared_prefs/
│   │   ├── auth_storage/ backup/ correlation/ meta/ special/
│   │   └── logging/ ui/
│   ├── llm/                             # router + failover
│   │   ├── router.py
│   │   ├── remediation.py
│   │   └── severity_rationale.py
│   ├── memory/                          # 3-tier bus
│   │   ├── interface.py
│   │   ├── lightweight.py               # SQLite + Chroma + NetworkX
│   │   └── production.py                # Redis + Qdrant + Neo4j (stubbed)
│   ├── exploit/                         # Phase 7.5
│   │   ├── driver.py                    # ExploitDriver, ExploitOutcome, _LoopbackListener
│   │   ├── drivers.py                   # RaceCondition / Idor / DeepLink sub-drivers
│   │   ├── poc_generator.py             # PoCGenerator (new)
│   │   ├── poc_studio.py                # emit_for_finding / emit_for_scan (legacy)
│   │   ├── models.py                    # ExploitFormat / ExploitContext / ExploitArtifact
│   │   ├── prompts.py                   # render_user_prompt
│   │   └── safety.py                    # ensure_authorized, technique gating
│   ├── monitor/                         # Phase 4.5 UIDriver
│   ├── fuzz/                            # mass-assignment + BOLA fuzzers
│   ├── verify/                          # VER_001, HON_001
│   ├── correlation/                     # attack-chain builder
│   ├── reports/                         # R_001
│   ├── scope/                           # S_001
│   ├── planner/ apex/ symbolic/ rag/ safety/ tenancy/
│   ├── swarm/ learning/ knowledge/ remediation/ triage/ impact/
│   ├── compliance/ profiles/ tools/ devices/ auth/
├── frontend/                            # vanilla JS + web components
│   └── ui/js/components/*.js
├── tests/                               # pytest suite
├── docs/                                # per-agent / feature docs
├── rules/                               # Semgrep YAML rules
├── migrations/
├── scripts/
├── workspace/                           # per-session working dir
├── reports/                             # generated reports
├── frida_agent/                         # Frida hook scripts
├── frida-server-17.6.1-android-arm64    # shipped binary
├── pyproject.toml, poetry.lock, docker-compose.yml
├── README.md, AboutSentinel.md, AllAbout.md, BUSINESS_TECHNICAL_DOSSIER.md,
├── Complete_SAST_Design.md, StaticAnalysis_Deep_Dive.md, FRIDA_UPGRADE.md, BUILD.md
├── graphify-out/                        # knowledge graph of the codebase
└── CLAUDE.md                            # AI-coding-assistant instructions
```

## 21. Testing / dev workflow

- **Tests:** `poetry run pytest`
- **Async tests:** `pytest-asyncio`
- **Coverage:** `pytest-cov`
- **Redis mocking:** `fakeredis`
- **Lint:** `poetry run ruff check .`
- **Types:** `poetry run mypy sentinel`
- **Pre-commit hooks:** `pre-commit install`

Ruff config: `line-length = 120`, `target-version = py312`, selects `E F W I B`, ignores `E501 B008 B904`.

## 22. Recent milestones (Jul 2026)

- Finding model extended with **4 exploitation fields**
- `APITrafficMap` dataclass + `build_traffic_map()` factory
- **ExploitDriver** promotes API findings end-to-end
- **PoC generator** emits API-replay + deep-link templates + Frida-Python / shell-curl / HTML-XSS / markdown
- **Phase 7.5** (active exploitation) integrated into orchestrator
- Mass-assignment fuzzer expanded: **balance payload** + **DOB PII detection**
- BOLA verifier + mass-assignment fuzzer surface **API-replay logs** to frontend
- **Autonomous UI driver** — `UIDriver` protocol with NoOp + Monkey; `finding_category` enum for dual rendering; wired into Phase 4 capture window; CLI parameter added
- `API_002 / 003 / 004` slotted under `api_security/` path
- **Exploitation-Proof section** + **API-Replay table** rendered in Finding Detail View
- Comprehensive PoC-generator unit tests added
- **Audit-log middleware** fix — pure ASGI, no shutdown traceback (`anyio.WouldBlock` → `CancelledError` bug on CTRL+C eliminated)


## 23. Roadmap & known gaps

- **Phases 2–9 detection agents** — sprint 3+ fills each category with real `BaseAgent` subclasses (skeleton dirs mostly present)
- **Production memory backend** (Redis + Qdrant + Neo4j) — stubbed, scheduled Sprint 11
- **iOS support** — planned
- **Web GUI** — placeholder → active enhancement (finding detail view, screenshot carousel, compliance panel etc. landing)
- **`--generate-patch`** — experimental; AI-suggested unified diffs against decompiled code, human-review required, never auto-applied
- **Report generation** — occasional 600 s timeouts on large scans; needs streaming rewrite

## 24. Legal

Authorised security testing only — CTF, your own apps, or explicit written scope in a bug-bounty program. Local-first LLM stack ensures no data leaves your machine in `--private` mode. Authors assume **no liability** for misuse. Always respect the bug-bounty program's scope. Disclaimer pinned on `GET /`, every PoC file, and every generated report.
