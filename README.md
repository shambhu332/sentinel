# SENTINEL

**Open-source, autonomous, multi-agent mobile-application security platform.**

SENTINEL ingests an Android APK (iOS support planned), runs it through a
10-phase pipeline of decompilation + static + LLM-driven analysis, and emits
structured, scope-filtered, severity-rated findings ready for a bug-bounty
report.

The project is designed to be **free to run locally**: it uses a free-tier
Cerebras Cloud LLM as primary, with a local Ollama model as automatic fallback,
so a full scan costs nothing beyond your own electricity.

> ⚠️ **Legal — read this first.** SENTINEL is for **authorised** security
> testing, CTF practice, your own apps, or programs whose written scope grants
> you permission. Running it against third-party apps without written consent
> may violate computer-misuse, copyright, or DMCA-style laws in your
> jurisdiction. Always respect the bug-bounty program's scope. The authors
> assume **no liability** for misuse.

---

## Table of contents

- [Status](#status)
- [Highlights](#highlights)
- [Architecture overview](#architecture-overview)
- [The 10-phase pipeline](#the-10-phase-pipeline)
- [Agent catalogue](#agent-catalogue)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration (.env)](#configuration-env)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [HTTP API](#http-api)
- [Bug-bounty scope handling](#bug-bounty-scope-handling)
- [Memory architecture (3 tiers)](#memory-architecture-3-tiers)
- [LLM router & failover](#llm-router--failover)
- [Data model — Finding & BountyScope](#data-model--finding--bountyscope)
- [Writing a new agent](#writing-a-new-agent)
- [Testing](#testing)
- [Development workflow](#development-workflow)
- [Roadmap](#roadmap)
- [Security & privacy](#security--privacy)
- [License & disclaimer](#license--disclaimer)

---

## Status

SENTINEL is an **active, sprint-driven build**. The skeleton is in place; the
detection agents are landing one sprint at a time.

| Layer                              | State                                                              |
| ---------------------------------- | ------------------------------------------------------------------ |
| Core data model (Finding/Scope)    | ✅ Implemented + tested                                             |
| Configuration / `Settings`         | ✅                                                                  |
| FastAPI gateway (`/scans`, `/agents`, `/scope`, `/health`, `/status`) | ✅ Stub `/scans` + live `/agents`, `/scope`         |
| CLI (`sentinel serve / scope / agents / status`) | ✅                                                  |
| Scope parser S_001 (5 platforms)   | ✅                                                                  |
| LLM router (Cerebras → Ollama)     | ✅                                                                  |
| BaseAgent contract                 | ✅                                                                  |
| Memory bus — Lightweight (SQLite + Chroma + NetworkX) | ✅                                              |
| Memory bus — Production (Redis + Qdrant + Neo4j) | 🚧 stubbed, scheduled for Sprint 11             |
| Phase 0 (ingest) + Phase 1 (recon) | ✅ JADX + apktool + androguard wired                                |
| Phase 2 — TEST_001 smoke agent     | ✅                                                                  |
| Phases 2–9 — real detection agents | 🚧 Sprint 3+                                                        |
| Frontend (web GUI)                 | 🚧 placeholder                                                      |
| iOS support                        | 🚧 planned                                                          |

---

## Highlights

- **88-agent design** across 14 categories (Auth, Crypto/Storage, Network,
  Firebase, Business Logic, Privacy, Platform, Native, Cloud, AI, Wireless,
  Deserialization, Supply Chain, Special/Meta).
- **10-phase pipeline** — ingestion → recon → static → dynamic → behavioural
  → verification → triage → correlation → reporting → meta-exploration.
- **Pluggable memory** — same `MemoryInterface` abstraction works for solo
  laptops (SQLite/Chroma/NetworkX) and SaaS deployments (Redis/Qdrant/Neo4j).
- **Free-tier-first LLM stack** — Cerebras Llama 3.3 70B primary, local
  Ollama (`qwen2.5-coder:7b`) fallback, automatic circuit-breaker failover.
- **Strict scope enforcement** — every finding is gated against a parsed
  `BountyScope` *before* it reaches storage. Out-of-scope packages get dropped
  silently inside `BaseAgent.run`.
- **SSRF-safe scope ingestion** — URLs are pre-validated (no localhost, no
  RFC1918, no `file://`) before fetch.
- **Hardened pydantic models** — `extra="forbid"`, `str_max_length=10_000`,
  validator-checked agent/session IDs prevent malicious APK content from
  poisoning reports.
- **API secrets are `SecretStr`** — never appear in logs, `repr`, tracebacks.

---

## Architecture overview

```
┌──────────────┐      ┌────────────────────────────────────────────────┐
│  CLI (click) │──┐   │                FastAPI gateway                 │
│  Web GUI     │──┴──▶│  /scans  /agents  /scope  /health  /status     │
│  (planned)   │      └────────────────────────┬───────────────────────┘
└──────────────┘                               │
                                               ▼
                       ┌──────────────────────────────────────────────┐
                       │              Orchestrator                     │
                       │  Phase 0 → Phase 9, per session_id            │
                       └────────────┬─────────────────────────────────┘
                                    │
        ┌──────────────────┬────────┼────────┬────────────────┬──────────┐
        ▼                  ▼        ▼        ▼                ▼          ▼
  ┌──────────┐    ┌─────────────┐ ┌────┐ ┌──────────────┐ ┌─────────┐ ┌──────────┐
  │ JADX     │    │  apktool    │ │AGu.│ │ BaseAgent x N│ │ Memory  │ │ LLM      │
  │ decomp   │    │  resources  │ │and.│ │  (88 total)  │ │ Bus 3-T │ │ Router   │
  └──────────┘    └─────────────┘ └────┘ └──────────────┘ └─────────┘ └──────────┘
                                                                ▲
                            ┌──────────────────┬────────────────┘
                            │                  │
                       ┌────┴─────┐      ┌─────┴─────┐
                       │ T1: events│      │ T2 vector │
                       │ + findings│      │ T3 graph  │
                       │  (SQLite) │      │(Chroma/NX)│
                       └───────────┘      └───────────┘
```

A scan is one `session_id`. Every emitted event, finding, embedding, and graph
node is keyed by it, so multiple scans can run side-by-side without crosstalk.

---

## The 10-phase pipeline

| #  | Phase                | Implemented | What happens                                                              |
| -- | -------------------- | ----------- | ------------------------------------------------------------------------- |
| 0  | **Ingestion**        | ✅           | SHA-256 hash, size check, per-session workspace creation                  |
| 1  | **Recon**            | ✅           | JADX decompile + apktool decode + androguard manifest extraction          |
| 2  | **Static analysis**  | 🚧 (TEST_001 only) | Per-agent code/manifest pattern + LLM-driven detection             |
| 3  | **Dynamic analysis** | 🚧           | Frida hooks, runtime taint, instrumented APK execution                    |
| 4  | **Behavioural**      | 🚧           | mitmproxy traffic capture, GraphQL/REST fuzzing                           |
| 5  | **Verification**     | 🚧           | VER_001 re-runs tooling to detect LLM hallucinations; HON_001 honeypot    |
| 6  | **Triage**           | 🚧           | Severity recalibration, deduplication                                     |
| 7  | **Correlation**      | 🚧           | NetworkX/Neo4j chain detection: low + low → critical exploit chains       |
| 8  | **Reporting**        | 🚧           | R_001: HackerOne/Bugcrowd-formatted markdown bounty submissions           |
| 9  | **Meta-exploration** | 🚧           | M_001: time-bounded autonomous research for novel issues                  |

The orchestrator (`sentinel/core/orchestrator.py`) drives this. Each phase
emits `phase.started` / `phase.completed` events plus per-agent
`agent.started` / `agent.completed` / `agent.failed` events on the memory bus.

---

## Agent catalogue

The complete 88-agent registry is exposed at `GET /agents` and is the source
of truth — see `sentinel/api/routes/agents.py`. A condensed view:

| Cat. prefix | Category            | Count | Examples                                                |
| ----------- | ------------------- | ----- | ------------------------------------------------------- |
| `A_*`       | Authentication      | 12    | Hardcoded credentials, JWT alg confusion, biometric bypass |
| `C_*`       | Crypto / Storage    | 14    | ECB cipher, static IV, hardcoded keys, Keystore misuse  |
| `N_*`       | Network             | 11    | Cleartext HTTP, missing pinning, hostname verifier off   |
| `F_*`       | Firebase            | 1     | Public RealtimeDB / Firestore / Storage                  |
| `B_*`       | Business Logic      | 5     | IDOR, mass assignment, TOCTOU, receipt forgery           |
| `S_*`       | Scope               | 1     | S_001 — bounty-program scope ingestion                   |
| `R_*`       | Report              | 1     | R_001 — bounty report generator                          |
| `M_*`       | Meta exploration    | 1     | M_001 — autonomous vulnerability research                |
| `VER_*`     | Verification        | 1     | Re-run tooling, kill hallucinations                      |
| `HON_*`     | Honeypot            | 1     | Inject fake bugs to calibrate confidence                 |
| `TEST_*`    | Pipeline smoke test | 1     | Always emits a synthetic Info finding                    |
| `SG_*`      | Semgrep AST SAST    | 1     | SG_001 — 18 YAML rules: WebView, crypto, TLS, storage, SQLi, command injection (see `docs/SEMGREP.md`) |

> The directories `agents/auth/`, `agents/crypto/`, `agents/network/` …
> currently hold only `__init__.py` placeholders. Each sprint fills one
> category with real `BaseAgent` subclasses.

Agent IDs are **regex-validated** at instantiation time (`^[A-Z]+_\d{3}$`) —
malformed IDs raise `AgentError` before a finding is ever produced.

---

## Repository layout

```
sentinel/
├── pyproject.toml          Poetry project, ruff/mypy/pytest config
├── docker-compose.yml      Redis + Qdrant + Neo4j (production memory)
├── .env.example            Template — copy to .env and fill in
├── README.md               You are here
├── corpus/                 Real-world APKs for evaluation (gitignored)
│   ├── InsecureBankv2.apk  Reference APK for integration tests
│   └── labels.json         Ground-truth labels for evaluation
├── data/                   Runtime: SQLite, Chroma persist dir, graphs
│   ├── sentinel.db
│   ├── chroma/
│   └── graphs/<session_id>.json
├── workspace/              Per-session decompiled output (gitignored)
├── docs/                   ARCHITECTURE.md, API.md, SETUP.md, AGENT_GUIDE.md
├── rules/                  Static rule packs (android/, ios/, custom/)
├── scripts/
│   ├── verify_setup.sh     Pre-flight: jadx, apktool, ollama, models, .env
│   └── dev_scan.py         Manual end-to-end scan runner
├── sentinel/               <-- the package
│   ├── cli.py              Click entry point (`sentinel ...`)
│   ├── core/
│   │   ├── config.py           Settings + SecretStr-backed env loading
│   │   ├── finding.py          Finding, BountyScope, Severity, TriageState
│   │   ├── scan_context.py     Per-scan shared state
│   │   └── orchestrator.py     The 10-phase driver
│   ├── api/
│   │   ├── app.py              FastAPI factory + middleware
│   │   └── routes/{scans,agents,scope}.py
│   ├── llm/
│   │   └── router.py           FreeProviderRouter (Cerebras → Ollama)
│   ├── memory/
│   │   ├── interface.py        MemoryInterface ABC (3 tiers)
│   │   ├── lightweight.py      SQLite + ChromaDB + NetworkX
│   │   └── production.py       Redis + Qdrant + Neo4j (stub)
│   ├── agents/
│   │   ├── base/base_agent.py  BaseAgent contract
│   │   ├── special/test_agent.py   TEST_001 smoke agent
│   │   └── {auth,crypto,network,...}/  category packages (placeholders)
│   ├── tools/
│   │   ├── jadx.py             JADX decompiler wrapper
│   │   ├── apktool.py          apktool resources/manifest wrapper
│   │   └── manifest.py         androguard manifest parser
│   ├── scope/
│   │   └── scope_parser.py     S_001 — multi-platform bounty scope parser
│   └── apex/                   Reserved for future IR/parser layer
├── frontend/               Web UI placeholder
└── tests/
    ├── unit/               Sprint-scoped unit tests (offline)
    └── integration/        Real-APK end-to-end tests (skip if tools missing)
```

---

## Requirements

| Tool          | Version        | Used for                                |
| ------------- | -------------- | --------------------------------------- |
| **Python**    | 3.12 (only)    | Runtime — `>=3.12,<3.13` is enforced    |
| **Poetry**    | ≥ 1.7          | Dependency management                   |
| **Java**      | 17 +           | JADX, apktool, FlowDroid                |
| **JADX**      | latest         | APK → Java decompilation                |
| **apktool**   | latest         | APK → manifest + decoded resources      |
| **Ollama**    | latest         | Local LLM fallback (offline mode)       |
| Ollama models | `qwen2.5-coder:7b-instruct-q4_K_M`, `nomic-embed-text` | Code understanding + embeddings |
| FlowDroid     | latest jar     | Taint analysis (later sprints)          |

The shipped `scripts/verify_setup.sh` checks every one of these and exits
non-zero on the first missing piece.

---

## Installation

```bash
# 1. Clone
git clone <your-fork> sentinel && cd sentinel

# 2. Install Python deps
poetry install

# 3. (CachyOS / Arch) install system tools
paru -S jadx apktool jdk-openjdk ollama

# 4. Pull Ollama models (a few GB, one-time)
systemctl --user enable --now ollama
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama pull nomic-embed-text

# 5. Configure secrets
cp .env.example .env
$EDITOR .env        # paste your Cerebras free-tier key

# 6. Verify
./scripts/verify_setup.sh
```

Non-Arch distros: install JADX + apktool from your package manager, ensure
`java` and `ollama` are on `$PATH`. The Linux-specific bits are limited to
the `paru` line and the `systemctl is-active ollama` check.

---

## Configuration (.env)

| Variable                       | Default                  | Purpose                                            |
| ------------------------------ | ------------------------ | -------------------------------------------------- |
| `CEREBRAS_API_KEY`             | *(empty)*                | Primary LLM provider — get one at cloud.cerebras.ai |
| `GROQ_API_KEY`                 | *(empty)*                | Optional fallback (reserved)                        |
| `MISTRAL_API_KEY`              | *(empty)*                | Optional fallback (reserved)                        |
| `GITHUB_TOKEN`                 | *(empty)*                | For GitHub-Models provider (reserved)               |
| `OLLAMA_HOST`                  | `http://localhost:11434` | Local LLM endpoint                                  |
| `SENTINEL_LOG_LEVEL`           | `INFO`                   | DEBUG / INFO / WARNING / ERROR / CRITICAL          |
| `SENTINEL_WORKSPACE`           | `./workspace`            | Per-session decompile output root                  |
| `SENTINEL_MAX_APK_SIZE_MB`     | `500`                    | Hard upper bound on uploads (DoS guard)            |
| `SENTINEL_SCAN_TIMEOUT_SECONDS`| `1800`                   | Whole-scan timeout (30 min)                        |

All keys load through `pydantic-settings`; the API-key fields are
`SecretStr`, so they will never appear in logs, `repr`, or stack traces.

---

## Quick start

### A. Run a scan via the CLI helper script

```bash
poetry run python scripts/dev_scan.py corpus/InsecureBankv2.apk
```

This runs Phases 0–2 against `InsecureBankv2.apk` (or the path you pass),
prints the manifest summary, decompilation outcome, findings, and per-phase
timings, and stores everything in `./data/sentinel.db`.

### B. Run the API gateway

```bash
poetry run sentinel serve            # http://127.0.0.1:8000
# Browse:
#   http://127.0.0.1:8000/docs       (Swagger UI)
#   http://127.0.0.1:8000/redoc      (ReDoc)
```

### C. Parse a bug-bounty program's scope

```bash
poetry run sentinel scope parse --url https://hackerone.com/<program>
poetry run sentinel scope parse --file docs/example_scope.json
poetry run sentinel scope parse --text 'In scope: com.example.app'
```

### D. List the 88 agents (gateway must be running)

```bash
poetry run sentinel agents
poetry run sentinel agents --category Firebase
```

---

## CLI reference

```
sentinel
├── serve      [--host 127.0.0.1] [--port 8000] [--reload]
├── scope
│   └── parse  [--url URL | --file PATH | --text TEXT] [--json]
├── agents     [--category NAME]            (queries running gateway)
└── status                                  (workspace, log level, key state)
```

Implemented in `sentinel/cli.py` — all commands respect `SENTINEL_LOG_LEVEL`.

---

## HTTP API

Implemented in `sentinel/api/`. Full schema at `/openapi.json`.

### Meta

| Method | Path        | Purpose                                          |
| ------ | ----------- | ------------------------------------------------ |
| GET    | `/`         | Service banner + legal disclaimer                |
| GET    | `/health`   | `{"status": "ok"}`                              |
| GET    | `/status`   | Version, workspace, whether Cerebras key is set  |

### Agents

| Method | Path                | Purpose                          |
| ------ | ------------------- | -------------------------------- |
| GET    | `/agents`           | List all agents (`?category=`)   |
| GET    | `/agents/{agent_id}`| Fetch one agent (e.g. `F_001`)   |

### Scope

| Method | Path           | Body shape                                        |
| ------ | -------------- | ------------------------------------------------- |
| POST   | `/scope/parse` | `{"mode": "url"|"file"|"text", "value": "..."}` |

### Scans (stub — Sprint 2 wires the orchestrator behind these)

| Method | Path                  | Purpose                                  |
| ------ | --------------------- | ---------------------------------------- |
| POST   | `/scans`              | Enqueue a scan; returns `session_id`     |
| GET    | `/scans`              | List all scans newest-first              |
| GET    | `/scans/{session_id}` | Inspect a scan                           |
| DELETE | `/scans/{session_id}` | Cancel a scan                            |

### Built-in security middleware (`sentinel/api/app.py`)

- CORS pinned to `localhost:{3000,5173,8000}` and `127.0.0.1` equivalents
- Per-request `X-Request-ID` header + audit log (`method path status duration`)
- Catch-all 500 handler — never leaks stack traces to clients
- 600 MB request body cap (APK-upload guard)

---

## Bug-bounty scope handling

The scope agent (`S_001`, in `sentinel/scope/scope_parser.py`) accepts three
input modes (URL / file / pasted text), detects the platform from the URL
host, and emits a strict `BountyScope` pydantic object.

Supported platforms (auto-detection): **HackerOne, Bugcrowd, YesWeHack,
Intigriti, Immunefi**. Anything else parses as `platform="unknown"`.

What it extracts:

- In-scope vs out-of-scope **Android/iOS package names**
  (`com.example.app` reverse-DNS form)
- In-scope vs out-of-scope **domains** (with `*.example.com` wildcards)
- **Forbidden techniques** (DoS, social-engineering, brute-force, automated
  scanning, spam, physical attacks)
- **Reward ranges** per severity tier
- **Program name** from `<title>` or URL slug

Safety:

- URLs are scheme-restricted (only `http`/`https`)
- Localhost, RFC-1918, link-local addresses are **rejected** to prevent SSRF
- Maximum input size is 500 KB — pages larger than this are truncated
- Custom `User-Agent: SENTINEL-security-scanner/0.1` (transparent identity)

The orchestrator hands this `BountyScope` into every `ScanContext`. Each
finding's evidence dict is checked against `scope.package_in_scope(...)`
inside `BaseAgent.run` — out-of-scope findings are silently dropped before
they touch storage.

A reusable JSON example lives at `docs/example_scope.json`.

---

## Memory architecture (3 tiers)

`sentinel/memory/interface.py` defines a single `MemoryInterface` ABC. Two
implementations satisfy it:

| Tier | Concept              | Lightweight (`LightweightMemory`)        | Production (`ProductionMemory`, **stub**) |
| ---- | -------------------- | ---------------------------------------- | ----------------------------------------- |
| 1    | Events + findings    | SQLite (`aiosqlite`, WAL mode)           | Redis                                     |
| 2    | Semantic similarity  | ChromaDB (persistent, cosine HNSW)       | Qdrant                                    |
| 3    | Knowledge graph      | NetworkX `DiGraph`, JSON-persisted       | Neo4j                                     |

Choose at runtime via the factory:

```python
from sentinel.memory import create_memory
mem = create_memory("lightweight", data_dir="./data")     # SQLite + Chroma + NX
mem = create_memory("production")                          # raises until Sprint 11
await mem.connect()
```

What each tier is for:

- **Tier 1** — fast bus and ground-truth storage. Every event
  (`scan.started`, `phase.completed`, `finding.emitted` …) goes here, and the
  agents subscribe by polling.
- **Tier 2** — embedding store. Used to find similar past findings across
  scans and to power retrieval-augmented prompting in the report generator
  (R_001).
- **Tier 3** — directed graph of nodes (findings, code locations, network
  endpoints) and edges (`leads_to`, `enables`, …). Used by the correlation
  phase to detect **chains** (e.g. `cleartext + missing pinning + auth in URL
  → critical token theft`) via `find_paths`.

ProductionMemory is intentionally a stub right now — its surface matches
LightweightMemory exactly, so agents written today will continue to work
unmodified once the Redis/Qdrant/Neo4j wiring lands in Sprint 11. The
`docker-compose.yml` at the repo root already brings up the three services.

---

## LLM router & failover

`sentinel/llm/router.py` exposes a single `FreeProviderRouter.query(...)` API
that hides which backend actually answered.

- **Primary**: Cerebras Cloud, `llama-3.3-70b`, ~2 000 tok/s on the free tier
- **Fallback**: local Ollama, `qwen2.5-coder:7b-instruct-q4_K_M`
- **Retries**: 3 attempts on 429 / 5xx with `[1, 3, 8]`-second back-off
- **Circuit breaker**: after 5 consecutive Cerebras failures, requests skip
  straight to Ollama until process restart
- **JSON mode**: `query_json(...)` enables structured output and tolerates
  ` ```json ` markdown fences in responses
- **`force_local=True`**: bypass Cerebras entirely (offline / private-data
  scans)

Agents never construct provider clients themselves — they always go through
the router, so adding a third or fourth provider later is a single-file
change.

---

## Data model — Finding & BountyScope

Defined in `sentinel/core/finding.py`. Both are `extra="forbid"` pydantic
models, so any field not listed in the schema is rejected — this is the
defence-in-depth layer that keeps malicious APK strings (think: a base-64
payload in a string resource) out of reports.

```python
class Severity(str, Enum):
    CRITICAL = "Critical"; HIGH = "High"; MEDIUM = "Medium"; LOW = "Low"; INFO = "Info"

class TriageState(str, Enum):
    UNREVIEWED = "Unreviewed"
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    NEEDS_VERIFICATION = "Needs Verification"

class Finding(BaseModel):
    agent_id: str            # ^[A-Z]+_\d{3}$        — validator-checked
    vuln_class: str          # 1..200 chars
    severity: Severity
    confidence: float        # 0.0 .. 1.0
    evidence: dict[str, Any] # ≤ 50 fields
    cvss_vector: str | None
    owasp:       str | None
    masvs:       str | None
    poc:         str | None
    recommendation: str
    session_id: str          # ^[a-zA-Z0-9_-]{8,64}$ — validator-checked
    triage: TriageState = UNREVIEWED
    created_at: datetime
    finding_id: str          # SHA-256[:16] over (agent_id, vuln_class, evidence)
```

`finding_id` is a **content hash**, so re-runs of the same agent on the same
target produce the same ID — the SQLite store's primary key is
`(session_id, finding_id)`, and saves are idempotent on it.

```python
class BountyScope(BaseModel):
    program_name: str
    platform: str
    in_scope_packages / in_scope_domains: list[str]
    out_of_scope_packages / out_of_scope_domains: list[str]
    excluded_vuln_classes: set[str]
    forbidden_techniques: set[str]
    reward_ranges: dict[str, tuple[int, int]]   # severity → (min, max) USD

    is_unrestricted()        -> bool
    package_in_scope(pkg)    -> bool
    technique_allowed(tech)  -> bool
```

---

## Writing a new agent

Subclass `BaseAgent` and implement two coroutines. The base class handles
event emission, scope filtering, error isolation, and timeout policy.

```python
# sentinel/agents/crypto/c001_insecure_shared_prefs.py
from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

class InsecureSharedPrefs(BaseAgent):
    AGENT_ID   = "C_001"
    VULN_CLASS = "Insecure SharedPreferences"
    PHASE      = "Phase 2"

    async def is_applicable(self) -> bool:
        # Skip on iOS, only run on Android targets
        return self.context.manifest.get("package") is not None

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        sources = self.context.decompiled_dir
        if sources is None:
            return findings

        for java_file in sources.rglob("*.java"):
            text = java_file.read_text(errors="replace")
            if "MODE_WORLD_READABLE" in text:
                findings.append(self._make_finding(
                    vuln_class=self.VULN_CLASS,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    evidence={"file": str(java_file.relative_to(sources)),
                              "package": self.context.manifest["package"]},
                    recommendation=(
                        "Replace MODE_WORLD_READABLE with MODE_PRIVATE and "
                        "store sensitive values in EncryptedSharedPreferences."
                    ),
                ))
        return findings
```

Conventions enforced by `BaseAgent.__init__`:

- `AGENT_ID` must match `^[A-Z]+_\d{3}$` (e.g. `C_001`, `VER_001`)
- `VULN_CLASS` must be non-empty
- Throw inside `analyze()` and the orchestrator turns it into an
  `agent.failed` event — the rest of the scan keeps running.

The orchestrator picks up new agents by being told about them at construction
time (`Orchestrator(... agents=[YourAgent, ...])`) — the long-term plan is to
auto-discover via the registry in `agents.py`.

---

## Testing

```bash
poetry run pytest tests/unit -v               # offline, fast (≈ seconds)
poetry run pytest tests/integration -v        # needs jadx + apktool + APK
poetry run ruff check sentinel tests          # lint (matches CI)
```

What's covered today:

- `tests/unit/test_sprint1_core.py` — Finding/Scope/ScanContext validators,
  Settings secret hygiene, LLM router happy-path + failover + JSON-mode
- `tests/unit/test_scope_parser.py` — HackerOne / Bugcrowd / YesWeHack
  fixtures, SSRF blocks, JSON file path, BountyScope gating
- `tests/unit/test_api.py` — every FastAPI endpoint, including 404s and 422s
- `tests/unit/test_sprint2a.py` — memory bus (events / findings / graph /
  health), BaseAgent lifecycle (skip/error-isolation/scope-filter), TEST_001
- `tests/unit/test_sprint2b.py` — JADX/apktool/manifest wrappers (mocked
  subprocess), Orchestrator phase emission + timing + failure handling
- `tests/integration/test_phase1_real_apk.py` — full Phase 0+1+2 against
  `corpus/InsecureBankv2.apk` (skips if any tool is missing)

CI: `.github/workflows/ci.yml` runs ruff + unit tests on Ubuntu against
Python 3.12 on every push and PR.

---

## Development workflow

- **Lint:** ruff is configured with `select = E,F,W,I,B`, `line-length=120`,
  with relaxations for tests, route handlers, and the CLI (see `pyproject.toml`).
- **Type check:** mypy is enabled in `--strict` mode but not yet wired into CI.
- **Pre-commit:** `pre-commit` is in the dev group — install hooks with
  `poetry run pre-commit install` once you've added a `.pre-commit-config.yaml`.
- **Pytest defaults:** `asyncio_mode = "auto"` (no need to decorate every
  async test) and `testpaths = ["tests"]`.

---

## Roadmap

| Sprint | Theme                                               |
| ------ | --------------------------------------------------- |
| 1      | Core data model, settings, LLM router               |
| 1.2    | FastAPI gateway + CLI skeleton                      |
| 2a     | Memory bus + BaseAgent + TEST_001                   |
| 2b     | Tool wrappers (JADX / apktool / androguard) + Orchestrator Phases 0+1 |
| 3+     | Real detection agents — Auth, Crypto, Network first |
| 5      | VER_001, HON_001 — verification & honeypots         |
| 7      | Correlation phase + chain detection                 |
| 8      | R_001 reporting agent                               |
| 9      | M_001 meta-exploration agent                        |
| 11     | ProductionMemory wiring (Redis + Qdrant + Neo4j)    |
| —      | Frontend, iOS support                               |

---

## Security & privacy

- **Where your APK goes:** files stay local. Only short text snippets
  (the bits an agent needs the LLM to reason about) cross the network — and
  only to Cerebras if you supply a key. With `force_local=True`, *nothing*
  ever leaves the host.
- **Where secrets go:** `SecretStr` blocks them from logs, `repr`,
  exception printers. The audit-log middleware never logs request bodies.
- **Where reports go:** SQLite + ChromaDB inside `./data/`. Already
  `.gitignore`-d. Delete `./data/` to wipe state.
- **Path safety:** every external path goes through `Path.resolve()` to
  defang `../` traversal in attacker-controlled scope files.
- **Subprocess safety:** JADX and apktool are invoked with explicit argv
  arrays (no shell), bounded JVM heap, timeouts, and resource-limit checks
  (`MAX_OUTPUT_SIZE_MB = 500`).
- **Network safety:** the scope parser blocks localhost / RFC-1918 / `file://`
  before fetching.
- **Workspace cleanup:** `Orchestrator.cleanup()` only `rmtree`s when the
  workspace lives under `$HOME` — defence against a misconfigured workspace
  pointing at `/`.

---

## License & disclaimer

License: TBD (the authors will pick one in a forthcoming sprint; treat the
code as **All Rights Reserved** until then).

> **You are responsible for what you scan.** Mobile-app reverse engineering
> may be restricted or illegal depending on jurisdiction, EULA, and program
> rules. Use SENTINEL only on:
>
> 1. apps you own,
> 2. apps whose developer has given you written permission, or
> 3. apps explicitly listed as in-scope by an active bug-bounty program.
>
> Always read the program's rules of engagement, honour `forbidden_techniques`,
> and stay within `in_scope_packages`. The authors of SENTINEL accept no
> liability for any use of this software.


### Contact
- stw00070@softwarica.edu.np
-  Teams: stw0070
Albert Maharjan