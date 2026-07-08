# SENTINEL

**Autonomous Android security scanner for AppSec teams and bug bounty hunters.**

SENTINEL ingests an Android APK, runs it through a multi-phase pipeline of
decompilation, static analysis, dynamic instrumentation, and LLM-driven triage,
and emits structured, scope-filtered, severity-rated findings ready for a
bug-bounty report or internal security review.

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
- [Roadmap](#roadmap)
- [Security & privacy](#security--privacy)
- [License & disclaimer](#license--disclaimer)

---

## Status

| Layer | State |
|---|---|
| Core data model (Finding/Scope) | ✅ Implemented + tested |
| Configuration / `Settings` | ✅ |
| FastAPI gateway (`/scans`, `/agents`, `/scope`, `/health`, `/status`) | ✅ |
| CLI (`sentinel serve / scope / agents / status`) | ✅ |
| Scope parser S_001 (5 platforms) | ✅ |
| LLM router (Cerebras → Groq → Ollama) | ✅ |
| BaseAgent contract | ✅ |
| Memory — T1 PostgreSQL (asyncpg + RLS) | ✅ Phase 1.1 |
| Memory — T2 Qdrant (semantic search) | ✅ Phase 1.2 |
| Memory — T3 Neo4j (graph store) | ✅ Phase 1.2 |
| Memory — Lightweight (SQLite + Chroma + NetworkX) | ✅ dev fallback |
| RBAC + Multi-tenancy + JWT revocation | ✅ Phase 1.3 |
| APK encryption at rest (AES-256-GCM) | ✅ Phase 1.4 |
| Janitor (workspace pruning) | ✅ Phase 1.4 |
| Phase 0 (ingest) + Phase 1 (recon) | ✅ JADX + apktool + androguard |
| Phase 2 — static agents | ✅ SG_001, SCA_001, TAINT_001, + auth/crypto/network/platform/API agents |
| Phase 3 — dynamic agents | 🚧 Frida hooks in progress |
| Phase 4 — behavioural | 🚧 mitmproxy capture |
| Frontend (web GUI) | 🚧 in progress |
| iOS support | 🗺 roadmap |

---

## Highlights

- **Multi-agent pipeline** across 14 categories (Auth, Crypto/Storage, Network,
  Firebase, Business Logic, Privacy, Platform, Native, Cloud, AI, Wireless,
  Deserialization, Supply Chain, Special/Meta).
- **10-phase pipeline** — ingestion → recon → static → dynamic → behavioural
  → verification → triage → correlation → reporting → meta-exploration.
- **Pluggable memory** — same `MemoryInterface` abstraction for local dev
  (SQLite/Chroma/NetworkX) and production deployments (PostgreSQL/Qdrant/Neo4j).
- **Local-first LLM stack** — run entirely offline with local Ollama; use
  Cerebras or Groq cloud APIs when available. No APK content ever leaves the
  host with `--private`.
- **Production security** — per-tenant RBAC (admin/analyst/viewer), JWT
  revocation, APK encryption at rest (HKDF-derived per-tenant AES-256-GCM),
  path-traversal-hardened workspace isolation.
- **Strict scope enforcement** — every finding is gated against a parsed
  `BountyScope` before reaching storage. Out-of-scope packages are dropped
  silently inside `BaseAgent.run`.
- **SSRF-safe scope ingestion** — URLs pre-validated (no localhost, RFC-1918,
  `file://`) before fetch.

---

## Architecture overview

```
┌──────────────┐      ┌────────────────────────────────────────────────┐
│  CLI (click) │──┐   │                FastAPI gateway                 │
│  Web GUI     │──┴──▶│  /scans  /agents  /scope  /health  /status     │
└──────────────┘      └────────────────────────┬───────────────────────┘
                                               │  RBAC + JWT middleware
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
  │ decomp   │    │  resources  │ │and.│ │  (registry)  │ │ Bus 3-T │ │ Router   │
  └──────────┘    └─────────────┘ └────┘ └──────────────┘ └─────────┘ └──────────┘
                                                                ▲
                            ┌──────────────────┬────────────────┘
                            │                  │
                       ┌────┴─────┐      ┌─────┴────────┐
                       │ T1: PG   │      │ T2: Qdrant   │
                       │ events + │      │ T3: Neo4j    │
                       │ findings │      │ (semantic +  │
                       │  (RLS)   │      │  graph)      │
                       └──────────┘      └──────────────┘
```

A scan is one `session_id`. Every emitted event, finding, embedding, and graph
node is keyed by it, enabling parallel scans without crosstalk.

---

## The 10-phase pipeline

| # | Phase | Implemented | What happens |
|---|---|---|---|
| 0 | **Ingestion** | ✅ | SHA-256 hash, size check, per-tenant workspace creation, AES-256-GCM encryption |
| 1 | **Recon** | ✅ | JADX decompile + apktool decode + androguard manifest extraction |
| 2 | **Static analysis** | ✅ (core agents) | Per-agent code/manifest pattern + LLM-driven detection |
| 3 | **Dynamic analysis** | 🚧 | Frida hooks, runtime taint, instrumented APK execution |
| 4 | **Behavioural** | 🚧 | mitmproxy traffic capture, GraphQL/REST fuzzing |
| 5 | **Verification** | 🚧 | VER_001 re-runs tooling; HON_001 honeypot calibration |
| 6 | **Triage** | 🚧 | Severity recalibration, deduplication |
| 7 | **Correlation** | 🚧 | Chain detection: low + low → critical exploit chains |
| 8 | **Reporting** | 🚧 | R_001: HackerOne/Bugcrowd-formatted markdown submissions |
| 9 | **Meta-exploration** | 🚧 | M_001: time-bounded autonomous research for novel issues |

---

## Agent catalogue

The agent registry is exposed at `GET /agents` — source of truth is
`sentinel/api/routes/agents.py`. A condensed view:

| Cat. prefix | Category | Examples |
|---|---|---|
| `A_*` | Authentication | Hardcoded credentials, JWT alg confusion, biometric bypass |
| `C_*` | Crypto / Storage | ECB cipher, static IV, hardcoded keys, Keystore misuse |
| `N_*` | Network | Cleartext HTTP, missing pinning, hostname verifier off |
| `F_*` | Firebase | Public RealtimeDB / Firestore / Storage |
| `B_*` | Business Logic | IDOR, mass assignment, TOCTOU, receipt forgery |
| `P_*` | Platform / IPC | Deep-link hijack, ContentProvider IDOR, Intent redirect |
| `API_*` | Backend API | BOLA replay, mass-assignment fuzzer, excessive data exposure |
| `SG_*` | Semgrep AST SAST | 18 YAML rules: WebView, crypto, TLS, storage, SQLi, command injection |
| `SCA_*` | Supply chain | Third-party library CVE scanner (OSV.dev Maven snapshot) |
| `TAINT_*` | Data-flow taint | Backward-slice tracer, 3-hop IPA, source→sink traces |
| `RN_*` | React Native | JS bundle auditor, AsyncStorage/cleartext/secrets/WebView |
| `FL_*` | Flutter (exp.) | `libapp.so` string-level audit |
| `VER_*` | Verification | Re-run tooling, kill hallucinations |
| `HON_*` | Honeypot | Inject fake bugs to calibrate confidence |
| `TEST_*` | Smoke test | Always emits a synthetic Info finding |

---

## Repository layout

```
sentinel/
├── pyproject.toml          Poetry project, ruff/mypy/pytest config
├── docker-compose.yml      Postgres + Redis + Qdrant + Neo4j
├── .env.example            Template — copy to .env and fill in
├── migrations/             SQL migrations (0001–0004)
├── sentinel/               Python package
│   ├── cli.py              Click entry point
│   ├── core/
│   │   ├── config.py           Settings (pydantic-settings)
│   │   ├── finding.py          Finding, BountyScope, Severity
│   │   ├── scan_context.py     Per-scan shared state
│   │   ├── orchestrator.py     10-phase driver
│   │   ├── crypto.py           AES-256-GCM at-rest encryption
│   │   ├── workspace.py        Tenant-scoped path resolver
│   │   └── janitor.py          Background workspace pruner
│   ├── api/
│   │   ├── app.py              FastAPI factory + middleware
│   │   └── routes/
│   ├── auth/
│   │   ├── models.py           User, Role, Organization, APIKey
│   │   ├── jwt_auth.py         JWT create/verify + revocation
│   │   ├── rbac.py             RBACMiddleware
│   │   └── revocation.py       RevocationStore (in-memory / Redis)
│   ├── llm/router.py           LLM router (Cerebras → Groq → Ollama)
│   ├── memory/
│   │   ├── interface.py        MemoryInterface ABC
│   │   ├── lightweight.py      SQLite + ChromaDB + NetworkX (dev)
│   │   ├── postgres.py         PostgreSQL T1 (asyncpg + RLS)
│   │   ├── qdrant_backend.py   Qdrant T2 (semantic search)
│   │   └── neo4j_backend.py    Neo4j T3 (graph store)
│   └── agents/                 BaseAgent + category packages
├── tests/
│   ├── unit/               Fast offline tests
│   └── integration/        Real-APK end-to-end tests
└── frontend/               Web UI
```

---

## Requirements

| Tool | Version | Used for |
|---|---|---|
| **Python** | 3.12 | Runtime — `>=3.12,<3.13` enforced |
| **Poetry** | ≥ 1.7 | Dependency management |
| **Java** | 17+ | JADX, apktool |
| **JADX** | latest | APK → Java decompilation |
| **apktool** | latest | APK → manifest + decoded resources |
| **Docker** | latest | Postgres / Qdrant / Neo4j (optional, for production memory) |
| **Ollama** | latest | Local LLM (optional, for offline mode) |

---

## Installation

```bash
# 1. Clone
git clone <repo> sentinel && cd sentinel

# 2. Install Python deps
poetry install

# 3. Install system tools (Arch / CachyOS)
paru -S jadx apktool jdk-openjdk

# 4. (Optional) local LLM
ollama pull qwen2.5-coder:7b-instruct-q4_K_M

# 5. Configure
cp .env.example .env && $EDITOR .env

# 6. (Optional) start production memory stack
docker compose up -d
```

---

## Configuration (.env)

| Variable | Default | Purpose |
|---|---|---|
| `CEREBRAS_API_KEY` | *(empty)* | Cloud LLM — primary if set |
| `GROQ_API_KEY` | *(empty)* | Cloud LLM — secondary fallback |
| `OLLAMA_HOST` | `http://localhost:11434` | Local LLM endpoint |
| `SENTINEL_JWT_SECRET` | *(empty)* | **Required in production** — HS256 signing key |
| `SENTINEL_DEV_AUTH_BYPASS` | `true` | Set `false` in production |
| `SENTINEL_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `SENTINEL_WORKSPACE` | `./workspace` | Per-session decompile output root |
| `SENTINEL_MAX_APK_SIZE_MB` | `500` | Upload hard cap |
| `SENTINEL_SCAN_TIMEOUT_SECONDS` | `1800` | Per-scan timeout |
| `SENTINEL_MASTER_KEY` | *(empty)* | AES-256-GCM master key (base64, 32 bytes). Empty = encryption disabled |
| `SENTINEL_SCAN_RETENTION_DAYS` | `30` | Workspace auto-delete TTL |
| `SENTINEL_JANITOR_INTERVAL_SECONDS` | `3600` | Janitor poll interval |
| `DATABASE_URL` | *(empty)* | PostgreSQL DSN — falls back to SQLite if unset |
| `QDRANT_URL` | *(empty)* | Qdrant endpoint — falls back to ChromaDB if unset |
| `NEO4J_URL` | *(empty)* | Neo4j bolt URL — falls back to NetworkX if unset |
| `REDIS_URL` | *(empty)* | Redis URL (token revocation, optional) |

Generate a master key: `python -c "from sentinel.core.crypto import generate_master_key; print(generate_master_key())"`

---

## Quick start

```bash
# Run a scan via the CLI helper
poetry run python scripts/dev_scan.py corpus/InsecureBankv2.apk

# Start the API gateway
poetry run sentinel serve   # http://127.0.0.1:8000
# Swagger UI → http://127.0.0.1:8000/docs

# Parse a bug-bounty scope
poetry run sentinel scope parse --url https://hackerone.com/<program>

# List all agents
poetry run sentinel agents
poetry run sentinel agents --category Network
```

---

## CLI reference

```
sentinel
├── serve      [--host 127.0.0.1] [--port 8000] [--reload]
├── scope
│   └── parse  [--url URL | --file PATH | --text TEXT] [--json]
├── agents     [--category NAME]
└── status
```

---

## HTTP API

Full schema at `/openapi.json`. Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | `{"status": "ok"}` |
| GET | `/status` | Version, workspace, key state |
| POST | `/auth/register` | Create user |
| POST | `/auth/login` | Get JWT |
| POST | `/auth/logout` | Revoke JWT (JTI blacklist) |
| GET | `/agents` | List agents (`?category=`) |
| POST | `/scans` | Upload APK, start scan → `session_id` |
| GET | `/scans` | List scans (newest-first) |
| GET | `/scans/{id}` | Scan status + progress |
| GET | `/scans/{id}/findings` | Full findings list |
| DELETE | `/scans/{id}` | Cancel + cleanup |
| POST | `/scope/parse` | Parse bounty scope |

**RBAC:** `viewer` → GET only. `analyst` → GET + POST. `admin` → all methods.

---

## Bug-bounty scope handling

`S_001` (`sentinel/scope/scope_parser.py`) accepts URL / file / pasted text,
detects platform from URL host, and emits a strict `BountyScope` pydantic object.

Supported platforms (auto-detection): HackerOne, Bugcrowd, YesWeHack,
Intigriti, Immunefi. Anything else parses as `platform="unknown"`.

Extracts: in/out-scope Android package names, domains (with `*.` wildcards),
forbidden techniques, reward ranges, program name.

Safety: scheme-restricted (https only), localhost/RFC-1918/`file://` blocked,
500 KB input cap, transparent `User-Agent` header.

---

## Memory architecture (3 tiers)

`sentinel/memory/interface.py` defines a single `MemoryInterface` ABC.

| Tier | Concept | Dev backend | Production backend |
|---|---|---|---|
| 1 | Events + findings | SQLite (`aiosqlite`) | PostgreSQL (asyncpg + RLS) |
| 2 | Semantic similarity | ChromaDB | Qdrant |
| 3 | Knowledge graph | NetworkX DiGraph | Neo4j |

The factory in `sentinel/memory/__init__.py` auto-selects based on which URLs
are configured. With no `DATABASE_URL`/`QDRANT_URL`/`NEO4J_URL`, it falls back
to the lightweight stack and logs a warning.

---

## LLM router & failover

`sentinel/llm/router.py` exposes a single `FreeProviderRouter.query(...)` call.

Priority order: local Ollama (if `force_local=True` or no cloud key) →
Cerebras Cloud → Groq. Retries: 3 attempts with `[1, 3, 8]`s backoff.
Circuit breaker: after 5 consecutive failures, skips straight to next provider.

Use `--private` / `force_local=True` to guarantee no data leaves the host.

---

## Data model — Finding & BountyScope

```python
class Finding(BaseModel):
    agent_id:       str          # ^[A-Z]+_\d{3}$
    vuln_class:     str          # 1..200 chars
    severity:       Severity     # Critical/High/Medium/Low/Info
    confidence:     float        # 0.0 .. 1.0
    evidence:       dict[str, Any]
    recommendation: str
    session_id:     str          # ^[a-zA-Z0-9_-]{8,64}$
    finding_id:     str          # SHA-256[:16] — content-addressed, idempotent
    triage:         TriageState  # Unreviewed / True Positive / False Positive
    created_at:     datetime
```

---

## Writing a new agent

```python
from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

class InsecureSharedPrefs(BaseAgent):
    AGENT_ID   = "C_001"
    VULN_CLASS = "Insecure SharedPreferences"
    PHASE      = "Phase 2"

    async def is_applicable(self) -> bool:
        return self.context.manifest.get("package") is not None

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        for java_file in (self.context.decompiled_dir or Path()).rglob("*.java"):
            if "MODE_WORLD_READABLE" in java_file.read_text(errors="replace"):
                findings.append(self._make_finding(
                    vuln_class=self.VULN_CLASS,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    evidence={"file": str(java_file)},
                    recommendation="Use EncryptedSharedPreferences with MODE_PRIVATE.",
                ))
        return findings
```

`BaseAgent` handles scope filtering, event emission, error isolation, and
timeout policy. `AGENT_ID` must match `^[A-Z]+_\d{3}$`.

---

## Testing

```bash
poetry run pytest tests/unit -v          # offline, fast
poetry run pytest tests/integration -v   # needs jadx + apktool + APK
poetry run ruff check sentinel tests
poetry run mypy sentinel --strict
```

---

## Roadmap

| Phase | Theme | State |
|---|---|---|
| 1.1 | PostgreSQL T1 backend | ✅ Done |
| 1.2 | Qdrant T2 + Neo4j T3 backends | ✅ Done |
| 1.3 | RBAC + multi-tenancy + JWT revocation | ✅ Done |
| 1.4 | APK encryption at rest + janitor | ✅ Done |
| 1.5 | Containerised scan workers (RQ + Docker) | 🚧 Next |
| 1.6 | Immutable audit log (Postgres-backed) | 🗺 Planned |
| 2.x | LLM stack: local-primary, cache, circuit-breaker | 🗺 Planned |
| 3.x | 15 production-quality agents (replace stubs) | 🗺 Planned |
| 4.x | DAST + Frida runtime agents | 🗺 Planned |
| 5.x | Exploitation safety gate + rate limiting | 🗺 Planned |
| 6.x | Async report generation + SSE events | 🗺 Planned |
| — | iOS support | 🗺 Roadmap |

---

## Security & privacy

- **Where your APK goes:** files stay local by default. Only short code
  snippets sent to cloud LLM providers — and only if you supply a key.
  `--private` guarantees nothing leaves the host.
- **Encryption at rest:** APKs encrypted with AES-256-GCM using per-tenant
  HKDF-derived keys when `SENTINEL_MASTER_KEY` is set.
- **Secrets:** `SecretStr` blocks API keys from logs, `repr`, tracebacks.
- **Path safety:** `resolve_workspace()` validates tenant/session IDs against
  strict regexes and resolves paths to prevent `../` traversal.
- **Subprocess safety:** JADX and apktool invoked with explicit argv arrays
  (no shell), bounded JVM heap, timeouts, output-size caps.

---

## License & disclaimer

License: MIT (see `LICENSE`).

> **You are responsible for what you scan.** Mobile-app reverse engineering
> may be restricted depending on jurisdiction, EULA, and program rules.
> Use SENTINEL only on apps you own, apps whose developer has given written
> permission, or apps explicitly in-scope on an active bug-bounty program.
> The authors of SENTINEL accept no liability for any use of this software.
