# SENTINEL — Technical Architecture Reference

**Version:** Production (Active Development)

---

## Executive Summary

SENTINEL is an autonomous, multi-agent Android security testing platform for AppSec teams and bug bounty hunters. It orchestrates specialized detection agents through a 10-phase pipeline combining static analysis (SAST), dynamic analysis (DAST), runtime instrumentation (Frida), and LLM-powered triage to produce actionable, scope-filtered vulnerability findings.

**Core Design Philosophy:** Local-first, autonomous, production-grade security testing with zero cloud dependencies when run in `--private` mode.

> Community tier requires a local GPU/Ollama. Pro/Enterprise tiers include managed inference.

---

## 1. PROJECT STRUCTURE & CODE ORGANIZATION

### 1.1 Directory Tree

```
sentinel/
├── sentinel/                       # Main Python package
│   ├── core/                       # Core orchestration & data models
│   │   ├── orchestrator.py         # 10-phase pipeline driver
│   │   ├── finding.py              # Finding & BountyScope models
│   │   ├── scan_context.py         # Per-scan shared state
│   │   ├── config.py               # Settings loader (pydantic-settings)
│   │   ├── diff.py                 # APK diff for CI regression gates
│   │   ├── dedup.py                # Finding deduplication
│   │   ├── crypto.py               # AES-256-GCM at-rest encryption
│   │   ├── janitor.py              # Workspace cleanup background task
│   │   └── baseline_store.py       # Fingerprint storage for diff
│   │
│   ├── agents/                     # Detection agents
│   │   ├── base/base_agent.py      # Abstract agent contract
│   │   ├── special/test_agent.py   # Pipeline smoke test (TEST_001)
│   │   ├── auth/                   # Auth agents (A_*)
│   │   ├── crypto/                 # Crypto/storage agents (C_*)
│   │   ├── network/                # Network agents (N_*)
│   │   ├── platform/               # IPC/deep-link agents (P_*)
│   │   ├── dynamic/                # DAST agents (D_*)
│   │   ├── business/               # Business logic (B_*)
│   │   ├── taint/                  # Data-flow taint tracer (TAINT_001)
│   │   ├── semgrep/                # AST SAST (SG_001)
│   │   ├── supply_chain/           # SCA CVE scanner (SCA_001)
│   │   ├── crossplatform/          # React Native + Flutter
│   │   ├── reporting/              # Report generator (R_001)
│   │   ├── correlation/            # Exploit chain detector (COR_001)
│   │   └── meta/                   # Obfuscation detector, profiler
│   │
│   ├── llm/                        # LLM routing & remediation
│   │   ├── router.py               # Multi-provider with circuit breaker
│   │   └── remediation.py          # Patch generation (experimental)
│   │
│   ├── memory/                     # 3-tier memory bus
│   │   ├── interface.py            # MemoryInterface ABC
│   │   ├── lightweight.py          # SQLite + Chroma + NetworkX
│   │   ├── postgres.py             # T1: PostgreSQL (production)
│   │   ├── qdrant_backend.py       # T2: Qdrant vector store
│   │   ├── neo4j_backend.py        # T3: Neo4j graph store
│   │   └── composite.py            # Composite memory bus
│   │
│   ├── auth/                       # Authentication & authorization
│   │   ├── jwt_auth.py             # JWT token handling
│   │   ├── models.py               # User/org models
│   │   ├── rbac.py                 # Role-based access control
│   │   └── revocation.py           # Token revocation store
│   │
│   ├── tools/                      # External tool wrappers
│   │   ├── jadx.py                 # JADX decompiler
│   │   ├── apktool.py              # apktool resources
│   │   ├── androguard_analyzer.py  # Bytecode analysis
│   │   ├── manifest.py             # Manifest parser
│   │   ├── frida_runner.py         # Frida instrumentation
│   │   ├── mitmproxy_runner.py     # Traffic interception
│   │   └── adb_runner.py           # ADB device control
│   │
│   ├── triage/                     # LLM-powered triage
│   │   ├── triager.py              # False positive filter
│   │   ├── prompts.py              # Triage prompt templates
│   │   └── code_loader.py          # Evidence enrichment
│   │
│   ├── rag/                        # Retrieval-augmented generation
│   │   ├── knowledge_base.py       # ChromaDB wrapper
│   │   ├── ingester.py             # Corpus ingestion (CWE, MASVS, OSV)
│   │   ├── retriever.py            # Semantic search
│   │   └── enricher.py             # Finding enrichment
│   │
│   ├── verify/                     # Runtime verification
│   │   ├── engine.py               # Verification orchestrator
│   │   ├── verifiers/              # Per-finding verifiers
│   │   └── replayers.py            # Active HTTP replay clients
│   │
│   ├── exploit/                    # PoC generation
│   │   ├── generator.py            # Exploit artifact builder
│   │   ├── drivers.py              # Vuln-specific drivers
│   │   └── safety.py               # Authorization checks + dry-run
│   │
│   ├── scope/                      # Bounty scope parser
│   │   └── scope_parser.py         # S_001 agent
│   │
│   ├── api/                        # FastAPI REST gateway
│   │   ├── app.py                  # Application factory
│   │   ├── routes/                 # Endpoints
│   │   │   ├── scans.py            # /scans CRUD
│   │   │   ├── agents.py           # /agents registry
│   │   │   ├── scope.py            # /scope parser
│   │   │   ├── reports.py          # /reports download
│   │   │   └── auth.py             # JWT + API key auth
│   │   ├── scan_runner.py          # Async scan executor
│   │   └── middleware/             # Rate limiting, RBAC
│   │
│   └── cli.py                      # Click CLI entry point
│
├── frida_agent/                    # TypeScript Frida hooks
│   └── src/
│       ├── agent.ts                # Hook orchestrator
│       └── hooks/                  # 30+ hook modules
│
├── frontend/                       # Web UI
│   └── js/
│       ├── pages/                  # SPA views
│       └── components/             # Reusable UI components
│
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   └── integration/                # Real APK tests
│
├── migrations/                     # Database migrations (Alembic)
├── scripts/                        # Utility scripts
├── docs/                           # Documentation
├── rules/                          # Semgrep YAML rules
├── pyproject.toml                  # Poetry config
└── docker-compose.yml              # Production infrastructure
```

---

## 2. ARCHITECTURE DECISIONS

### 2.1 Agent Framework

**CUSTOM IMPLEMENTATION** — Not using LangChain/AutoGen/CrewAI.

**Why custom?**
1. **Deterministic execution** — LangChain's async chains introduce non-determinism
2. **Memory control** — Fine-grained control over 3-tier memory (events/embeddings/graph)
3. **Scope enforcement** — Built-in scope filtering at the BaseAgent level
4. **Performance** — Parallel agent execution via asyncio.gather, not serialized chains
5. **Error isolation** — One agent failure doesn't cascade

**BaseAgent Contract:**
```python
class BaseAgent(ABC):
    AGENT_ID: str        # e.g., "N_002", "C_007"
    VULN_CLASS: str      # e.g., "Cleartext Traffic"
    PHASE: str           # "Phase 2" (static), "Phase 4" (dynamic)

    @abstractmethod
    async def is_applicable(self) -> bool:
        """Skip if wrong platform, missing prereqs"""

    @abstractmethod
    async def analyze(self) -> list[Finding]:
        """Run detection, return 0+ findings"""

    async def run(self) -> list[Finding]:
        """Orchestrator calls this — handles scope filter,
        error isolation, event emission, storage"""
```

### 2.2 LLM Setup

**LOCAL-FIRST, cloud optional**

**Provider Priority:**
1. **Local vLLM/TensorRT-LLM** (`SENTINEL_LOCAL_LLM_URL`) — primary
2. **Groq** — Llama 3.3 70B Versatile (if key set)
3. **Cerebras** — Llama 3.3 70B (if key set)
4. **Ollama** — qwen2.5-coder:7b (always-on local fallback)

**Router Features:**
- **Circuit breaker:** After 3 consecutive failures, provider skipped for 2 minutes
- **Auto-retry:** 3 attempts with exponential backoff on 429/5xx
- **JSON mode:** Structured output with markdown fence stripping
- **`--private` flag:** Forces local-only

### 2.3 3-Tier Memory Bus

| Tier | Backend | Purpose |
|------|---------|---------|
| T1 | PostgreSQL (asyncpg) | Events, findings, audit log |
| T2 | Qdrant | Semantic vector search |
| T3 | Neo4j | Exploit chain graph |
| Dev | SQLite + ChromaDB + NetworkX | Local development fallback |

**Tenant isolation:** PostgreSQL uses Row-Level Security (RLS) per `org_id`. All queries scoped automatically.

### 2.4 Security Architecture

- **RBAC:** Role-based access (admin, analyst, viewer, auditor)
- **JWT revocation:** Redis-backed revocation store with in-memory fallback
- **At-rest encryption:** APK uploads encrypted with AES-256-GCM, key derived per-tenant
- **Workspace janitor:** Background task purges expired workspaces
- **Audit log:** Append-only PostgreSQL table (no DELETE/UPDATE rules)

---

## 3. CURRENT CAPABILITIES

### 3.1 What's Working

✅ **Phase 0 — Ingestion:** SHA-256 hashing, size validation, per-tenant encrypted workspace

✅ **Phase 1 — Recon (Parallel):** JADX + apktool + Androguard run concurrently

✅ **Phase 2 — Static Analysis:** SAST agents, Semgrep (18 YAML rules), taint analysis, SCA CVE scanner, React Native, Flutter

✅ **Phase 3 — LLM Triage:** False positive filtering, severity adjustment, RAG-enhanced prompts (CWE/MASVS/OWASP citations)

✅ **Phase 4 — Dynamic Analysis (DAST):** mitmproxy traffic capture, ADB runner, DAST agents

✅ **Phase 4.5 — Frida Runtime:** 30+ hook modules (crypto, pinning bypass, biometric, IPC, file)

✅ **Phase 7 — Exploit Chain Detection (COR_001):** NetworkX graph, pattern matching, confidence scoring

✅ **Phase 8 — Reporting (R_001):** Markdown, HTML, SARIF 2.1.0, SIEM rules, PoC bundles

✅ **Verification Engine:** 15+ verifiers (manifest, Frida, MITM, active replay)

✅ **Exploit Generation:** Driver system with PoC artifacts, authorization checks, dry-run default

✅ **Authentication:** JWT + API keys, RBAC middleware, token revocation

✅ **CI Integration (Diff Mode):** Baseline fingerprinting, delta computation, `--fail-on critical,high`

### 3.2 Partially Implemented

🚧 **Frontend Web UI** — Static prototype, SSE wiring in progress

🚧 **Async Report Queue** — RQ worker integration planned

🚧 **iOS Support** — Architecture ready, tooling gaps remain

### 3.3 Not Yet Implemented

❌ **Real-time scan SSE stream** — Clients currently poll `GET /scans/{id}`

❌ **Benchmark suite** — No MSTG/DIVA/InsecureBankv2 precision/recall measurements

---

## 4. CONFIGURATION & SETUP

### 4.1 System Requirements

**Platform:** Linux (tested on CachyOS/Arch, Ubuntu/Debian compatible)

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12 | Runtime |
| Poetry | ≥1.7 | Dependency management |
| Java | 17+ | JADX, apktool |
| JADX | latest | APK → Java decompilation |
| apktool | latest | APK → manifest + resources |
| Ollama | latest | Local LLM |
| Node.js | 18+ | Frida agent build |
| Frida | 16.5.7 | Runtime instrumentation |
| mitmproxy | 12.2.3 | Traffic interception |
| ADB | latest | Device communication |
| Semgrep | 1.163+ | AST-based SAST |
| PostgreSQL | 16 | Production memory T1 |
| Redis | 7 | Token revocation + rate limiting |
| Qdrant | latest | Vector store T2 |
| Neo4j | 5 | Graph store T3 |

### 4.2 Quick Start

```bash
git clone <repo> sentinel && cd sentinel
poetry install
docker-compose up -d          # Start Postgres, Redis, Qdrant, Neo4j
cp .env.example .env && $EDITOR .env
./scripts/verify_setup.sh
cd frida_agent && npm install && npm run build
poetry run sentinel rag build
poetry run sentinel serve
```

### 4.3 Environment Variables

```bash
# LLM Providers
SENTINEL_LOCAL_LLM_URL=http://localhost:8080   # vLLM/TensorRT-LLM (preferred)
GROQ_API_KEY=gsk_...                           # Optional cloud
CEREBRAS_API_KEY=csk_...                       # Optional cloud
OLLAMA_HOST=http://localhost:11434             # Always-on fallback

# Database
DATABASE_URL=postgresql://sentinel:pass@localhost:5432/sentinel
REDIS_URL=redis://localhost:6379
QDRANT_URL=http://localhost:6333
NEO4J_URL=bolt://localhost:7687

# Runtime
SENTINEL_LOG_LEVEL=INFO
SENTINEL_WORKSPACE=./workspace
SENTINEL_MAX_APK_SIZE_MB=500
SENTINEL_SCAN_TIMEOUT_SECONDS=1800
SENTINEL_ENCRYPT_WORKSPACES=true
```

---

## 5. SECURITY & PRIVACY

### 5.1 Where Your APK Goes

**Local-only by default:**
- APK stays in `./workspace/<session_id>/` (encrypted at rest)
- Only short text snippets sent to LLM (not entire APK)

**Cloud LLM usage:**
- Triage prompts: ~500 tokens per finding (evidence summary only)
- **No source code** sent — only metadata (file paths, line numbers, pattern matches)

**Private mode:**
```bash
sentinel scan app.apk --private  # Forces local-only
```

### 5.2 Exploitation Safety

All exploit drivers default to **dry-run mode**. Live exploitation requires:
1. `--exploit-mode live` CLI flag
2. Explicit authorization justification
3. Scope check passes
4. Rate limiter allows (10 req/min per target host)

Audit log records every exploit authorization decision.

---

## 6. CONTRIBUTING

**How to add an agent:**
1. Create `sentinel/agents/<category>/<id>_<name>.py`
2. Implement `BaseAgent` (override `is_applicable` + `analyze`)
3. Register in category `__init__.py`
4. Add to orchestrator phase list
5. Write unit test with 100% coverage

**Code quality gates:**
```bash
poetry run ruff check sentinel tests
poetry run ruff format sentinel tests
poetry run pytest tests/unit -v
poetry run mypy sentinel --strict
```

**License:** TBD (All Rights Reserved until formal license chosen)
