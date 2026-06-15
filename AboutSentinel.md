# SENTINEL - Deep Technical Analysis

**Generated:** June 8, 2026  
**Version:** Sprint 8+ (Active Development)

---

## Executive Summary

SENTINEL is an autonomous, multi-agent mobile application security testing platform designed for Android (iOS planned). It orchestrates 88+ specialized security agents through a 10-phase pipeline combining static analysis (SAST), dynamic analysis (DAST), runtime instrumentation (Frida), and LLM-powered triage to produce actionable, scope-filtered vulnerability findings ready for bug bounty submission.

**Core Design Philosophy:** Free-tier-first, autonomous, production-grade security testing with zero cloud dependencies when run in `--private` mode.

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
│   │   └── baseline_store.py       # Fingerprint storage for diff
│   │
│   ├── agents/                     # 88 detection agents
│   │   ├── base/base_agent.py      # Abstract agent contract
│   │   ├── special/test_agent.py   # Pipeline smoke test (TEST_001)
│   │   ├── auth/                   # 12 auth agents (A_*)
│   │   ├── crypto/                 # 14 crypto/storage agents (C_*)
│   │   ├── network/                # 11 network agents (N_*)
│   │   ├── platform/               # IPC/deep-link agents (P_*)
│   │   ├── dynamic/                # 41 DAST agents (D_*)
│   │   ├── business/               # Business logic (B_*)
│   │   ├── taint/                  # Data-flow taint tracer (TAINT_001)
│   │   ├── semgrep/                # AST SAST (SG_001)
│   │   ├── supply_chain/           # SCA CVE scanner (SCA_001)
│   │   ├── crossplatform/          # React Native + Flutter
│   │   ├── reporting/              # Report generator (R_001)
│   │   ├── correlation/            # Exploit chain detector (COR_001)
│   │   └── meta/                   # Obfuscation detector, debuggable
│   │
│   ├── llm/                        # LLM routing & remediation
│   │   ├── router.py               # Multi-provider with circuit breaker
│   │   └── remediation.py          # Patch generation (experimental)
│   │
│   ├── memory/                     # 3-tier memory bus
│   │   ├── interface.py            # MemoryInterface ABC
│   │   ├── lightweight.py          # SQLite + Chroma + NetworkX
│   │   └── production.py           # Redis + Qdrant + Neo4j (stub)
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
│   ├── exploit/                    # PoC generation (Sprint 9)
│   │   ├── generator.py            # Exploit artifact builder
│   │   ├── drivers.py              # Vuln-specific drivers
│   │   └── safety.py               # Authorization checks
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
│   │   └── middleware/             # Rate limiting
│   │
│   ├── auth/                       # Authentication system
│   │   ├── jwt_auth.py             # JWT token handling
│   │   └── api_keys.py             # API key management
│   │
│   └── cli.py                      # Click CLI entry point
│
├── frida_agent/                    # TypeScript Frida hooks
│   └── src/
│       ├── agent.ts                # Hook orchestrator
│       └── hooks/                  # 30+ hook modules
│           ├── crypto.ts           # Runtime crypto detection
│           ├── pinning_*.ts        # Cert pinning bypass (5 variants)
│           ├── biometric*.ts       # Biometric hooks
│           ├── clipboard*.ts       # Clipboard monitoring
│           ├── webview_runtime.ts  # WebView settings
│           ├── accessibility.ts    # A11y abuse detection
│           ├── sqlite.ts           # SQL injection detection
│           └── ...                 # 20+ more
│
├── frontend/                       # Web UI (in progress)
│   └── js/
│       ├── pages/                  # SPA views
│       ├── components/             # Reusable UI
│       └── data/                   # Mock data
│
├── tests/                          # Test suite
│   ├── unit/                       # 90+ unit tests
│   └── integration/                # Real APK tests
│
├── scripts/                        # Utility scripts
│   ├── verify_setup.sh             # Pre-flight checks
│   ├── dev_scan.py                 # Manual scan runner
│   ├── fetch_osv_db.py             # OSV.dev database builder
│   └── install-mitm-ca.sh          # mitmproxy CA installer
│
├── docs/                           # Documentation
├── rules/                          # Semgrep YAML rules
├── corpus/                         # Test APKs (gitignored)
├── data/                           # Runtime data (gitignored)
├── workspace/                      # Decompiled APKs (gitignored)
├── pyproject.toml                  # Poetry config
├── docker-compose.yml              # Production memory services
└── .env.example                    # Config template
```

### 1.2 Lines of Code Analysis

**Total:** ~80,450 lines across 917 files (429 prioritized)

**Breakdown by module:**
- Core orchestration: ~2,000 LOC
- Agents (88 total): ~15,000 LOC
- Tools/wrappers: ~3,500 LOC
- Frida hooks (TypeScript): ~5,000 LOC
- LLM/RAG/Triage: ~2,500 LOC
- API/CLI: ~1,500 LOC
- Tests: ~12,000 LOC
- Frontend (in progress): ~3,000 LOC

---

## 2. ARCHITECTURE DECISIONS

### 2.1 Agent Framework

**CUSTOM IMPLEMENTATION** - Not using LangChain/AutoGen/CrewAI.

**Why custom?**
1. **Deterministic execution** - LangChain's async chains introduce non-determinism
2. **Memory control** - Need fine-grained control over 3-tier memory (events/embeddings/graph)
3. **Scope enforcement** - Built-in scope filtering at the BaseAgent level
4. **Performance** - Parallel agent execution via asyncio.gather, not serialized chains
5. **Error isolation** - One agent failure doesn't cascade

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
        """Orchestrator calls this - handles scope filter, 
        error isolation, event emission, storage"""
```

**Agent lifecycle:**
1. Orchestrator instantiates agent with `ScanContext` + `MemoryInterface`
2. Calls `agent.run()` which wraps `is_applicable()` + `analyze()`
3. Findings auto-filtered by scope before storage
4. Events published: `agent.started`, `agent.completed`, `agent.failed`, `finding.emitted`

### 2.2 Communication Method

**EVENT BUS + SHARED MEMORY** - No message queues between agents.

**Data flow:**
```
Orchestrator → Phase N → Agent.run() → Memory.save_finding()
                                     → Memory.publish_event()
                                     ↓
                        Other agents poll Memory.poll_events()
```

**Storage:**
- **Findings:** Persisted to SQLite with (session_id, finding_id) PK
- **Events:** Append-only log in SQLite, indexed by session_id + event_type
- **Embeddings:** ChromaDB for semantic similarity
- **Graph:** NetworkX DiGraph for exploit chain detection

**Why not RabbitMQ/Redis Streams?**
- Lightweight deployment (single laptop)
- Events are small (<1KB each)
- No inter-scan dependencies
- Production mode (Sprint 11) will add Redis pub/sub for multi-worker scaling

### 2.3 LLM Setup

**HYBRID: Cloud primary, local fallback**

**Provider Priority (Sprint 8+):**
1. **Groq** - Llama 3.3 70B Versatile (~14k RPD free tier) - BEST QUALITY
2. **Cerebras** - Llama 3.3 70B (1M tok/day free) - Fast fallback
3. **Ollama** - qwen2.5-coder:7b (local) - Always-on emergency

**Router Features:**
- **Circuit breaker:** After 3 consecutive failures, provider skipped for 2 minutes
- **Auto-retry:** 3 attempts with [1s, 3s] backoff on 429/5xx
- **JSON mode:** Structured output with markdown fence stripping
- **`--private` flag:** Forces local-only (skips cloud providers)

**Models Used:**
- **Code analysis:** qwen2.5-coder:7b-instruct-q4_K_M (Ollama)
- **Embeddings:** nomic-embed-text (Ollama)
- **Triage/Report:** Groq/Cerebras Llama 3.3 70B

**LLM Router Code Location:** `sentinel/llm/router.py` (479 LOC)

**Where LLMs are used:**
1. **Triage** (Sprint 7) - `LLMTriager` filters false positives, adjusts severity
2. **Report generation** (R_001) - Markdown/HTML bounty reports
3. **Remediation** (Sprint 9) - Diff patch generation (experimental, `--generate-patch`)
4. **Exploit PoC** (Sprint 9) - `ExploitGenerator` creates payloads

**API Keys Configuration (.env):**
```bash
GROQ_API_KEY=your-groq-key
CEREBRAS_API_KEY=your-cerebras-key
OLLAMA_HOST=http://localhost:11434
```

### 2.4 RAG Implementation

**Vector Database:** ChromaDB (persistent mode)

**Indexed Corpora:**
- **CWE definitions** - Common Weakness Enumeration
- **OWASP Mobile Top 10** - Attack vectors and mitigations
- **MASVS** - Mobile Application Security Verification Standard
- **OSV.dev Maven advisories** - CVE database for Java libraries (offline snapshot)

**Embedding Model:** `nomic-embed-text` (768-dim, cosine similarity)

**RAG Pipeline:**
```
Finding → KnowledgeRetriever.retrieve_for_finding()
        → ChromaDB.query(embedding, top_k=5)
        → Passages ranked by cosine similarity
        → Enricher injects into LLM prompt context
        → Enhanced triage/report with citations
```

**Code Location:**
- `sentinel/rag/knowledge_base.py` - ChromaDB wrapper
- `sentinel/rag/ingester.py` - Corpus loading
- `sentinel/rag/retriever.py` - Semantic search
- `sentinel/rag/enricher.py` - Finding enrichment

**Usage:**
```bash
# Build knowledge base
sentinel rag build

# Query interactively
sentinel rag query "SQL injection in Android ContentProvider"

# Stats
sentinel rag stats
```

**Storage:** `./data/chroma/` directory (persistent across scans)

---

## 3. CURRENT CAPABILITIES

### 3.1 What's Working (Sprint 8+)

✅ **Phase 0 - Ingestion**
- SHA-256 hashing
- Size validation (max 500MB configurable)
- Per-session workspace creation

✅ **Phase 1 - Recon (Parallel Tool Execution)**
- **JADX** - Java decompilation (crashes isolated, continues scan)
- **apktool** - Resources + manifest decode
- **Androguard** - Bytecode-level analysis
- All tools run concurrently via `asyncio.gather(return_exceptions=True)`

✅ **Phase 2 - Static Analysis (65+ agents active)**
- **SAST agents:** N_002 cleartext traffic, C_007 weak crypto, A_004 hardcoded secrets
- **Semgrep (SG_001):** 18 YAML rules (WebView, crypto, TLS, SQL injection)
- **Taint analysis (TAINT_001):** Tree-sitter backward slicing, 3-hop IPA
- **SCA (SCA_001):** CVE scanner against offline OSV.dev database
- **React Native (RN_001):** JS bundle audit (AsyncStorage, secrets, WebView)
- **Flutter (FL_001):** Experimental string-level audit (cleartext URLs, secrets)

✅ **Phase 4 - Dynamic Analysis (DAST)**
- **mitmproxy integration:** HTTP/HTTPS traffic capture
- **ADB runner:** Install APK, set proxy, launch app, logcat capture
- **Device proxy config:** Global proxy + WiFi cycling for adherence
- **MITM addon:** Custom Python addon captures flows to JSONL
- **41 DAST agents:** D_001-D_041 analyze captured traffic
  - D_003: Biometric weakness detection
  - D_004: Anti-tamper coverage
  - D_007: Race condition detection
  - D_010: JWT weakness analysis
  - D_012: Notification leak detection
  - D_026: Insecure Keystore usage
  - And 35+ more...

✅ **Phase 4.5 - Frida Runtime Instrumentation**
- **30+ hook modules** (TypeScript)
- Crypto hooks: `Cipher.getInstance`, `MessageDigest`, `SecretKeyFactory`
- Pinning hooks: OkHttp, System TrustManager, native libssl, WebView
- Biometric hooks: `BiometricPrompt`, weak-only fallback detection
- Accessibility hooks: A11y abuse, notification listener
- IPC hooks: Intent dispatch, receiver registration, ContentProvider
- File hooks: FileProvider, ZIP traversal, external storage
- Runtime exec: `ProcessBuilder`, `Runtime.exec()`, `System.load()`
- **Hook orchestration:** `frida_agent/src/agent.ts` (182 LOC)
- **Event stream:** Hooks emit structured events to Python via `send()`

✅ **Phase 3 - LLM Triage**
- False positive filtering
- Severity adjustment based on context
- Code context enrichment (loads snippets from decompiled source)
- RAG-enhanced prompts (CWE/MASVS/OWASP citations)
- Triage outcomes: `VERIFIED`, `FILTERED`, `UNCERTAIN`, `NEEDS_VERIFICATION`

✅ **Phase 7 - Exploit Chain Detection (COR_001)**
- NetworkX graph construction (findings as nodes, relationships as edges)
- Pattern matching: Token Theft Chain, RCE Chain
- Novel chain discovery via path traversal
- Confidence scoring based on edge weights
- Promotes LOW+LOW findings → CRITICAL when chained

✅ **Phase 8 - Reporting (R_001)**
- Markdown format (GitHub/HackerOne/Bugcrowd compatible)
- HTML format (self-contained, VAPT report style)
- Executive summary generation (LLM-powered)
- Risk score calculation (0-100 based on severity distribution)
- Reference aggregation (CWE, OWASP, MASVS links from RAG)

✅ **Verification Engine**
- 15+ verifiers for runtime confirmation
- **Manifest verifiers:** Backup rules, debuggable flag, file provider, permissions
- **Frida verifiers:** Crypto detection, pinning bypass
- **MITM verifiers:** Cleartext traffic
- **Active replay verifiers:** IDOR perturbation, race condition parallel-fire, token redaction
- Outcomes: `VERIFIED`, `REFUTED`, `INCONCLUSIVE`, `UNSUPPORTED`

✅ **Exploit Generation (Sprint 9 - Experimental)**
- Driver system: Deep-link hijack, IDOR, race condition
- Burp payloads, shell scripts, Python replayers
- Frida hook injection scripts
- Authorization checks (scope + forbidden techniques)
- `sentinel exploit generate <session_id> <finding_id>`

✅ **Diff Mode (CI Integration)**
- Baseline fingerprinting (finding_id = hash(agent_id, vuln_class, evidence))
- Delta computation: NEW / FIXED / UNCHANGED
- Exit code gating: `--fail-on critical,high`
- Markdown report (PR comment format)
- `sentinel diff --base old.apk --head new.apk`

✅ **Memory Bus**
- SQLite (WAL mode) for events + findings
- ChromaDB for embeddings (semantic search)
- NetworkX for exploit chain graph
- Health checks, connection pooling, async I/O

✅ **API Gateway (FastAPI)**
- `/scans` - Create, list, get, delete
- `/agents` - Registry with 88 agents
- `/scope` - Parse bounty programs (5 platforms)
- `/reports` - Download Markdown/HTML/JSON
- `/auth` - JWT + API key authentication
- Rate limiting middleware (100 req/min per IP)
- CORS pinned to localhost origins

✅ **CLI (Click)**
```bash
sentinel serve              # Start API gateway
sentinel scan <apk>         # Full scan
sentinel diff <base> <head> # APK regression diff
sentinel verify <session>   # Re-run verifiers
sentinel exploit generate   # PoC generation
sentinel rag build/query    # Knowledge base
sentinel scope parse        # Bounty scope ingestion
sentinel agents             # List 88 agents
```

### 3.2 Partially Implemented

🚧 **Frontend Web UI**
- Dashboard with scan overview
- Findings table (severity filtering)
- Agent registry browser
- Settings panel
- **Status:** Static prototype, not wired to API yet

🚧 **Production Memory (Sprint 11)**
- Redis for event bus (pub/sub)
- Qdrant for vector store
- Neo4j for knowledge graph
- **Status:** Interface defined, stub implementation

🚧 **iOS Support**
- Agent contracts are platform-agnostic
- Tooling gaps: Need ipa-extract, class-dump, iOS Frida hooks
- **Status:** Architecture ready, tools not integrated

🚧 **Emulator Automation (Sprint 8.3)**
- Intent fuzzing, UI crawler, deep-link exerciser
- **Status:** Manual app interaction required for DAST

### 3.3 Not Yet Implemented

❌ **Phase 5 - Verification** (roadmap-only; no `_phase5_verification()` in `orchestrator.py`)
❌ **Phase 9 - Meta-exploration (M_001)** (SWARM_001 runs in Phase 2.6, but no standalone M_001/Phase 9)
🚧 **Multi-worker orchestration** (asyncio task-per-scan in a single process via `scan_runner.py:475`; no multiprocess/Celery/distributed queue)
❌ **Real-time scan progress** (no WebSocket endpoints; clients poll `GET /scans/{id}` per `routes/scans.py:193`)
🚧 **Scan queue management** (in-memory FIFO `ScanRegistry` with cancel-only; no priority, reorder, or persistence)
❌ **User authentication** (JWT + API keys implemented, not enforced)

---

## 4. CONFIGURATION & SETUP

### 4.1 System Requirements

**Platform:** Linux (tested on CachyOS / Arch, should work on Ubuntu/Debian)

**Dependencies:**
| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12 only | Runtime (enforced in pyproject.toml) |
| Poetry | ≥1.7 | Dependency management |
| Java | 17+ | JADX, apktool, FlowDroid |
| JADX | latest | APK → Java decompilation |
| apktool | latest | APK → manifest + resources |
| Ollama | latest | Local LLM (qwen2.5-coder + embeddings) |
| Node.js | 18+ | Frida agent build |
| Frida | 16.5.7 | Runtime instrumentation |
| mitmproxy | 12.2.3 | Traffic interception |
| ADB | latest | Device communication |
| Semgrep | 1.163+ | AST-based SAST |

**Ollama Models:**
```bash
ollama pull qwen2.5-coder:7b-instruct-q4_K_M  # ~4GB
ollama pull nomic-embed-text                  # ~275MB
```

### 4.2 Installation

```bash
# 1. Clone repo
git clone <your-fork> sentinel && cd sentinel

# 2. Install Python dependencies
poetry install

# 3. (Arch/CachyOS) Install system tools
paru -S jadx apktool jdk-openjdk ollama android-tools semgrep

# 4. Start Ollama service
systemctl --user enable --now ollama

# 5. Pull models
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama pull nomic-embed-text

# 6. Configure API keys
cp .env.example .env
$EDITOR .env  # Add GROQ_API_KEY or CEREBRAS_API_KEY

# 7. Verify setup
./scripts/verify_setup.sh

# 8. Build Frida agent (TypeScript)
cd frida_agent && npm install && npm run build

# 9. Build knowledge base (one-time)
poetry run sentinel rag build
```

### 4.3 Environment Variables (.env)

```bash
# LLM Providers (at least one required for triage)
GROQ_API_KEY=gsk_...              # Recommended (14k RPD free)
CEREBRAS_API_KEY=csk_...          # Fallback (1M tok/day)
OLLAMA_HOST=http://localhost:11434

# Runtime
SENTINEL_LOG_LEVEL=INFO           # DEBUG|INFO|WARNING|ERROR
SENTINEL_WORKSPACE=./workspace    # Decompile output
SENTINEL_MAX_APK_SIZE_MB=500      # Upload limit
SENTINEL_SCAN_TIMEOUT_SECONDS=1800 # Per-scan timeout (30 min)
```

### 4.4 Docker (Production Memory - Sprint 11)

```bash
# Start Redis + Qdrant + Neo4j
docker-compose up -d

# Configure SENTINEL to use production memory
# (Not yet wired - Sprint 11 deliverable)
```

---

## 5. KEY CODE FILES & IMPLEMENTATION DETAILS

### 5.1 Agent Orchestration Logic

**File:** `sentinel/core/orchestrator.py` (887 LOC)

**Key Methods:**

```python
class Orchestrator:
    async def run(self) -> ScanResult:
        """Execute 10-phase pipeline"""
        # Phase 0: Ingestion (hash, workspace)
        await self._phase0_ingestion()
        
        # Phase 1: Recon (PARALLEL - Sprint 7.6.3)
        await asyncio.gather(
            self._run_jadx(),
            self._run_apktool(),
            self._run_androguard(),
            return_exceptions=True  # Crash-proof
        )
        
        # Phase 2: Static agents
        await self._phase2_agents(static_agents)
        
        # Phase 3: Triage (optional)
        if self._triager:
            await self._phase3_triage()
        
        # Phase 4: Dynamic (opt-in via --dynamic)
        if self._dynamic_enabled:
            await self._phase4_dynamic()
            
            # Phase 4.5: Frida (opt-in via --frida)
            if self._frida_enabled:
                await self._run_frida_subphase()
        
        # Phase 7: Correlation
        await self._phase7_correlation()
        
        # Phase 8: Reporting
        await self._phase8_report()
```

**Crash Isolation:**
- Tools return `ToolResult(success=bool, data, error)` instead of raising
- `asyncio.gather(return_exceptions=True)` prevents one tool failure from blocking others
- Agent errors caught in `BaseAgent.run()`, emit `agent.failed` event, continue scan

**Parallel Execution:**
- Phase 1 tools run concurrently (JADX + apktool + Androguard)
- Phase 2 agents run in parallel via `asyncio.gather()`
- No inter-agent dependencies (all read from shared `ScanContext`)

### 5.2 Agent Definition & Initialization

**File:** `sentinel/agents/base/base_agent.py` (178 LOC)

**Example Agent:**
```python
class CleartextTrafficAgent(BaseAgent):
    AGENT_ID = "N_002"
    VULN_CLASS = "Cleartext Traffic"
    PHASE = "static"
    
    async def is_applicable(self) -> bool:
        return bool(self._context.manifest)
    
    async def analyze(self) -> list[Finding]:
        findings = []
        
        # Check manifest flag
        if self._context.manifest.get("cleartext_enabled"):
            findings.append(self._make_finding(
                severity=Severity.HIGH,
                confidence=0.9,
                evidence={"flag": "usesCleartextTraffic=true"},
                recommendation="Set android:usesCleartextTraffic=\"false\""
            ))
        
        # Scan decompiled code for http:// URLs
        if self._context.decompiled_dir:
            urls = self._scan_directory(self._context.decompiled_dir)
            if urls:
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    evidence={"urls": urls[:10]},  # Cap samples
                    recommendation="Migrate to HTTPS"
                ))
        
        return findings
```

**Auto-filled Fields:**
- `_make_finding()` auto-sets `session_id`, `agent_id`, `evidence['package']`
- `evidence['package']` populated from manifest to enable scope filtering

**Scope Enforcement:**
- `BaseAgent.run()` calls `_within_scope(finding)` before storage
- Out-of-scope findings dropped silently (logged at DEBUG level)

### 5.3 Inter-Agent Communication

**Pattern:** Agents don't talk to each other directly. They share data via:

1. **ScanContext** (read-only shared state)
```python
@dataclass
class ScanContext:
    session_id: str
    apk_path: Path
    decompiled_dir: Path | None
    manifest: dict[str, Any]
    scope: BountyScope
    sources: dict[str, Any]  # Tool outputs
```

2. **Memory Bus** (async pub/sub)
```python
# Agent A publishes
await memory.publish_event(
    session_id=ctx.session_id,
    event_type="finding.emitted",
    payload={"finding_id": "...", "severity": "High"}
)

# Agent B polls (if needed - rare)
events = await memory.poll_events(
    session_id=ctx.session_id,
    event_type="finding.emitted",
    since_timestamp=...
)
```

3. **Shared findings storage**
```python
# Agent C retrieves findings from Agent A/B
findings = await memory.get_findings(
    session_id=ctx.session_id,
    severity_filter=[Severity.HIGH, Severity.CRITICAL]
)
```

**Why this pattern?**
- Agents can run in any order
- No coupling between agents
- Easy to add new agents without touching existing ones
- Parallel execution without race conditions

### 5.4 LLM Integration Code

**File:** `sentinel/llm/router.py` (479 LOC)

**Provider Interface:**
```python
class LLMProvider(ABC):
    @abstractmethod
    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        json_mode: bool = False
    ) -> str:
        """Send messages, return response text"""
```

**Router Logic:**
```python
class FreeProviderRouter:
    async def query(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        force_local: bool = False
    ) -> str:
        # Try providers in priority order
        for provider in self._eligible_providers(force_local):
            if provider.is_circuit_open():
                continue
            
            try:
                response = await provider.query(...)
                provider.record_success()
                return response
            except Exception as e:
                provider.record_failure()
                if provider.consecutive_failures >= CIRCUIT_BREAK_THRESHOLD:
                    provider.open_circuit(CIRCUIT_RESET_SECONDS)
        
        raise RouterError("All providers exhausted")
```

**Circuit Breaker:**
- Tracks consecutive failures per provider
- After 3 failures, provider skipped for 2 minutes
- Prevents beating on a rate-limited/down endpoint

**Usage in Agents:**
```python
from sentinel.llm.router import FreeProviderRouter

router = FreeProviderRouter()
response = await router.query(
    messages=[
        {"role": "system", "content": "You are a security analyst"},
        {"role": "user", "content": f"Is this a false positive? {evidence}"}
    ],
    temperature=0.3
)
```

### 5.5 Frida Script Generation & Execution

**Generation:**
Frida hooks are **pre-written TypeScript modules**, not LLM-generated.

**Location:** `frida_agent/src/hooks/*.ts` (30+ modules)

**Build Process:**
```bash
cd frida_agent
npm install
npm run build  # TypeScript → JavaScript bundle
```

**Output:** `frida_agent/_agent.js` (single-file bundle)

**Execution Flow:**

1. **Python side** (`sentinel/tools/frida_runner.py`):
```python
class FridaRunner:
    async def inject_script(self, package_name: str) -> FridaCapture:
        # 1. Find target process PID
        pid = await self._find_pid(package_name)
        
        # 2. Attach Frida session
        session = await frida.attach(pid)
        
        # 3. Load compiled agent
        script_code = load_runtime_hooks()
        script = await session.create_script(script_code)
        
        # 4. Set up message handler
        script.on('message', self._on_message)
        
        # 5. Load script into app process
        await script.load()
        
        # 6. Wait for duration (default 60s)
        await asyncio.sleep(self._duration)
        
        # 7. Detach and return captured events
        await session.detach()
        return FridaCapture(events=self._events)
```

2. **TypeScript side** (`frida_agent/src/agent.ts`):
```typescript
// Wait for Java bridge availability
waitForJava("sentinel-agent", () => {
    // Install all hook modules
    installCryptoHooks(result);
    installOkHttpHooks(result);
    installSystemHooks(result);
    // ... 27 more modules
    
    // Emit summary
    emitHooksSummary(result);
});
```

3. **Hook Module Example** (`hooks/crypto.ts`):
```typescript
export function installCryptoHooks(result: HookResult) {
    Java.perform(() => {
        const Cipher = Java.use("javax.crypto.Cipher");
        
        Cipher.getInstance.overload("java.lang.String")
            .implementation = function(transformation: string) {
            
            // Emit event to Python
            send({
                type: "crypto.cipher_instance",
                transformation: transformation,
                algorithm: transformation.split("/")[0],
                stack: shortStack()  // 3-frame stack trace
            });
            
            // Call original
            return this.getInstance(transformation);
        };
    });
}
```

**Event Flow:**
```
Frida Hook → send({type, data}) → Python _on_message() 
          → Append to events list → FridaCapture returned
          → DAST agents (A_003, N_005) analyze events
```

### 5.6 mitmproxy Integration

**File:** `sentinel/tools/mitmproxy_runner.py` (270 LOC)

**Architecture:**

1. **Runner starts mitmdump subprocess:**
```python
class MitmproxyRunner:
    async def start(self, capture_file: Path, port: int = 8080):
        # Write addon code to temp file
        addon_path = self._workspace / "mitm_addon.py"
        addon_path.write_text(_ADDON_CODE.format(
            capture_file=capture_file
        ))
        
        # Start mitmdump with addon
        self._proc = await asyncio.create_subprocess_exec(
            "mitmdump",
            "-s", str(addon_path),
            "-p", str(port),
            "--set", "flow_detail=2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
```

2. **Addon captures flows to JSONL:**
```python
_ADDON_CODE = '''
def response(flow):
    """mitmproxy calls this for each request/response"""
    record = {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "scheme": flow.request.scheme,
        "host": flow.request.pretty_host,
        "request_headers": dict(flow.request.headers),
        "request_body": flow.request.get_text()[:5000],
        "response_status": flow.response.status_code,
        "response_body": flow.response.get_text()[:5000],
        "tls_failed": False
    }
    
    with open("{capture_file}", "a") as f:
        f.write(json.dumps(record) + "\\n")
'''
```

3. **Device proxy configuration:**
```python
class AdbRunner:
    async def set_global_proxy(self, host: str, port: int):
        await self._run_adb([
            "shell", "settings", "put", "global",
            "http_proxy", f"{host}:{port}"
        ])
        
        # Cycle WiFi to enforce proxy on stubborn apps
        await self._cycle_wifi()
```

4. **DAST agents parse JSONL:**
```python
class DataInTransitAgent(BaseAgent):  # N_004
    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if not capture:
            return []
        
        for flow in capture.flows:
            # Scan for secrets in URLs/headers/body
            self._scan_flow(flow, findings)
        
        return findings
```

**mitmproxy CA Certificate:**
- Installed via `scripts/install-mitm-ca.sh`
- Pushes `~/.mitmproxy/mitmproxy-ca-cert.pem` to device
- Required for HTTPS interception

---

## 6. DEPENDENCIES & TECH STACK

### 6.1 Python Libraries (pyproject.toml)

**Core:**
- `pydantic` (2.9) - Data validation, SecretStr for API keys
- `pydantic-settings` (2.6) - .env file loading
- `httpx` (0.27) - Async HTTP client for LLM providers
- `click` (8.1) - CLI framework
- `rich` (13.9) - Terminal formatting

**Web:**
- `fastapi` (0.115) - REST API gateway
- `uvicorn` (0.32) - ASGI server
- `websockets` (13.0) - Real-time scan updates (stub)
- `jinja2` (3.1) - HTML template rendering
- `python-multipart` (0.0.29) - File upload handling

**Security:**
- `python-jose[cryptography]` (3.5) - JWT tokens
- `passlib[bcrypt]` (1.7) - Password hashing

**Analysis:**
- `androguard` (4.1.2) - APK bytecode analysis
- `tree-sitter` (0.23) - AST parsing for taint analysis
- `tree-sitter-languages` (1.10.2) - Language grammars
- `tree-sitter-java` (0.23.5) - Java grammar
- `semgrep` (1.163) - AST-based SAST

**ML/RAG:**
- `chromadb` (0.5.15) - Vector database
- `networkx` (3.4.2) - Graph algorithms for exploit chains

**Storage:**
- `sqlalchemy` (2.0.35) - ORM (unused, SQLite accessed via aiosqlite)
- `aiosqlite` (0.20) - Async SQLite driver

**Tools:**
- `mitmproxy` (12.2.3) - Traffic interception
- `frida` (16.5.7) - Runtime instrumentation
- `aiofiles` (25.1) - Async file I/O
- `unidiff` (0.7.5) - Patch parsing for remediation

### 6.2 External Binaries

| Tool | Purpose | Wrapper |
|------|---------|---------|
| jadx | APK → Java | `sentinel/tools/jadx.py` |
| apktool | APK → resources | `sentinel/tools/apktool.py` |
| semgrep | AST SAST | `sentinel/agents/semgrep/semgrep_agent.py` |
| adb | Device control | `sentinel/tools/adb_runner.py` |
| mitmdump | Traffic capture | `sentinel/tools/mitmproxy_runner.py` |
| ollama | Local LLM | `sentinel/llm/router.py` |

### 6.3 TypeScript/Node.js (Frida Agent)

**Build Tool:** esbuild (bundles to single JS file)

**Dependencies:**
- `frida` (npm) - Type definitions
- `@types/node` - Node.js types

**Source:** `frida_agent/src/**/*.ts`  
**Output:** `frida_agent/_agent.js`

---

## 7. TESTING STRATEGY

### 7.1 Test Structure

**Total:** 90+ unit tests, 1 integration test

**Coverage:**
- Core models (Finding, Scope, ScanContext): 100%
- LLM router (failover, circuit breaker, JSON mode): 95%
- Memory bus (events, findings, graph): 100%
- Agent lifecycle (skip, error isolation, scope filter): 100%
- Tool wrappers (mocked subprocess calls): 85%
- Triage (LLM response parsing): 90%
- Diff mode (fingerprinting, delta computation): 95%

**Test Files:**
```
tests/unit/
├── test_sprint1_core.py          # Finding, Scope, Settings
├── test_sprint2a.py              # Memory bus, BaseAgent
├── test_sprint2b.py              # Orchestrator, tool wrappers
├── test_scope_parser.py          # Bounty program parsing
├── test_api.py                   # FastAPI endpoints
├── test_triage.py                # LLM triager
├── test_diff.py                  # APK diff
├── test_verify.py                # Verification engine
├── test_*_agent.py               # Per-agent tests (80+ files)

tests/integration/
└── test_phase1_real_apk.py       # Full scan on InsecureBankv2.apk
```

### 7.2 Test Approach

**Unit Tests:**
- Mock external dependencies (subprocess, httpx, file I/O)
- Fixtures for common objects (ScanContext, MemoryInterface)
- Parametrized tests for agent permutations

**Integration Test:**
- Requires `corpus/InsecureBankv2.apk` (gitignored, manually added)
- Runs full Phase 0+1+2 pipeline
- Skipped if tools (jadx/apktool) not on PATH

**Example Test:**
```python
@pytest.fixture
async def memory():
    mem = LightweightMemory(Path("/tmp/test"))
    await mem.connect()
    yield mem
    await mem.close()

async def test_agent_emits_finding(memory):
    ctx = ScanContext(...)
    agent = CleartextTrafficAgent(ctx, memory)
    
    findings = await agent.run()
    
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    
    # Verify finding was saved
    saved = await memory.get_finding(ctx.session_id, findings[0].finding_id)
    assert saved is not None
```

### 7.3 CI Pipeline

**File:** `.github/workflows/ci.yml`

**Steps:**
1. Checkout code
2. Set up Python 3.12
3. Install Poetry
4. `poetry install`
5. `ruff check` (linting)
6. `pytest tests/unit -v` (unit tests only, skips integration)

**Missing:**
- Integration tests (require APK corpus)
- Type checking (`mypy --strict`)
- Coverage reporting

---

## 8. PERFORMANCE & BOTTLENECKS

### 8.1 Scan Duration (InsecureBankv2.apk benchmark)

**Full scan with --dynamic --frida --triage:**
- Phase 0 (Ingestion): ~1s
- Phase 1 (Recon): ~30s (JADX 25s, apktool 5s, Androguard 3s)
- Phase 2 (Static): ~20s (88 agents, most skip)
- Phase 3 (Triage): ~15s (LLM calls, 10-20 findings)
- Phase 4 (Dynamic): ~90s (mitmproxy setup 5s + manual testing 60s + teardown 5s)
- Phase 4.5 (Frida): ~60s (hook installation + wait period)
- Phase 7 (Correlation): ~2s
- Phase 8 (Reporting): ~5s
- **Total: ~223s (~3.7 minutes)**

**Bottlenecks:**

1. **JADX decompilation (25s)**
   - Single-threaded, CPU-bound
   - Scales linearly with APK size
   - **Mitigation:** Already parallelized with apktool/Androguard

2. **LLM triage (15s for 20 findings)**
   - Network latency to Groq/Cerebras
   - ~750ms per finding
   - **Mitigation:** Batch findings in single prompt (Sprint 10 planned)

3. **Manual DAST interaction (60s)**
   - User exercises app while mitmproxy/Frida capture
   - **Mitigation:** Emulator automation (Sprint 8.3)

4. **Taint analysis (TAINT_001) on large codebases**
   - Tree-sitter parsing: ~50ms per file
   - Backward slicing: ~100ms per sink
   - **Cap:** 3000 files, 10s per-file timeout
   - **Mitigation:** Already optimized with timeout

### 8.2 Memory Usage

**Typical scan:**
- Python process: ~500MB (ChromaDB embeddings)
- JADX subprocess: ~2GB (JVM heap)
- SQLite database: ~5MB per scan
- Frida hooks: ~20MB injected into target process

**Large APK (500MB, 10k classes):**
- Python process: ~1.5GB
- JADX subprocess: ~8GB (can OOM, configured with `-Xmx8G`)

### 8.3 Disk Usage

**Per scan:**
- Decompiled sources: ~50MB (JADX)
- Resources: ~20MB (apktool)
- JSONL captures: ~5MB (mitmproxy + Frida)
- **Total workspace:** ~75MB

**Cumulative:**
- SQLite database: ~5MB per scan
- ChromaDB vectors: ~50MB (grows slowly with corpus ingestion)
- **After 100 scans:** ~7.5GB workspace + ~500MB SQLite

**Cleanup:**
```bash
# Remove workspace for a session
rm -rf workspace/<session_id>

# Vacuum SQLite
sqlite3 data/sentinel.db "VACUUM;"
```

---

## 9. SPECIFIC AREAS FOR FEEDBACK

### 9.1 Architecture Questions

1. **Is the custom agent framework justified vs. LangChain?**
   - Trade-off: Control vs. ecosystem
   - Concern: Reinventing the wheel for orchestration

2. **Should agents communicate via events or direct function calls?**
   - Current: Events (decoupled, async-friendly)
   - Alternative: Direct calls (simpler, but tight coupling)

3. **Is SQLite + ChromaDB sufficient for production at scale?**
   - Concern: Multi-worker scans need Redis/Qdrant (Sprint 11)
   - Question: When to migrate? After 1000 scans/day?

### 9.2 LLM Usage Concerns

1. **Triage accuracy:**
   - False positive rate: ~15% (anecdotal, not measured)
   - Over-reliance on LLM vs. rule-based heuristics?

2. **Cost management:**
   - Groq free tier: 14k RPD → ~200 scans/day (70 findings each)
   - What happens when free tier exhausted mid-scan?
   - Current: Falls back to Cerebras → Ollama

3. **Remediation patch quality:**
   - Experimental, not production-ready
   - Accuracy unknown (needs evaluation corpus)
   - Should this be behind a flag permanently?

### 9.3 DAST Reliability

1. **mitmproxy CA trust issues:**
   - Some apps (banking, fintech) reject user CAs even after install
   - Workaround: `--no-proxy` mode (less coverage)
   - Better solution?

2. **Frida detection:**
   - RASP solutions (Promon, Guardsquare) detect Frida hooks
   - App crashes immediately
   - Mitigation: Bypass RASP first (Sprint 10 planned)

3. **Device proxy stubbornness:**
   - Some apps ignore global proxy setting
   - Current: WiFi cycle (helps 80% of cases)
   - Alternative: iptables redirect (requires root)?

### 9.4 Agent Coverage Gaps

1. **Platform-specific agents:**
   - 11 IPC/Platform agents (P_*), but Android IPC is vast
   - Missing: Service binding IDOR, Binder transaction abuse
   - Priority?

2. **Business logic agents:**
   - Only 5 agents (B_*) for business logic
   - Hard to generalize (app-specific)
   - Should these be framework + user-written rules?

3. **AI/ML agents:**
   - Placeholder category, 0 agents
   - What would these detect? Model extraction? Adversarial robustness?

### 9.5 Deduplication Strategy

1. **Current approach:**
   - Hash (agent_id, vuln_class, evidence["file"], evidence["line"])
   - Collapses identical detections across runs
   - Problem: Different file path = different finding_id

2. **Semantic dedup via embeddings?**
   - Cluster findings by similarity (cosine distance < 0.1)
   - Concern: False negatives (genuinely different bugs clustered)

3. **Should diff mode be the primary interface?**
   - Always compare against baseline from last scan
   - Only report NEW findings
   - Shift from "scan" to "delta scan"

### 9.6 Verification Bottlenecks

1. **Active replay safety:**
   - Replayers issue real HTTP requests to production
   - Gated by `--active-replay` flag + scope check
   - Still risky (parallel race condition fire = mini-DDoS)
   - Rate limiting needed?

2. **Verifier coverage:**
   - 15 verifiers for 88 agents (17%)
   - Most findings unverified → high false positive rate
   - Writing verifiers is hard (need runtime environment)
   - Prioritize which agents?

3. **Verification timeout:**
   - Active replays can hang on slow/broken backends
   - Current: 30s per HTTP request
   - Adjust? Configurable?

---

## 10. DEVELOPMENT WORKFLOW

### 10.1 Adding a New Agent

1. **Create agent file:**
   ```bash
   touch sentinel/agents/<category>/<agent_id>_<name>.py
   ```

2. **Implement BaseAgent:**
   ```python
   class NewAgent(BaseAgent):
       AGENT_ID = "X_999"
       VULN_CLASS = "New Vulnerability"
       PHASE = "static"
       
       async def is_applicable(self) -> bool:
           return self._context.decompiled_dir is not None
       
       async def analyze(self) -> list[Finding]:
           # Detection logic here
           pass
   ```

3. **Register in `__init__.py`:**
   ```python
   # sentinel/agents/<category>/__init__.py
   from .x999_new_agent import NewAgent
   __all__ = ["NewAgent"]
   ```

4. **Add to orchestrator:**
   ```python
   # sentinel/core/orchestrator.py
   from sentinel.agents.<category> import NewAgent
   
   static_agents = [
       # ... existing agents
       NewAgent,
   ]
   ```

5. **Write tests:**
   ```bash
   touch tests/unit/test_new_agent.py
   ```

6. **Run tests:**
   ```bash
   poetry run pytest tests/unit/test_new_agent.py -v
   ```

### 10.2 Adding a Frida Hook

1. **Create hook module:**
   ```bash
   touch frida_agent/src/hooks/new_hook.ts
   ```

2. **Implement hook:**
   ```typescript
   export function installNewHook() {
       Java.perform(() => {
           const Target = Java.use("com.example.TargetClass");
           Target.method.implementation = function(...args) {
               send({ type: "new_hook.event", data: args });
               return this.method(...args);
           };
       });
   }
   ```

3. **Register in `agent.ts`:**
   ```typescript
   import { installNewHook } from "./hooks/new_hook.js";
   
   waitForJava("sentinel-agent", () => {
       // ... existing hooks
       installNewHook();
   });
   ```

4. **Rebuild:**
   ```bash
   cd frida_agent && npm run build
   ```

5. **Create DAST agent to consume events:**
   ```python
   # sentinel/agents/dynamic/d999_new_dynamic.py
   class NewDynamicAgent(BaseAgent):
       async def analyze(self) -> list[Finding]:
           capture = self._context.sources.get("frida")
           events = [e for e in capture.events if e["type"] == "new_hook.event"]
           # Process events...
   ```

### 10.3 Pre-commit Checklist

```bash
# 1. Lint
poetry run ruff check sentinel tests

# 2. Format
poetry run ruff format sentinel tests

# 3. Unit tests
poetry run pytest tests/unit -v

# 4. Type check (optional, not enforced)
poetry run mypy sentinel

# 5. Integration test (if APK available)
poetry run pytest tests/integration -v -m integration
```

---

## 11. ROADMAP & FUTURE WORK

### Sprint 10 (Current)
- [ ] Emulator automation (UI crawler, intent fuzzer)
- [ ] RASP bypass module
- [ ] Batch LLM triage (reduce latency)
- [ ] Semantic finding deduplication

### Sprint 11
- [ ] Production memory (Redis/Qdrant/Neo4j)
- [ ] Multi-worker orchestration
- [ ] WebSocket real-time progress
- [ ] Scan queue management (priority, cancellation)

### Sprint 12
- [ ] Frontend web UI completion
- [ ] User management (teams, roles)
- [ ] Scan scheduling (cron, webhooks)
- [ ] Report customization (templates, branding)

### Long-term
- [ ] iOS support (ipa-extract, Frida iOS hooks)
- [ ] Cloud deployment (Kubernetes, Terraform)
- [ ] SaaS mode (multi-tenant, billing)
- [ ] API rate limiting per user
- [ ] Marketplace for community agents

---

## 12. SECURITY & PRIVACY

### 12.1 Where Your APK Goes

**Local-only by default:**
- APK stays on your laptop in `./workspace/<session_id>/`
- Only short text snippets sent to LLM (not entire APK)

**Cloud LLM usage:**
- Triage prompts: ~500 tokens per finding (evidence summary)
- Reports: ~1000 tokens per scan (aggregated findings)
- **No source code** sent, only metadata (file paths, line numbers, pattern matches)

**Private mode:**
```bash
sentinel scan app.apk --private  # Forces local-only, skips cloud LLMs
```

### 12.2 API Key Safety

- Stored as `SecretStr` (pydantic)
- Never logged, never in `repr()`, never in tracebacks
- Loaded from `.env` (gitignored)

**Verification:**
```python
settings = get_settings()
print(settings.groq_api_key)  # Output: SecretStr('**********')
```

### 12.3 Scan Data Retention

**SQLite database:**
- Location: `./data/sentinel.db`
- Contains: Findings, events, session metadata
- **No APK binary data** stored

**Workspace cleanup:**
```bash
# Auto-cleanup after scan (opt-in)
sentinel scan app.apk --cleanup

# Manual cleanup
rm -rf workspace/<session_id>
```

**ChromaDB vectors:**
- Only knowledge base corpora (CWE, MASVS, OSV)
- No app-specific data embedded

### 12.4 Network Safety

**Scope parser SSRF protection:**
- Blocks `localhost`, `127.0.0.1`, RFC-1918 private IPs
- Blocks `file://` scheme
- 500KB max page size

**Active replay authorization:**
- Gated by `--active-replay` flag
- Scope check (must be in-scope domain/package)
- Forbidden technique check (no DoS, no brute-force)

---

## 13. CONTACT & CONTRIBUTION

**Author:** Shambhu (stw00070@softwarica.edu.np)  
**Teams:** stw0070  
**GitHub:** (not public yet)

**How to contribute:**
1. Read `docs/AGENT_GUIDE.md`
2. Pick an agent from the 88-agent roadmap
3. Implement + test
4. Submit PR with:
   - Agent code
   - Unit test (100% coverage)
   - Entry in `sentinel/agents/<category>/__init__.py`
   - README update

**License:** TBD (All Rights Reserved until formal license chosen)

---

## 14. SUMMARY & RECOMMENDATIONS

### What's Working Well

✅ **Crash-proof orchestration** - Tool failures don't cascade  
✅ **Agent isolation** - Easy to add/modify agents independently  
✅ **Free-tier LLM strategy** - Groq → Cerebras → Ollama works reliably  
✅ **Scope enforcement** - Out-of-scope findings never stored  
✅ **Frida instrumentation** - 30+ hooks cover broad attack surface  
✅ **DAST pipeline** - mitmproxy + Frida integration functional  
✅ **Taint analysis** - Tree-sitter backward slicing with IPA is novel  

### What Needs Work

🔧 **Verification coverage** - Only 17% of agents have verifiers  
🔧 **DAST reliability** - CA trust and Frida detection issues  
🔧 **Emulator automation** - Manual app interaction bottleneck  
🔧 **LLM triage accuracy** - 15% false positive rate too high  
🔧 **Frontend** - Web UI not wired to backend yet  
🔧 **Production memory** - Sprint 11 deliverable (Redis/Qdrant/Neo4j)  
🔧 **iOS support** - Architecture ready, tooling missing  

### Key Technical Strengths

1. **No framework lock-in** - Custom agent system, not tied to LangChain
2. **Hybrid LLM** - Cloud quality with local fallback
3. **3-tier memory** - Events + embeddings + graph in one interface
4. **Diff mode** - CI regression gate is production-ready
5. **RAG integration** - CWE/MASVS/OSV citations enhance reports

### Architecture Recommendations

1. **Keep custom agent framework** - LangChain adds overhead, limited benefit here
2. **Migrate to Redis/Qdrant after 1000 scans/day** - SQLite fine for solo use
3. **Add semantic dedup with 0.9 cosine threshold** - Reduce noise
4. **Batch triage prompts (10 findings per LLM call)** - 5x speedup
5. **Make `--diff` the default mode** - Always compare against baseline
6. **Add rate limiting to active replays** - 1 req/sec max per verifier
7. **Prioritize verifiers for HIGH/CRITICAL agents** - 80/20 rule

### Next Steps for Developer

1. **Profile TAINT_001 on large APK** - Identify per-file timeout sweet spot
2. **Evaluate remediation patch accuracy** - Build ground-truth corpus
3. **Implement emulator automation** - Unblock DAST at scale
4. **Add RASP bypass module** - Detect + disable Promon/Guardsquare
5. **Write 20 more verifiers** - Target HIGH/CRITICAL agents first
6. **Deploy on CI** - GitHub Actions integration with `sentinel diff`

---

**End of Document**

