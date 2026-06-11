# SENTINEL Static Analysis - Deep Technical Dive

**Generated:** June 8, 2026  
**Analysis Focus:** How static analysis works and how agents find bugs

---

## Table of Contents

1. [Static Analysis Architecture](#1-static-analysis-architecture)
2. [Phase 2 Pipeline Flow](#2-phase-2-pipeline-flow)
3. [Agent Detection Techniques](#3-agent-detection-techniques)
4. [Detailed Agent Analysis](#4-detailed-agent-analysis)
5. [Code Examples](#5-code-examples)
6. [Performance Characteristics](#6-performance-characteristics)

---

## 1. STATIC ANALYSIS ARCHITECTURE

### 1.1 Overview

SENTINEL's static analysis (Phase 2) operates on **decompiled APK artifacts** produced by Phase 1 (Recon). It uses **multiple complementary techniques** rather than relying on a single analysis engine:

```
Phase 1 Recon Output:
├── JADX decompiled Java → .java source files
├── apktool resources → XML manifests, layouts, configs
├── Androguard bytecode → DEX classes, strings, method signatures
└── Manifest parser → Structured manifest dict

                    ↓ feeds into ↓

Phase 2 Static Analysis (88+ agents):
├── Regex-based pattern matching (C_007, A_004, N_002)
├── AST parsing via tree-sitter (TAINT_001, P_010, RN_001)
├── Semgrep rules (SG_001) - 18 YAML rule files
├── Bytecode string scanning (A_004 via Androguard)
├── Manifest structure analysis (META_002, P_005, STG_009)
└── Cross-platform bundle inspection (RN_001, FL_001)
```

### 1.2 Why Multiple Techniques?

**No single analysis engine covers all vulnerability classes:**

| Technique | Best For | Limitations |
|-----------|----------|-------------|
| **Regex** | Crypto API misuse, hardcoded secrets, URL patterns | No data-flow, high false positives on comments/strings |
| **AST (tree-sitter)** | Control-flow, taint tracking, intent redirect | Requires parseable source (JADX can fail on obfuscation) |
| **Semgrep** | Known dangerous patterns, compliance checks | Rule coverage gaps, no inter-procedural analysis |
| **Bytecode strings** | Secrets in obfuscated APKs (always works) | No context (can't see usage, just presence) |
| **Manifest** | Permission abuse, component exposure | Only catches configuration issues |

**Design Philosophy:** Layer complementary techniques to maximize recall while keeping each agent's logic simple and auditable.

### 1.3 Data Flow Architecture

```python
# Orchestrator Phase 2 execution
async def _phase2_agents(self, agents: list[type[BaseAgent]]):
    """Run all static agents in parallel"""
    
    # 1. Instantiate all agents with shared context
    instances = [
        AgentClass(context=self._context, memory=self._memory)
        for AgentClass in agents
    ]
    
    # 2. Run in parallel (asyncio.gather)
    results = await asyncio.gather(
        *[agent.run() for agent in instances],
        return_exceptions=True  # One failure doesn't kill others
    )
    
    # 3. Aggregate findings (already saved to memory by BaseAgent.run())
    all_findings = [f for r in results if isinstance(r, list) for f in r]
    
    return all_findings
```

**Key Properties:**
- **Parallel execution** - 88 agents run concurrently via async I/O
- **Crash isolation** - Agent exceptions caught in `BaseAgent.run()`, logged, scan continues
- **Shared context** - All agents read from same `ScanContext` (immutable)
- **Independent storage** - Each agent saves findings directly to memory bus

### 1.4 Input Sources (What Agents Read)

**ScanContext provides:**

```python
@dataclass
class ScanContext:
    # Core
    session_id: str
    apk_path: Path
    workspace: Path
    
    # Phase 1 outputs (read by Phase 2 agents)
    decompiled_dir: Path | None          # JADX Java source
    resources_dir: Path | None           # apktool decoded resources
    manifest: dict[str, Any]             # Parsed AndroidManifest.xml
    target_sdk: int
    permissions: list[str]
    
    # Multi-source dict (Sprint 7.6.3+)
    sources: dict[str, Any]
        # 'jadx': JadxResult
        # 'apktool': ApktoolResult  
        # 'androguard': AndroguardAnalysis
    
    # Scope (out-of-scope filtering)
    scope: BountyScope
```

**Agents query these fields:**
- `ctx.decompiled_dir` - Walk for .java files (C_007, A_004, TAINT_001)
- `ctx.resources_dir` - Scan XML configs (STG_009, P_001, N_012)
- `ctx.manifest` - Check flags and component declarations (META_002, P_005)
- `ctx.sources['androguard']` - Query bytecode (A_004, NL_001)

---

## 2. PHASE 2 PIPELINE FLOW

### 2.1 Execution Timeline

```
Orchestrator._phase2_agents() called
    │
    ├─> Agent instantiation (88 agents, ~5ms total)
    │
    ├─> Parallel execution via asyncio.gather()
    │   │
    │   ├─ N_002 (Cleartext Traffic)     [0.2s] ─┐
    │   ├─ C_007 (Weak Crypto)           [0.8s] ─┤
    │   ├─ A_004 (Hardcoded Secrets)     [1.2s] ─┤
    │   ├─ SG_001 (Semgrep)              [15s]  ─┤  Run concurrently
    │   ├─ TAINT_001 (Data-flow)         [12s]  ─┤  (not sequentially)
    │   ├─ SCA_001 (CVE scanner)         [3s]   ─┤
    │   ├─ P_010 (Intent Redirect)       [5s]   ─┤
    │   └─ [... 81 more agents ...]              ─┘
    │       │
    │       ├─> Most agents skip (is_applicable = False)
    │       └─> ~15-20 agents produce findings
    │
    └─> Findings aggregated (already saved to SQLite)

Total Phase 2 duration: ~20s (limited by slowest agent, not sum)
```

### 2.2 Agent Lifecycle (BaseAgent.run())

Every agent goes through this standardized flow:

```python
async def run(self) -> list[Finding]:
    """BaseAgent orchestrates this automatically"""
    
    # 1. Emit start event
    await memory.publish_event(
        event_type="agent.started",
        payload={"agent_id": self.AGENT_ID}
    )
    
    # 2. Check applicability (skip if wrong platform, missing data)
    if not await self.is_applicable():
        await memory.publish_event(event_type="agent.skipped")
        return []
    
    # 3. Run detection logic (subclass implements this)
    try:
        findings = await self.analyze()  # <-- Agent's custom logic
    except Exception as e:
        await memory.publish_event(
            event_type="agent.failed",
            payload={"error": str(e)[:500]}
        )
        return []
    
    # 4. Scope filtering (out-of-scope findings dropped)
    scoped = [f for f in findings if self._within_scope(f)]
    
    # 5. Save findings + emit events
    for f in scoped:
        await memory.save_finding(f)
        await memory.publish_event(
            event_type="finding.emitted",
            payload={"finding_id": f.finding_id, "severity": f.severity}
        )
    
    # 6. Emit completion
    await memory.publish_event(
        event_type="agent.completed",
        payload={"findings_count": len(scoped)}
    )
    
    return scoped
```

**Key Points:**
- Agent only implements `is_applicable()` and `analyze()`
- Error isolation built into `run()` - exceptions don't crash pipeline
- Scope filter happens automatically before storage
- Events enable observability (CLI shows agent progress)

### 2.3 Scope Filtering Mechanism

```python
def _within_scope(self, finding: Finding) -> bool:
    """Automatic out-of-scope rejection"""
    scope = self._context.scope
    
    if scope.is_unrestricted():
        return True  # No scope file provided, accept everything
    
    # Check package (e.g., "com.example.app")
    package = finding.evidence.get("package")
    if package and not scope.package_in_scope(str(package)):
        logger.debug(
            "%s: Dropping out-of-scope package %s",
            self.AGENT_ID, package
        )
        return False
    
    # Check domain (for network-related findings)
    domain = finding.evidence.get("domain")
    if domain and not scope.domain_in_scope(str(domain)):
        return False
    
    return True
```

**Example:**
```python
# Bounty scope says "in scope: com.company.app"
# Agent finds hardcoded AWS key in com.thirdparty.analytics

finding = Finding(
    agent_id="A_004",
    evidence={"package": "com.thirdparty.analytics", ...}
)

# _within_scope() returns False
# Finding never saved to SQLite
# User never sees it in report
```

---

## 3. AGENT DETECTION TECHNIQUES

SENTINEL agents use 6 core detection patterns:

### 3.1 Regex Pattern Matching

**Used by:** C_007 (Weak Crypto), A_004 (Hardcoded Secrets), N_002 (Cleartext Traffic)

**Approach:**
1. Walk decompiled `.java` files recursively
2. Read each file as text (not parsed)
3. Apply regex to match dangerous API calls or secret patterns
4. Extract surrounding line for context
5. Group matches by pattern type
6. Emit one finding per pattern with all match locations

**Example (C_007 detecting DES):**

```python
_DES_PATTERN = re.compile(
    r'Cipher\.getInstance\s*\(\s*"DES(?:/[A-Z]+/[A-Za-z0-9]+)?"'
)

for java_file in decompiled_dir.rglob("*.java"):
    text = java_file.read_text()
    
    for match in _DES_PATTERN.finditer(text):
        # Extract line for context
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        line = text[start:end].strip()
        
        hits.append({
            "file": str(java_file.relative_to(decompiled_dir)),
            "context": line[:200],
            "matched": match.group(0)
        })
```

**Strengths:**
- Fast (milliseconds per file)
- Reliable on known patterns
- Works on any Java source (obfuscated or not)

**Weaknesses:**
- No data-flow (can't distinguish safe vs. dangerous usage)
- High false positives on comments/test code
- Misses variants (e.g., `cipher = "DES"; Cipher.getInstance(cipher)`)

### 3.2 AST-Based Control Flow Analysis

**Used by:** P_010 (Intent Redirect), TAINT_001 (Data-flow), RN_001 (React Native)

**Approach:**
1. Parse Java source with `tree-sitter-java` into AST
2. Walk AST nodes (method declarations, statements, expressions)
3. Track variable assignments within method scope
4. Match source/sink patterns on tree nodes
5. Check for sanitizers between source and sink

**Example (P_010 detecting Intent Redirect):**

```python
# Parse Java file into AST
parser = Parser()
parser.set_language(Language(tree_sitter_java.language(), "java"))
tree = parser.parse(java_source.encode())

# Walk method bodies
for method in methods:
    tainted_vars = set()  # Variables holding attacker-controlled Intents
    
    # Find taint sources (getIntent().getParcelableExtra())
    for node in walk_method_body(method):
        if node.type == "method_invocation":
            if matches_intent_extra_getter(node):
                # Track the variable this is assigned to
                assigned_var = find_assignment_target(node)
                tainted_vars.add(assigned_var)
    
    # Find sinks (startActivity with tainted Intent)
    for node in walk_method_body(method):
        if node.type == "method_invocation":
            method_name = extract_method_name(node)
            if method_name in DISPATCH_SINKS:  # startActivity, sendBroadcast
                arg = node.child_by_field_name("arguments").children[0]
                arg_name = extract_identifier(arg)
                
                if arg_name in tainted_vars:
                    # Check if sanitized (setPackage called on same var)
                    if not has_sanitizer_between(assigned_var, node):
                        emit_finding(
                            severity=Severity.HIGH,
                            evidence={
                                "source": "getParcelableExtra",
                                "sink": method_name,
                                "tainted_var": arg_name,
                                "line": node.start_point[0]
                            }
                        )
```

**Strengths:**
- Understands code structure (variables, assignments, calls)
- Can track data-flow within a method
- Detects patterns regex cannot (e.g., assignment chains)

**Weaknesses:**
- Requires parseable source (JADX failures break agent)
- No inter-procedural analysis (can't follow calls across methods)
- Slower than regex (~50ms per file)

### 3.3 Semgrep Rule Engine

**Used by:** SG_001 (18 YAML rules)

**Approach:**
1. Invoke `semgrep` CLI as subprocess
2. Point it at decompiled Java directory
3. Pass custom rule directory (`sentinel/agents/semgrep/rules/`)
4. Parse JSON output
5. Convert semgrep results to SENTINEL findings

**Example Rule (webview-javascript-interface-exposure.yaml):**

```yaml
rules:
  - id: webview-javascript-interface-exposure
    languages: [java]
    message: WebView with addJavascriptInterface exposes Android API to JS
    severity: ERROR
    metadata:
      sentinel_severity: HIGH
      sentinel_confidence: 0.85
      sentinel_vuln_class: JavaScript Interface Exposure
      cwe: CWE-749
      owasp_masvs: MSTG-PLATFORM-7
    patterns:
      - pattern-either:
          - pattern: |
              $WEBVIEW.addJavascriptInterface($OBJ, ...)
          - pattern: |
              addJavascriptInterface($OBJ, ...)
      - pattern-not-inside: |
          if ($WEBVIEW.getSettings().getJavaScriptEnabled() == false) {
            ...
          }
```

**Execution:**
```bash
semgrep \
  --config sentinel/agents/semgrep/rules/ \
  --json \
  --quiet \
  --metrics=off \
  workspace/<session_id>/sources/
```

**Output Parsing:**
```python
async def analyze(self) -> list[Finding]:
    raw_json = self._run_semgrep(decompiled_dir)
    data = json.loads(raw_json)
    
    findings = []
    for result in data.get("results", []):
        findings.append(self._result_to_finding(result))
    
    return findings

def _result_to_finding(self, result: dict) -> Finding:
    metadata = result["extra"]["metadata"]
    
    return self._make_finding(
        vuln_class=metadata["sentinel_vuln_class"],
        severity=self._severity_for(metadata),
        confidence=float(metadata.get("sentinel_confidence", 0.65)),
        evidence={
            "file": result["path"],
            "line": result["start"]["line"],
            "matched_lines": result["extra"]["lines"],
            "semgrep_rule_id": result["check_id"],
            "cwe": metadata.get("cwe"),
            "owasp_masvs": metadata.get("owasp_masvs")
        }
    )
```

**Strengths:**
- Declarative rules (contributors add coverage without Python)
- Battle-tested AST engine (handles Java syntax edge cases)
- Fast (parallelized internally)
- Community rule ecosystem (can import external rule packs)

**Weaknesses:**
- External dependency (crashes if `semgrep` not on PATH)
- 300s timeout (large APKs can hit limit)
- No custom sanitizer logic (rule must match exact pattern)

### 3.4 Bytecode String Extraction

**Used by:** A_004 (Hardcoded Secrets via Androguard)

**Approach:**
1. Query Androguard's `get_all_strings()` on DEX bytecode
2. Apply same regex patterns as file-based scanning
3. Deduplicate by string value (DEX interns identical strings)

**Why This Matters:**
- **JADX can fail** on obfuscated/malformed APKs (timeout, OOM, parse error)
- **Androguard always works** - reads raw DEX, extracts strings in seconds
- **Secrets are still findable** even when source code isn't decompilable

**Example:**

```python
def _scan_androguard_strings(self, hits: dict):
    androguard = self._context.sources.get("androguard")
    all_strings = androguard.get_all_strings()  # Returns list[str]
    
    logger.info("[A_004] Scanning %d bytecode strings", len(all_strings))
    
    for s in all_strings:
        for provider, pattern, severity, confidence in DETECTORS:
            match = pattern.search(s)
            if match:
                matched = match.group(0)
                
                # Skip test/placeholder strings
                if any(hint in s.lower() for hint in FALSE_POSITIVE_HINTS):
                    continue
                
                hits[provider].append({
                    "value": matched,
                    "file": "(extracted from DEX bytecode)",
                    "context": s[:200],
                    "source": "androguard"
                })
```

**Real-world Impact:**
- Sprint 7.6.5 tested on 91MB obfuscated APK
- JADX: timeout after 10 minutes
- Androguard: extracted strings in 25 seconds
- A_004: still found hardcoded AWS key via bytecode scan

**Strengths:**
- Works on ANY APK (obfuscated, malformed, huge)
- Fast (seconds, not minutes)
- Authoritative (reads actual DEX bytecode)

**Weaknesses:**
- No file paths (can't tell which class contained the string)
- No usage context (can't see if key was actually used)
- String de-duplication loses duplicate-key info

### 3.5 Manifest Structure Analysis

**Used by:** META_002 (Debuggable), P_005 (Excessive Permissions), STG_009 (Backup Rules)

**Approach:**
1. Read structured manifest dict (pre-parsed by `ManifestParser`)
2. Check flags, permissions, component declarations
3. Cross-reference against security best practices
4. Emit findings for misconfigurations

**Example (META_002 Debuggable Flag):**

```python
async def analyze(self) -> list[Finding]:
    manifest = self._context.manifest
    
    debuggable = manifest.get("application", {}).get("debuggable")
    
    if debuggable is True:  # Explicitly set to true
        return [self._make_finding(
            vuln_class="Debuggable Application",
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "package": manifest.get("package"),
                "flag": "android:debuggable=\"true\"",
                "vector": (
                    "Any app on the device can attach a debugger, read "
                    "memory, set breakpoints, and dump secrets. On "
                    "rooted devices this enables trivial code injection."
                )
            },
            recommendation=(
                "Remove android:debuggable=\"true\" from "
                "AndroidManifest.xml. Build tools set this automatically "
                "for debug builds; production APKs must NOT be debuggable."
            )
        )]
    
    return []
```

**Example (P_005 Excessive Permissions):**

```python
PERMISSION_SEVERITY = {
    "android.permission.READ_SMS": Severity.HIGH,
    "android.permission.CAMERA": Severity.MEDIUM,
    "android.permission.INTERNET": Severity.INFO,
    # ... 50+ permissions mapped
}

async def analyze(self) -> list[Finding]:
    findings = []
    manifest = self._context.manifest
    permissions = manifest.get("uses-permission", [])
    
    for perm in permissions:
        if perm in PERMISSION_SEVERITY:
            findings.append(self._make_finding(
                vuln_class="Excessive Permission",
                severity=PERMISSION_SEVERITY[perm],
                confidence=0.70,
                evidence={
                    "permission": perm,
                    "justification": (
                        "This permission grants access to sensitive user "
                        "data. Ensure the app genuinely requires it."
                    )
                }
            ))
    
    return findings
```

**Strengths:**
- Fast (manifest is already parsed, just dict lookups)
- High confidence (manifest is authoritative)
- Easy to add new checks (just dict key checks)

**Weaknesses:**
- Only catches configuration issues (not code bugs)
- Can't verify if permission is actually used
- Many INFO/LOW findings (noisy without context)

### 3.6 Cross-Platform Bundle Inspection

**Used by:** RN_001 (React Native), FL_001 (Flutter)

**Approach:**
1. Detect platform markers (native libs, bundle files)
2. Extract JS bundle or native lib
3. Apply platform-specific regex patterns
4. Emit findings with lower confidence (experimental)

**Example (RN_001 React Native):**

```python
async def is_applicable(self) -> bool:
    # Check for RN native libs
    for lib_hint in ["libreactnativejni.so", "libhermes.so"]:
        if any(lib_hint in str(p) for p in self._context.native_libs):
            return True
    
    # Check for JS bundle
    bundle_path = self._find_bundle()
    return bundle_path is not None

async def analyze(self) -> list[Finding]:
    bundle_path = self._find_bundle()
    
    # Check for Hermes bytecode (can't scan)
    magic = bundle_path.read_bytes()[:4]
    if magic == b"\x03\xBC\x1F\xC6":  # Hermes magic
        return [self._hermes_finding()]  # INFO: can't analyze
    
    # Scan plain JS bundle
    js_code = bundle_path.read_text(errors="replace")
    
    findings = []
    findings.extend(self._scan_async_storage(js_code))
    findings.extend(self._scan_cleartext(js_code))
    findings.extend(self._scan_secrets(js_code))
    findings.extend(self._scan_webview(js_code))
    findings.extend(self._scan_dangerous_html(js_code))
    
    return findings
```

**Hermes Detection:**
```python
def _hermes_finding(self) -> Finding:
    return self._make_finding(
        vuln_class="React Native Analysis Limitation",
        severity=Severity.INFO,
        confidence=1.0,
        evidence={
            "message": (
                "Bundle is Hermes-compiled bytecode. JS source not "
                "available for static analysis. Future integration with "
                "hermes-dec or hbctool would enable inspection."
            )
        }
    )
```

**Strengths:**
- Covers React Native / Flutter (growing segment of Android apps)
- Catches JS-specific issues (AsyncStorage, fetch)
- No JVM/Dalvik knowledge required

**Weaknesses:**
- Hermes bytecode blocks analysis (50%+ of RN apps as of 2024)
- Flutter analysis is string-level only (no Dart parser yet)
- Lower confidence (0.6-0.7) than Java agents

---

## 4. DETAILED AGENT ANALYSIS

### 4.1 N_002 - Cleartext Traffic Agent

**Detection Method:** Regex + Manifest Flag

**What it finds:** Apps configured to allow HTTP traffic or containing hardcoded `http://` URLs.

**Step-by-step:**

1. **Check manifest flag:**
```python
manifest_flag = manifest.get("uses_cleartext_traffic") == True
```

2. **Scan Java source for http:// URLs:**
```python
_HTTP_URL_RE = re.compile(
    r'http://(?!'  # Match http:// but exclude:
    r'(?:'
    r'localhost|127\.0\.0\.1|10\.0\.2\.2|'  # Local addresses
    r'schemas\.android\.com|'                # XML namespaces
    r'www\.w3\.org|java\.sun\.com'          # Schema definitions
    r')'
    r')'
    r'[a-zA-Z0-9./_\-:?=&%~#]+',
    re.IGNORECASE
)

for java_file in decompiled_dir.rglob("*.java"):
    text = java_file.read_text()
    for match in _HTTP_URL_RE.finditer(text):
        url = match.group(0)
        urls.add(url)
```

3. **Severity scaling:**
```python
if manifest_flag and url_count > 0:
    severity = Severity.HIGH      # Both signals = strong finding
    confidence = 0.90
elif manifest_flag:
    severity = Severity.MEDIUM    # Config issue only
    confidence = 0.80
else:
    severity = Severity.LOW       # Code only, might be test URLs
    confidence = 0.70
```

**Example Finding:**
```json
{
  "agent_id": "N_002",
  "vuln_class": "Cleartext Traffic",
  "severity": "High",
  "confidence": 0.9,
  "evidence": {
    "manifest_uses_cleartext_traffic": true,
    "http_urls_count": 12,
    "http_urls_sample": [
      {
        "url": "http://api.example.com/users",
        "locations": ["com/example/api/ApiClient.java"]
      }
    ]
  },
  "recommendation": "Remove android:usesCleartextTraffic and migrate to HTTPS"
}
```

**Performance:** ~200ms (manifest check instant, regex scan 150ms for 500 files)

---

### 4.2 C_007 - Weak Cryptography Agent

**Detection Method:** Regex on Crypto API calls

**What it finds:** Use of broken/deprecated crypto primitives (DES, RC4, MD5, SHA-1, AES-ECB).

**Detector Table:**
```python
_DETECTORS = [
    ("DES", re.compile(r'Cipher\.getInstance\s*\(\s*"DES'), 
     Severity.CRITICAL, 0.90),
    
    ("RC4", re.compile(r'Cipher\.getInstance\s*\(\s*"(?:RC4|ARCFOUR)'), 
     Severity.CRITICAL, 0.90),
    
    ("AES-ECB", re.compile(r'Cipher\.getInstance\s*\(\s*"AES/ECB'), 
     Severity.HIGH, 0.85),
    
    ("MD5", re.compile(r'MessageDigest\.getInstance\s*\(\s*"MD5"'), 
     Severity.HIGH, 0.80),
    
    ("SHA-1", re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"'), 
     Severity.MEDIUM, 0.75),
]
```

**Scanning Logic:**
```python
hits_by_primitive: dict[str, list] = {}

for java_file in decompiled_dir.rglob("*.java"):
    text = java_file.read_text()
    
    for primitive, pattern, severity, confidence in _DETECTORS:
        for match in pattern.finditer(text):
            # Extract surrounding line for context
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start:line_end].strip()
            
            hits_by_primitive.setdefault(primitive, []).append({
                "file": str(java_file.relative_to(decompiled_dir)),
                "context": line[:200],
                "matched": match.group(0)
            })
```

**One Finding Per Primitive:**
```python
# If DES found in 5 files, emit ONE finding with all 5 locations
for primitive, instances in hits_by_primitive.items():
    severity, confidence = primitive_metadata[primitive]
    
    findings.append(make_finding(
        vuln_class="Weak Cryptography",
        severity=severity,
        confidence=confidence,
        evidence={
            "primitive": primitive,
            "match_count": len(instances),
            "hits": instances[:10]  # Cap at 10 samples
        }
    ))
```

**Example Match:**
```java
// File: com/example/crypto/EncryptionUtil.java
// Line: Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
//       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//       Matched by DES regex
```

**Performance:** ~800ms (scans 500 files, 5 regex passes each)

---

### 4.3 A_004 - Hardcoded Secrets Agent

**Detection Method:** Regex (file scan) + Bytecode String Extraction (Androguard)

**What it finds:** Embedded API keys, tokens, credentials from 12+ providers.

**Multi-Source Strategy:**

```python
async def analyze(self) -> list[Finding]:
    hits: dict[str, list] = {}
    
    # Path 1: JADX-decompiled Java
    if ctx.decompiled_dir:
        self._scan_directory(ctx.decompiled_dir, hits, ".java", "java")
    
    # Path 2: apktool resources (XML)
    if ctx.resources_dir:
        self._scan_directory(ctx.resources_dir, hits, ".xml", "resources")
    
    # Path 3: Androguard bytecode strings (ALWAYS works)
    if ctx.has_androguard():
        self._scan_androguard_strings(hits)
    
    # Deduplicate by value (same key in Java + bytecode = one finding)
    for provider in hits:
        hits[provider] = self._dedupe_by_value(hits[provider])
    
    return [self._make_finding_per_provider(p, instances) 
            for p, instances in hits.items()]
```

**Secret Patterns:**
```python
DETECTORS = [
    ("AWS Access Key ID", 
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     Severity.CRITICAL, 0.95),
    
    ("Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.HIGH, 0.85),
    
    ("Stripe Live Secret Key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
     Severity.CRITICAL, 0.95),
    
    ("GitHub Token",
     re.compile(r"\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{36,}\b"),
     Severity.CRITICAL, 0.95),
    
    ("PEM Private Key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
     Severity.CRITICAL, 0.95),
]
```

**False Positive Filter:**
```python
FALSE_POSITIVE_HINTS = (
    "test", "example", "sample", "fake", "dummy", 
    "placeholder", "your_", "xxxx", "0000000000"
)

# If matched line contains any hint, skip
if any(hint in line.lower() for hint in FALSE_POSITIVE_HINTS):
    continue
```

**Androguard Bytecode Scan (Sprint 7.6.5):**
```python
def _scan_androguard_strings(self, hits: dict):
    androguard = self._context.sources["androguard"]
    all_strings = androguard.get_all_strings()  # 10k-50k strings typical
    
    for s in all_strings:
        if len(s) < 8:
            continue  # Too short to hold secrets
        
        for provider, pattern, severity, confidence in DETECTORS:
            match = pattern.search(s)
            if match and not is_false_positive(s):
                hits[provider].append({
                    "value": match.group(0),
                    "file": "(extracted from DEX bytecode)",
                    "context": s[:200],
                    "source": "androguard"
                })
```

**Deduplication:**
```python
# Same AWS key found in:
#   1. Foo.java line 42
#   2. Bar.java line 99
#   3. DEX string table
# → ONE finding with all 3 sources listed

def _dedupe_by_value(instances):
    by_value = {}
    for inst in instances:
        by_value.setdefault(inst["value"], []).append(inst)
    
    # Prefer Java/resource hits over bytecode (have file paths)
    deduped = []
    for value, group in by_value.items():
        group.sort(key=lambda x: SOURCE_PRIORITY[x["source"]])
        best = group[0]
        
        # Annotate if found in multiple sources
        if len(group) > 1:
            best["source"] = "+".join(sorted({g["source"] for g in group}))
        
        deduped.append(best)
    
    return deduped
```

**Performance:** 
- Java scan: ~1.2s (500 files)
- Androguard scan: ~0.3s (25,000 strings)
- Total: ~1.5s

---

### 4.4 SG_001 - Semgrep AST Agent

**Detection Method:** External Semgrep CLI with custom YAML rules

**What it finds:** 18 rule-defined patterns (WebView issues, crypto, SQL injection, command injection).

**Execution Flow:**

```python
async def analyze(self) -> list[Finding]:
    # 1. Check semgrep binary exists
    if shutil.which("semgrep") is None:
        logger.warning("semgrep not on PATH, returning 0 findings")
        return []
    
    # 2. Run semgrep subprocess
    raw_json = self._run_semgrep(decompiled_dir)
    
    # 3. Parse JSON output
    data = json.loads(raw_json)
    results = data.get("results", [])
    
    # 4. Convert to SENTINEL findings
    return [self._result_to_finding(r) for r in results]
```

**Subprocess Invocation:**
```python
def _run_semgrep(self, source_dir: Path) -> str:
    cmd = [
        "semgrep",
        "--config", str(self.RULES_DIR),  # sentinel/agents/semgrep/rules/
        "--json",
        "--quiet",
        "--metrics=off",
        "--no-git-ignore",
        str(source_dir)
    ]
    
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minute cap
        check=False
    )
    
    # Semgrep exit codes: 0 = no findings, 1 = findings, >1 = error
    if proc.returncode > 1:
        logger.warning("semgrep failed: %s", proc.stderr)
        return ""
    
    return proc.stdout
```

**Example Rule (webview-javascript-interface-exposure.yaml):**
```yaml
rules:
  - id: webview-javascript-interface-exposure
    languages: [java]
    message: >
      WebView.addJavascriptInterface exposes Java methods to JavaScript.
      If the WebView loads untrusted content, attackers can invoke exposed
      methods to read files, access credentials, or execute code.
    
    severity: ERROR
    
    metadata:
      sentinel_severity: HIGH
      sentinel_confidence: 0.85
      sentinel_vuln_class: JavaScript Interface Exposure
      cwe: CWE-749
      owasp_masvs: MSTG-PLATFORM-7
      references:
        - https://support.google.com/faqs/answer/9095419
    
    patterns:
      - pattern-either:
          # Direct call on WebView instance
          - pattern: $WEBVIEW.addJavascriptInterface($OBJ, ...)
          
          # Static import call
          - pattern: addJavascriptInterface($OBJ, ...)
      
      # Don't match if inside a JS-disabled guard
      - pattern-not-inside: |
          if (!$WEBVIEW.getSettings().getJavaScriptEnabled()) {
            ...
          }
```

**Result Parsing:**
```python
def _result_to_finding(self, result: dict) -> Finding:
    metadata = result["extra"]["metadata"]
    
    # Map semgrep severity to SENTINEL Severity enum
    sentinel_sev = metadata.get("sentinel_severity", "MEDIUM")
    severity = SEVERITY_MAP[sentinel_sev]
    
    # Extract file location
    rel_path = Path(result["path"]).relative_to(source_dir)
    line = result["start"]["line"]
    
    # Matched code
    matched_lines = result["extra"]["lines"][:1000]
    
    return self._make_finding(
        vuln_class=metadata["sentinel_vuln_class"],
        severity=severity,
        confidence=float(metadata.get("sentinel_confidence", 0.65)),
        evidence={
            "file": str(rel_path),
            "line": line,
            "matched_lines": matched_lines,
            "semgrep_rule_id": result["check_id"].rsplit(".", 1)[-1],
            "cwe": metadata.get("cwe"),
            "owasp_masvs": metadata.get("owasp_masvs"),
            "message": result["extra"]["message"]
        }
    )
```

**18 Shipped Rules:**
1. `webview-javascript-interface-exposure` - JS bridge risks
2. `webview-allow-file-access` - File URI access
3. `webview-universal-file-access` - XHR to file://
4. `webview-javascript-enabled` - JS enabled check
5. `crypto-des` - DES cipher usage
6. `crypto-ecb-mode` - ECB mode detection
7. `crypto-md5` - MD5 hash usage
8. `crypto-sha1` - SHA-1 usage
9. `crypto-insecure-random` - java.util.Random for crypto
10. `tls-hostname-verifier-allow-all` - ALLOW_ALL verifier
11. `tls-trust-all-certs` - Trust-all TrustManager
12. `tls-cleartext-http-url` - Hardcoded http:// URLs
13. `storage-mode-world-readable` - MODE_WORLD_READABLE
14. `storage-mode-world-writeable` - MODE_WORLD_WRITEABLE
15. `storage-external-storage` - External storage usage
16. `sql-raw-query-concatenation` - SQL injection via concat
17. `command-exec-concatenation` - Command injection
18. `pending-intent-mutable` - Mutable PendingIntent

**Performance:** ~15s (Semgrep's internal parallelization)

---

### 4.5 TAINT_001 - Data-Flow Taint Tracker

**Detection Method:** Tree-sitter AST + Backward Slicing + Inter-Procedural Analysis

**What it finds:** Data flows from untrusted sources to dangerous sinks (SQL injection, XSS, path traversal).

**Algorithm Overview:**

```
For each Java file:
  1. Parse with tree-sitter-java → AST
  2. Build method index (class.method → node)
  3. For each method:
     a. Build def-use map (var → assignment nodes)
     b. Find SINK invocations (rawQuery, loadUrl, etc.)
     c. For each sink argument:
        - Backward slice through def-use chain
        - Check if reaches SOURCE (getIntent, WebView.getUrl)
        - Check if SANITIZER in path (parseInt, setPackage)
        - If tainted + not sanitized → record flow
     d. If argument is method parameter → IPA hop
  4. IPA: Find callers of method, recurse on their arguments
  5. Emit findings with full source→sink trace
```

**Source/Sink/Sanitizer Config (sentinel/agents/taint/taint_config.py):**

```python
SOURCES = [
    SourceSpec(
        name="Intent Extra",
        pattern=r"getIntent\(\)\.get\w+Extra",
        description="Attacker-controlled via deep link or broadcast"
    ),
    SourceSpec(
        name="WebView URL",
        pattern=r"WebView\.getUrl",
        description="User-navigated URL, may contain攻击 payload"
    ),
    SourceSpec(
        name="Clipboard",
        pattern=r"ClipboardManager\.getPrimaryClip",
        description="Cross-app data, untrusted"
    ),
]

SINKS = [
    SinkSpec(
        name="SQL rawQuery",
        pattern=r"\.rawQuery\(",
        vuln_class="SQL Injection",
        severity=Severity.HIGH
    ),
    SinkSpec(
        name="WebView loadUrl",
        pattern=r"\.loadUrl\(",
        vuln_class="WebView XSS",
        severity=Severity.HIGH
    ),
    SinkSpec(
        name="Runtime.exec",
        pattern=r"Runtime\.getRuntime\(\)\.exec",
        vuln_class="Command Injection",
        severity=Severity.CRITICAL
    ),
]

SANITIZERS = [
    SanitizerSpec(
        name="Integer.parseInt",
        pattern=r"Integer\.parseInt",
        applies_to_classes=["SQL Injection"]  # Numeric cast kills SQL injection
    ),
    SanitizerSpec(
        name="Intent.setPackage",
        pattern=r"\.setPackage\(",
        applies_to_classes=["Intent Redirect"]
    ),
]
```

**Backward Slicing Example:**

```java
// Method body
public void doQuery(String userId) {
    String query = "SELECT * FROM users WHERE id=" + userId;  // ← sink
    Cursor c = db.rawQuery(query, null);
}

// Backward slice from 'query' argument to rawQuery:
// 1. 'query' is local variable
// 2. Defined by: query = "..." + userId
// 3. 'userId' is method parameter
// 4. Check callers of doQuery(...)
```

**Inter-Procedural Analysis (IPA):**

```python
def _follow_parameter(
    self,
    param_name: str,
    enclosing_method: str,
    depth: int
) -> list[TraceHop]:
    if depth >= MAX_IPA_DEPTH:  # Default: 3 hops
        return []
    
    # Find all call sites of enclosing_method in the project
    callers = self._project_index.callers_of(enclosing_method)
    
    traces = []
    for caller_method, call_node in callers:
        # Get argument at same positional index
        arg_node = self._get_argument_at_index(call_node, param_index)
        
        # Recurse: slice backward from that argument
        trace = self._slice_expr(arg_node, caller_method, depth + 1)
        if trace:
            traces.append(trace)
    
    return traces
```

**Confidence Scaling:**

```python
def confidence_for_depth(hops: int) -> float:
    """Deeper call chains = lower confidence"""
    return {
        0: 0.90,  # Source and sink in same method
        1: 0.80,  # One method call between
        2: 0.70,  # Two hops
        3: 0.60,  # Three hops (max)
    }.get(hops, 0.50)
```

**Sanitizer Check:**

```python
def _is_sanitized(self, flow: TaintFlow) -> bool:
    """Check if any hop in trace matches a sanitizer"""
    for hop in flow.hops:
        for sanitizer in SANITIZERS:
            if sanitizer.pattern.search(hop.code):
                # Check if sanitizer applies to this vuln class
                if flow.sink.vuln_class in sanitizer.applies_to_classes:
                    logger.debug(
                        "Flow sanitized by %s at %s:%d",
                        sanitizer.name, hop.file, hop.line
                    )
                    return True
    return False
```

**Example Finding:**

```json
{
  "agent_id": "TAINT_001",
  "vuln_class": "SQL Injection",
  "severity": "High",
  "confidence": 0.8,
  "evidence": {
    "source": "Intent Extra (getStringExtra)",
    "sink": "SQLiteDatabase.rawQuery",
    "hops": 1,
    "trace": [
      {
        "kind": "source",
        "file": "com/example/MainActivity.java",
        "line": 42,
        "code": "String userId = getIntent().getStringExtra(\"user_id\")",
        "label": "Intent Extra"
      },
      {
        "kind": "call",
        "file": "com/example/MainActivity.java",
        "line": 45,
        "code": "queryUser(userId)",
        "label": "parameter passed"
      },
      {
        "kind": "sink",
        "file": "com/example/DatabaseHelper.java",
        "line": 88,
        "code": "db.rawQuery(\"SELECT * FROM users WHERE id=\" + userId, null)",
        "label": "SQL rawQuery"
      }
    ]
  }
}
```

**Performance:** 
- Parsing: ~50ms per file
- Per-method analysis: ~10-100ms (depends on complexity)
- Per-file timeout: 8s (skips runaway methods)
- Total: ~12s for 500-file APK

---

### 4.6 SCA_001 - Supply Chain CVE Scanner

**Detection Method:** ZIP extraction + pom.properties parsing + OSV.dev SQLite query

**What it finds:** Vulnerable third-party libraries (Maven coordinates matched against CVE database).

**Three-Tier Detection:**

**Tier 1: pom.properties (Confidence 0.95)**
```python
# Extract from APK
with zipfile.ZipFile(apk_path) as z:
    for name in z.namelist():
        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
            # e.g. META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties
            props = z.read(name).decode()
            
            # Parse properties
            coord = parse_pom_properties(props)
            # → {"groupId": "com.squareup.okhttp3", 
            #    "artifactId": "okhttp",
            #    "version": "3.12.0"}
```

**Tier 2: Version Markers (Confidence 0.80)**
```python
# Scan decompiled Java for version strings
_VERSION_MARKERS = [
    ("com.squareup.okhttp3", "okhttp", 
     re.compile(r"okhttp/([0-9]+\.[0-9]+\.[0-9]+)")),
    
    ("com.google.code.gson", "gson",
     re.compile(r"gson[\s_/-]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"))
]

for java_file in decompiled_dir.rglob("*.java"):
    text = java_file.read_text()
    for groupId, artifactId, pattern in _VERSION_MARKERS:
        match = pattern.search(text)
        if match:
            version = match.group(1)
            detected[(groupId, artifactId)] = version
```

**Tier 3: Classpath Presence (Confidence 0.40)**
```python
# Check if package path exists in DEX classes
_CLASSPATH_FINGERPRINTS = [
    ("com.squareup.okhttp3", "okhttp", "com/squareup/okhttp3/"),
    ("com.google.code.gson", "gson", "com/google/gson/"),
]

androguard = ctx.sources["androguard"]
all_classes = androguard.get_all_classes()

for groupId, artifactId, path_prefix in _CLASSPATH_FINGERPRINTS:
    if any(path_prefix in cls for cls in all_classes):
        detected[(groupId, artifactId)] = "UNKNOWN"  # No version info
```

**OSV.dev Database Query:**

```python
# scripts/fetch_osv_db.py builds offline SQLite from OSV.dev JSONL dumps
# Schema:
#   CREATE TABLE advisories (
#       id TEXT PRIMARY KEY,       -- CVE-2021-1234
#       package_name TEXT,         -- com.squareup.okhttp3:okhttp
#       affected_ranges TEXT,      -- JSON list of version ranges
#       fixed_version TEXT,        -- First patched version
#       severity TEXT,             -- HIGH, CRITICAL, etc.
#       cvss_score REAL,
#       summary TEXT
#   )

def _match_cves(self, coord: DetectedLibrary) -> list[dict]:
    package_name = f"{coord.groupId}:{coord.artifactId}"
    
    cursor = db.execute(
        "SELECT * FROM advisories WHERE package_name = ?",
        (package_name,)
    )
    
    matches = []
    for row in cursor:
        # Parse affected_ranges JSON
        ranges = json.loads(row["affected_ranges"])
        
        # Check if detected version is vulnerable
        if self._version_in_any_range(coord.version, ranges):
            # And below fixed version
            if self._version_below(coord.version, row["fixed_version"]):
                matches.append({
                    "cve_id": row["id"],
                    "severity": row["severity"],
                    "cvss": row["cvss_score"],
                    "summary": row["summary"],
                    "fixed_in": row["fixed_version"]
                })
    
    return matches
```

**Semver Matching:**
```python
from packaging.version import Version

def _version_in_range(self, ver: str, range_spec: dict) -> bool:
    """
    range_spec: {
        "type": "SEMVER",
        "introduced": "3.0.0",
        "fixed": "3.12.13"
    }
    """
    try:
        v = Version(ver)
        introduced = Version(range_spec["introduced"])
        fixed = Version(range_spec.get("fixed", "999.0.0"))
        
        return introduced <= v < fixed
    except InvalidVersion:
        return False  # Malformed version, skip
```

**Example Finding:**

```json
{
  "agent_id": "SCA_001",
  "vuln_class": "Vulnerable Dependency",
  "severity": "High",
  "confidence": 0.95,
  "evidence": {
    "library": "com.squareup.okhttp3:okhttp",
    "detected_version": "3.12.0",
    "detection_tier": "pom.properties",
    "cves": [
      {
        "id": "CVE-2021-0341",
        "cvss": 7.5,
        "summary": "OkHttp DNS rebinding vulnerability",
        "fixed_in": "3.12.13"
      }
    ],
    "recommendation": "Upgrade to okhttp 3.12.13 or later"
  }
}
```

**Performance:** ~3s (ZIP scan 1s, DB queries 2s)

---

### 4.7 P_010 - Intent Redirect Agent

**Detection Method:** Tree-sitter AST intra-procedural taint tracking

**What it finds:** Intent objects read from untrusted sources then dispatched without sanitization (CWE-926 confused deputy).

**Intra-Method Taint Tracking:**

```python
# Parse method body AST
for method in methods:
    tainted_vars = set()  # Variables holding attacker-controlled Intents
    
    # Phase 1: Find taint sources
    for node in walk_method_body(method):
        if is_intent_extra_getter(node):
            # e.g. getIntent().getParcelableExtra("redirect_intent")
            assigned_var = find_assignment_target(node)
            tainted_vars.add(assigned_var)
    
    # Phase 2: Find sinks
    for node in walk_method_body(method):
        if is_dispatch_sink(node):  # startActivity, sendBroadcast, etc.
            arg = get_first_argument(node)
            if arg in tainted_vars:
                # Phase 3: Check for sanitizers between source and sink
                if has_sanitizer(assigned_var, node, method):
                    continue  # Flow is safe
                
                emit_finding(
                    severity=Severity.HIGH,
                    evidence={
                        "tainted_var": arg,
                        "source": "getParcelableExtra",
                        "sink": extract_method_name(node)
                    }
                )
```

**Taint Source Detection:**
```python
INTENT_EXTRA_GETTERS = {
    "getParcelableExtra", "getParcelableArrayExtra",
    "getBundleExtra", "getSerializableExtra"
}

def is_intent_extra_getter(node) -> bool:
    """
    Matches:
      - getIntent().getParcelableExtra("key")
      - intent.getBundleExtra("key")
      - bundle.getParcelable("key")
    """
    if node.type != "method_invocation":
        return False
    
    method_name = extract_method_name(node)
    if method_name not in INTENT_EXTRA_GETTERS:
        return False
    
    # Check receiver is Intent-shaped
    receiver = node.child_by_field_name("object")
    receiver_text = source_text(receiver)
    
    return any(hint in receiver_text for hint in [
        "getIntent()", "intent", "this.intent", "mIntent"
    ])
```

**Sanitizer Detection:**
```python
SANITIZER_METHODS = {
    "setPackage", "setComponent", "setClassName",
    "setClass", "setComponentName", "setSelector"
}

def has_sanitizer(var_name: str, sink_node, method_node) -> bool:
    """Check if var.setPackage() called between assignment and sink"""
    
    # Walk statements between variable assignment and sink
    for stmt in statements_between(var_assignment, sink_node):
        if stmt.type == "expression_statement":
            expr = stmt.child(0)
            if expr.type == "method_invocation":
                method = extract_method_name(expr)
                receiver = extract_receiver(expr)
                
                # Check if sanitizer called on our tainted variable
                if method in SANITIZER_METHODS and receiver == var_name:
                    return True
    
    return False
```

**Example Vulnerable Code:**

```java
// Vulnerable: attacker controls both Intent object and target
protected void onCreate(Bundle savedInstanceState) {
    Intent redirectIntent = getIntent().getParcelableExtra("target");
    if (redirectIntent != null) {
        startActivity(redirectIntent);  // ← CWE-926 confused deputy
    }
}

// Safe: setPackage forces recipient
protected void onCreate(Bundle savedInstanceState) {
    Intent redirectIntent = getIntent().getParcelableExtra("target");
    if (redirectIntent != null) {
        redirectIntent.setPackage(getPackageName());  // ← Sanitizer
        startActivity(redirectIntent);  // Now safe
    }
}
```

**Severity Scaling:**
```python
if has_sanitizer:
    # Not vulnerable, no finding
    pass
elif sink_method in ["startActivity", "startService"]:
    severity = Severity.HIGH
    confidence = 0.85
elif sink_method in ["sendBroadcast", "sendOrderedBroadcast"]:
    severity = Severity.CRITICAL  # Broader reach
    confidence = 0.90
```

**Performance:** ~5s (tree-sitter parsing + AST walk for 500 files)

---

## 5. CODE EXAMPLES - HOW BUGS ARE FOUND

### 5.1 Cleartext Traffic (N_002)

**Vulnerable Code:**
```xml
<!-- AndroidManifest.xml -->
<application
    android:usesCleartextTraffic="true"  ← RED FLAG
    ...>
</application>
```

```java
// ApiClient.java
public class ApiClient {
    private static final String BASE_URL = "http://api.example.com";  ← RED FLAG
    
    public void fetchUsers() {
        HttpURLConnection conn = (HttpURLConnection) 
            new URL(BASE_URL + "/users").openConnection();
        // Cleartext HTTP request
    }
}
```

**Detection:**
```python
# 1. Manifest flag detected
manifest["uses_cleartext_traffic"] == True

# 2. Regex matches http:// URL
_HTTP_URL_RE.finditer(java_text)
# → Match: "http://api.example.com"

# 3. Both signals present
severity = Severity.HIGH
confidence = 0.90
```

**Finding Output:**
```
[N_002] Cleartext Traffic - High severity (0.90 confidence)
  Evidence:
    - Manifest: android:usesCleartextTraffic="true"
    - 1 hardcoded http:// URL found in ApiClient.java
  
  Recommendation:
    Remove android:usesCleartextTraffic and migrate all URLs to HTTPS.
    Configure NetworkSecurityConfig if cleartext is absolutely required
    for specific domains.
```

---

### 5.2 Weak Crypto (C_007)

**Vulnerable Code:**
```java
// EncryptionUtil.java
public byte[] encrypt(byte[] data, String password) {
    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");  ← RED FLAG
    SecretKeySpec key = new SecretKeySpec(
        password.getBytes(), "DES"
    );
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
}
```

**Detection:**
```python
# Regex matches DES usage
pattern = re.compile(r'Cipher\.getInstance\s*\(\s*"DES')
match = pattern.search(java_text)
# → Match at line 3: Cipher.getInstance("DES/CBC/PKCS5Padding")

# Extract context
line = "Cipher cipher = Cipher.getInstance(\"DES/CBC/PKCS5Padding\");"

findings.append({
    "primitive": "DES",
    "file": "com/example/EncryptionUtil.java",
    "line": 3,
    "context": line,
    "severity": Severity.CRITICAL,
    "confidence": 0.90
})
```

**Finding Output:**
```
[C_007] Weak Cryptography - Critical severity (0.90 confidence)
  Primitive: DES
  Occurrences: 1
  
  Location:
    - com/example/EncryptionUtil.java:3
      Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
  
  Recommendation:
    Replace DES with AES-256 in GCM mode. DES has a 56-bit key space
    and is brute-forceable in hours on modern hardware.
```

---

### 5.3 Hardcoded AWS Key (A_004)

**Vulnerable Code:**
```java
// S3Manager.java
public class S3Manager {
    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";  ← RED FLAG
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    
    public void uploadFile(File file) {
        AWSCredentials credentials = new BasicAWSCredentials(AWS_KEY, AWS_SECRET);
        // ...
    }
}
```

**Detection (Two Paths):**

**Path 1: File Scan**
```python
pattern = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
match = pattern.search(java_text)
# → Match: "AKIAIOSFODNN7EXAMPLE"

# Check for false positive hints
if "test" not in line.lower() and "example" not in line.lower():
    hits["AWS Access Key ID"].append({
        "value": "AKIAIOSFODNN7EXAMPLE",
        "file": "com/example/S3Manager.java",
        "line": 3,
        "source": "java"
    })
```

**Path 2: Androguard Bytecode**
```python
# Even if JADX failed, Androguard extracts strings from DEX
all_strings = androguard.get_all_strings()
# → Contains "AKIAIOSFODNN7EXAMPLE"

for s in all_strings:
    match = pattern.search(s)
    if match:
        hits["AWS Access Key ID"].append({
            "value": match.group(0),
            "file": "(extracted from DEX bytecode)",
            "source": "androguard"
        })
```

**Finding Output:**
```
[A_004] Hardcoded Secret - Critical severity (0.95 confidence)
  Provider: AWS Access Key ID
  Sources: java+androguard
  
  Matches:
    - Redacted: AKIA...MPLE
      File: com/example/S3Manager.java
      Context: private static final String AWS_KEY = "AKIA...";
  
  Recommendation:
    Remove the hardcoded AWS key and rotate it immediately. Replace with
    runtime-fetched credential from AWS Secrets Manager or IAM role.
```

---

### 5.4 SQL Injection (TAINT_001)

**Vulnerable Code:**
```java
// MainActivity.java
public void onDeepLink(Intent intent) {
    String userId = intent.getStringExtra("user_id");  ← SOURCE
    queryUserById(userId);
}

// DatabaseHelper.java
public Cursor queryUserById(String id) {
    String query = "SELECT * FROM users WHERE id=" + id;  ← SINK
    return db.rawQuery(query, null);
}
```

**Detection (Multi-step):**

**Step 1: Find Sink**
```python
# Parse DatabaseHelper.java
# Find method: queryUserById(String id)
# Find sink: db.rawQuery(...)

sink_node = find_method_invocation("rawQuery")
sink_arg = get_first_argument(sink_node)
# → Variable: "query"
```

**Step 2: Backward Slice**
```python
# Trace 'query' back to definition
# query = "..." + id

# 'id' is method parameter
# Need to check callers (IPA)
```

**Step 3: Find Callers**
```python
# Search project for calls to queryUserById
callers = project_index.callers_of("DatabaseHelper.queryUserById")
# → Found: MainActivity.onDeepLink calls queryUserById(userId)
```

**Step 4: Trace Caller Argument**
```python
# In MainActivity.onDeepLink:
# userId comes from intent.getStringExtra("user_id")

# This matches SOURCE pattern: Intent Extra
```

**Step 5: Check Sanitizer**
```python
# No Integer.parseInt() between getStringExtra and queryUserById
# No other sanitizer matched
# → TAINTED FLOW CONFIRMED
```

**Finding Output:**
```
[TAINT_001] SQL Injection - High severity (0.80 confidence)
  Trace (2 hops):
    1. SOURCE  MainActivity.java:15
       String userId = intent.getStringExtra("user_id");
       
    2. CALL    MainActivity.java:16
       queryUserById(userId);
       
    3. SINK    DatabaseHelper.java:42
       db.rawQuery("SELECT * FROM users WHERE id=" + id, null);
  
  Recommendation:
    Use parameterized query: rawQuery("SELECT * FROM users WHERE id=?", 
    new String[]{id}). Never concatenate user input into SQL.
```

---

### 5.5 Intent Redirect (P_010)

**Vulnerable Code:**
```java
// DeepLinkActivity.java
protected void onCreate(Bundle savedInstanceState) {
    Intent redirectIntent = getIntent()
        .getParcelableExtra("redirect_target");  ← SOURCE
    
    if (redirectIntent != null) {
        startActivity(redirectIntent);  ← SINK (unsanitized)
    }
}
```

**Detection:**

**Step 1: Parse Method**
```python
tree = parser.parse(java_source)
method_node = find_method("onCreate")
```

**Step 2: Find Taint Source**
```python
for node in walk_method_body(method_node):
    if is_method_invocation(node, "getParcelableExtra"):
        assigned_var = find_assignment_target(node)
        # → "redirectIntent"
        tainted_vars.add("redirectIntent")
```

**Step 3: Find Sink**
```python
for node in walk_method_body(method_node):
    if is_method_invocation(node, "startActivity"):
        arg = get_first_argument(node)
        # → "redirectIntent"
        if arg in tainted_vars:
            # VULNERABLE!
```

**Step 4: Check Sanitizer**
```python
# Walk statements between assignment and startActivity
for stmt in statements_between(assignment_node, sink_node):
    if is_method_invocation(stmt, "setPackage"):
        # Sanitizer found, flow is safe
        return []

# No sanitizer found
emit_finding()
```

**Finding Output:**
```
[P_010] Intent Redirect (CWE-926) - High severity (0.85 confidence)
  File: com/example/DeepLinkActivity.java
  
  Vulnerable Flow:
    Line 5: Intent redirectIntent = getIntent().getParcelableExtra(...)
    Line 8: startActivity(redirectIntent)  // Unsanitized dispatch
  
  Attack:
    Attacker sends Intent with malicious redirect_target extra pointing
    to a signature-protected internal Activity. App's UID is used to
    launch it, bypassing permission check.
  
  Recommendation:
    Call redirectIntent.setPackage(getPackageName()) before startActivity
    to force the Intent to stay within your app's boundaries.
```

---

## 6. PERFORMANCE CHARACTERISTICS

### 6.1 Per-Agent Timing (InsecureBankv2.apk benchmark)

| Agent | Time | Files Scanned | Technique |
|-------|------|---------------|-----------|
| N_002 | 0.2s | 487 | Regex (HTTP URLs) |
| C_007 | 0.8s | 487 | Regex (7 patterns) |
| A_004 | 1.2s | 487 Java + 18k strings | Regex + Androguard |
| SG_001 | 15s | 487 | Semgrep subprocess |
| TAINT_001 | 12s | 487 | Tree-sitter AST |
| SCA_001 | 3s | 1 APK ZIP | pom.properties + DB query |
| P_010 | 5s | 487 | Tree-sitter AST |
| RN_001 | 0.1s | 1 bundle | Regex on JS |
| META_002 | <0.01s | - | Manifest dict lookup |

**Total Phase 2 Duration:** ~20s (agents run in parallel, not serially)

### 6.2 Scaling Characteristics

**File Count Impact:**

| APK Size | Java Files | Phase 2 Duration |
|----------|------------|------------------|
| 5 MB | 200 | ~8s |
| 15 MB | 500 | ~20s |
| 50 MB | 1500 | ~45s |
| 100 MB | 3000+ | ~90s (cap at 3000 files) |

**Rate-Limiting Factors:**
1. **TAINT_001** - Tree-sitter parsing is O(n) with file count
2. **SG_001** - Semgrep internally parallelizes, but still scales linearly
3. **Androguard string extraction** - O(DEX size), not file count

**Cap Mechanisms:**
- Most agents: `MAX_FILES_TO_SCAN = 3000`
- TAINT_001: `per_file_timeout = 8s` (skips runaway files)
- SG_001: `subprocess_timeout = 300s` (kills semgrep if stuck)

### 6.3 Memory Usage

| Agent | Peak Memory | Notes |
|-------|-------------|-------|
| Regex agents | ~50 MB | Text in memory per file |
| Tree-sitter | ~200 MB | AST nodes held during analysis |
| Semgrep | ~800 MB | External process |
| Androguard | ~300 MB | DEX loaded into memory |
| SCA_001 | ~100 MB | ZIP extraction + SQLite queries |

**Total Phase 2 Peak:** ~1.5 GB (agents run concurrently)

### 6.4 Bottleneck Analysis

**Slowest Components:**
1. **Semgrep (15s)** - External subprocess, can't optimize further
2. **TAINT_001 (12s)** - Tree-sitter parsing + backward slicing
3. **P_010 (5s)** - Tree-sitter parsing
4. **SCA_001 (3s)** - ZIP extraction

**Optimization Opportunities:**
1. **Cache tree-sitter parses** - TAINT_001 and P_010 parse same files twice
2. **Batch Semgrep rules** - Currently runs all 18 rules, could split critical/optional
3. **Parallel file processing** - Currently sequential per agent, could parallelize file-level

**Why Not Optimized Yet:**
- 20s total is acceptable for typical APK (~500 files)
- Premature optimization adds complexity
- Most time spent in external tools (Semgrep, tree-sitter) not under our control

---

## 7. SUMMARY - HOW STATIC ANALYSIS WORKS

### 7.1 Core Principles

1. **Layered Detection** - Regex, AST, Semgrep, bytecode each catch different bug classes
2. **Parallel Execution** - 88 agents run concurrently, not serially
3. **Crash Isolation** - One agent failure doesn't kill the scan
4. **Scope Filtering** - Out-of-scope findings dropped before storage
5. **Multi-Source Inputs** - JADX, apktool, Androguard all contribute

### 7.2 Agent Categories

| Category | Count | Example Agents | Primary Technique |
|----------|-------|----------------|-------------------|
| Crypto/Storage | 14 | C_007, STG_009 | Regex + manifest |
| Network | 11 | N_002, N_014 | Regex + XML scan |
| Auth | 12 | A_004, A_010 | Regex + bytecode |
| Platform/IPC | 11 | P_010, P_001 | AST control-flow |
| Taint | 1 | TAINT_001 | AST + backward slice |
| Semgrep | 1 | SG_001 | 18 YAML rules |
| SCA | 1 | SCA_001 | pom.properties + CVE DB |
| Cross-platform | 2 | RN_001, FL_001 | JS/Dart regex |

### 7.3 Detection Accuracy

**High Confidence (0.85-0.95):**
- Hardcoded secrets (clear patterns)
- Manifest misconfigurations (authoritative)
- Crypto API misuse (exact method names)
- CVE matches with pom.properties (tier 1)

**Medium Confidence (0.70-0.85):**
- Taint flows (1-2 hops)
- Intent redirect (intra-method only)
- Cleartext traffic (could be test URLs)

**Low Confidence (0.40-0.70):**
- Cross-platform (Hermes, Flutter limitations)
- SCA tier 3 (classpath presence only, no version)
- Excessive permissions (context-dependent)

### 7.4 Key Strengths

✅ **Works on obfuscated APKs** - Androguard bytecode scan always succeeds  
✅ **Fast** - 20s for typical APK (500 files)  
✅ **Comprehensive** - 88 agents cover OWASP Mobile Top 10  
✅ **Extensible** - Add agents without touching orchestrator  
✅ **Auditable** - Each agent's logic is <500 LOC, easy to review  

### 7.5 Known Limitations

❌ **No reflection** - Can't follow `Class.forName().newInstance()`  
❌ **Limited IPA** - Max 3 call-graph hops (TAINT_001)  
❌ **No field sensitivity** - Can't track instance/static fields  
❌ **JADX dependency** - Obfuscated/malformed APKs break some agents  
❌ **Hermes/Flutter** - Bytecode formats block JS/Dart analysis  

---

**End of Document**

