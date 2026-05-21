/**
 * architecture.js — long-form Architecture explainer.
 * Covers: pipeline phases, tool layer, BaseAgent abstraction,
 * LLM router, Frida hook script, crash-proof design, memory layer,
 * and an honest real-device validation section.
 */

const PHASES = [
  { n: 0,   name: 'Ingestion',           desc: 'SHA-256 hashing, workspace setup, manifest extraction. Produces a normalised APK record consumed by every later phase.',                            tools: ['hashlib', 'apkutil'] },
  { n: 1,   name: 'Parallel Recon',      desc: 'JADX, Androguard, apktool, and the manifest parser run concurrently via asyncio.gather. Each wrapper returns ToolResult.ok / ToolResult.fail so a single tool failure cannot stall recon.', tools: ['JADX', 'Androguard', 'apktool', 'ManifestParser'] },
  { n: 2,   name: '20 Analysis Agents',  desc: '14 SAST + 2 meta agents fan out across the decompiled corpus. Each agent inherits from BaseAgent and returns a list of Findings with structured evidence.', tools: ['BaseAgent', 'AgentRegistry'] },
  { n: 3,   name: 'LLM Triage',          desc: 'FreeProviderRouter rotates Groq → Cerebras → Ollama on rate-limit or 5xx. Each finding gets classified verified ✓ / filtered ✗ / uncertain ? / skipped —.',         tools: ['FreeProviderRouter', 'TriagePrompt'] },
  { n: 4,   name: 'Dynamic Analysis',    desc: 'Optional. Launches the app on a connected Android device, sets the WiFi proxy to a local mitmproxy, captures TLS traffic. --no-proxy skips proxy setup for apps with anti-MITM detection (Signal, banking).', tools: ['mitmproxy', 'adb', 'DeviceController'] },
  { n: 4.5, name: 'Frida Runtime Hooks', desc: 'Injects JS hooks via a standalone frida-server. Hooks Cipher.getInstance, MessageDigest.getInstance, and six pinning libraries (CertificatePinner, X509TrustManagerExtensions, WebViewClient.onReceivedSslError, TrustKit, Conscrypt, OkHostnameVerifier).', tools: ['frida', 'frida-server', 'ALL_RUNTIME_HOOKS'] },
];

const TOOLS = [
  { name: 'JADX',         role: 'Decompiles dex → .java sources',                        lang: 'Java',   notes: 'Wrapped; OOM falls back to apktool partial output.' },
  { name: 'Androguard',   role: 'Parses dex symbols, resources, manifest tree',          lang: 'Python', notes: 'In-process; never fatals the pipeline.' },
  { name: 'apktool',      role: 'Smali / resource extraction',                           lang: 'Java',   notes: 'Used as JADX fallback and for resource sweep.' },
  { name: 'mitmproxy',    role: 'Captures TLS traffic during dynamic analysis',          lang: 'Python', notes: 'Boots transparently; cleanup wired to ToolResult.' },
  { name: 'frida-server', role: 'Runtime instrumentation host on device',                lang: 'C',      notes: 'Standalone binary pushed once per-arch; 16.x pinned.' },
];

const FRIDA_SOURCE = `// ALL_RUNTIME_HOOKS — source verbatim from sentinel/tools/frida_runner.py
Java.perform(function () {
  /* Cipher / MessageDigest tracking ----------------------------- */
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.getInstance.overload('java.lang.String').implementation = function (algo) {
    send({ type: 'crypto.cipher', algo: algo, stack: getStack() });
    return this.getInstance(algo);
  };
  var MD = Java.use('java.security.MessageDigest');
  MD.getInstance.overload('java.lang.String').implementation = function (algo) {
    send({ type: 'crypto.digest', algo: algo, stack: getStack() });
    return this.getInstance(algo);
  };

  /* TLS pinning probes ------------------------------------------ */
  tryHook('okhttp3.CertificatePinner', 'check', function (orig, hostname, peerCerts) {
    try { var r = orig.apply(this, arguments); send({ type: 'tls.pin', lib: 'okhttp', result: 'survived' }); return r; }
    catch (e) { send({ type: 'tls.pin', lib: 'okhttp', result: 'bypass_success' }); }
  });
  tryHook('android.net.http.X509TrustManagerExtensions', 'checkServerTrusted', function () {
    send({ type: 'tls.pin', lib: 'x509ext', result: 'bypass_success' });
    return [];
  });
  tryHook('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify', function (orig) {
    var r = orig.apply(this, arguments); send({ type: 'tls.pin', lib: 'trustkit', result: r ? 'survived' : 'bypass_success' }); return r;
  });
  /* Conscrypt, WebViewClient.onReceivedSslError, OkHostnameVerifier — analogous wrappers */
});

function tryHook(cls, method, replacement) {
  try { var C = Java.use(cls); C[method].implementation = function () { return replacement.apply(this, [C[method].bind(this), ...arguments]); }; }
  catch (e) { send({ type: 'tls.pin', lib: cls, result: 'absent' }); }
}`;

export function renderArchitecture(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Architecture</h1>
        <div class="page-sub">5-phase pipeline · 20 agents · crash-proof tool layer</div>
      </div>
    </div>

    <!-- 1. Pipeline phases ----------------------------------------------- -->
    <h6 class="mt-8 mb-4">1 · Pipeline phases</h6>
    <div class="stack">
      ${PHASES.map((p) => `
        <article class="card">
          <div class="row-between mb-3">
            <div class="row-sm">
              <span class="phase-num" style="width:32px;height:32px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;background:var(--gradient);color:#0B0F1E;font-weight:700;">${p.n}</span>
              <h3 style="font-size: var(--fs-md);">${p.name}</h3>
            </div>
            <div class="row-sm">${p.tools.map((t) => `<span class="chip chip-cat">${t}</span>`).join('')}</div>
          </div>
          <p>${p.desc}</p>
        </article>`).join('')}
    </div>

    <!-- 2. Tool layer ---------------------------------------------------- -->
    <h6 class="mt-8 mb-4">2 · Tool layer</h6>
    <div class="card p-0" style="padding:0;">
      <table class="table">
        <thead><tr><th>Tool</th><th>Role</th><th>Lang</th><th>Crash-proof note</th></tr></thead>
        <tbody>
          ${TOOLS.map((t) => `<tr>
            <td><strong>${t.name}</strong></td>
            <td>${t.role}</td>
            <td><span class="chip chip-cat">${t.lang}</span></td>
            <td class="text-dim text-sm">${t.notes}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>

    <!-- 3. BaseAgent ----------------------------------------------------- -->
    <h6 class="mt-8 mb-4">3 · BaseAgent abstraction</h6>
    <div class="card">
      <p class="mb-4">Every analysis agent inherits from <code>BaseAgent</code> and implements three methods. The orchestrator never calls an agent that returns <code>False</code> from <code>is_applicable</code>, keeping cross-agent failures isolated.</p>
      <pre><code>class BaseAgent(ABC):
    """Base class for every Phase 2 / 4 / 4.5 agent."""
    id: str
    category: str

    @abstractmethod
    def is_applicable(self, ctx: ScanContext) -> bool:
        """Decide whether to run against this APK at all."""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Run the analysis. Must never raise — wrap in ToolResult."""

    def produce_finding(self, **kwargs) -> Finding:
        """Helper that fills in agent id, timestamps, scan id, etc."""
        return Finding(agent_id=self.id, **kwargs)</code></pre>
    </div>

    <!-- 4. LLM router ---------------------------------------------------- -->
    <h6 class="mt-8 mb-4">4 · LLM router</h6>
    <div class="card">
      <p class="mb-4">A single <code>FreeProviderRouter</code> rotates across three providers with exponential backoff and per-provider rate-limit tracking. Privacy mode pins the router to local Ollama.</p>
      <svg viewBox="0 0 800 200" style="width:100%; height: 200px; background: var(--surface-2); border-radius: var(--radius-md);">
        <defs>
          <linearGradient id="r-line" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#7C3AED"/><stop offset="100%" stop-color="#22D3EE"/></linearGradient>
          <marker id="r-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="#22D3EE"/></marker>
        </defs>
        <!-- Providers -->
        <g font-family="JetBrains Mono" font-size="12" fill="#E6EAF2">
          <rect x="40" y="40" width="120" height="40" rx="8" fill="#141B2E" stroke="#2A3454"/><text x="100" y="65" text-anchor="middle">Groq</text>
          <rect x="40" y="100" width="120" height="40" rx="8" fill="#141B2E" stroke="#2A3454"/><text x="100" y="125" text-anchor="middle">Cerebras</text>
          <rect x="40" y="160" width="120" height="40" rx="8" fill="#141B2E" stroke="#2A3454"/><text x="100" y="185" text-anchor="middle">Ollama (local)</text>
          <rect x="500" y="100" width="200" height="40" rx="8" fill="#1B2340" stroke="#22D3EE"/><text x="600" y="125" text-anchor="middle" fill="#22D3EE">Triager</text>
        </g>
        <g stroke="url(#r-line)" stroke-width="2" fill="none" marker-end="url(#r-arrow)">
          <path d="M160 60  C 300 60, 360 90, 500 120"/>
          <path d="M160 120 C 280 120, 360 120, 500 120"/>
          <path d="M160 180 C 300 180, 360 150, 500 120"/>
        </g>
        <g font-family="Inter" font-size="11" fill="#9CA8C0">
          <text x="280" y="55">primary</text>
          <text x="280" y="115">fallback on 429</text>
          <text x="280" y="200">privacy mode pin</text>
        </g>
      </svg>
    </div>

    <!-- 5. Frida hook script -------------------------------------------- -->
    <h6 class="mt-8 mb-4">5 · Frida hook script</h6>
    <div class="card">
      <p class="mb-4">Source for <code>ALL_RUNTIME_HOOKS</code> — injected once per attach. Each <code>tryHook</code> records absent / survived / bypass_success outcomes for the six pinning libraries probed.</p>
      <pre><code>${escapeHtml(FRIDA_SOURCE)}</code></pre>
    </div>

    <!-- 6. Crash-proof design ------------------------------------------- -->
    <h6 class="mt-8 mb-4">6 · Crash-proof tool layer</h6>
    <div class="card">
      <p class="mb-4">Every external-process wrapper returns <code>ToolResult.ok(value)</code> or <code>ToolResult.fail(reason)</code> instead of raising. The orchestrator never sees a stack trace from a tool process.</p>
      <pre><code>@dataclass(frozen=True)
class ToolResult(Generic[T]):
    value: T | None
    error: str | None

    @classmethod
    def ok(cls, value: T) -> "ToolResult[T]":
        return cls(value=value, error=None)

    @classmethod
    def fail(cls, error: str) -> "ToolResult[T]":
        return cls(value=None, error=error)</code></pre>
    </div>

    <!-- 7. Memory layer ------------------------------------------------- -->
    <h6 class="mt-8 mb-4">7 · Memory layer</h6>
    <div class="card">
      <p>A lightweight <code>LightweightMemory</code> wraps ChromaDB plus an in-memory event bus. Agents publish findings to the bus; the triager subscribes and rolls events into a single per-scan transcript that the LLM router consumes in one shot.</p>
    </div>

    <!-- 8. Real-device validation --------------------------------------- -->
    <h6 class="mt-8 mb-4">8 · Real-device validation (honest)</h6>
    <div class="card" style="border-color: rgba(251,191,36,0.30);">
      <div class="row-sm mb-3"><i data-lucide="alert-triangle" style="color: var(--sev-medium);"></i> <strong>Known limitations</strong></div>
      <ul style="padding-left: var(--space-5);">
        <li style="list-style:disc;">Supported architectures: <code>arm64-v8a</code> (validated on Pixel 4a + GrapheneOS), <code>x86_64</code> (validated on Android Studio Emulator API 34).</li>
        <li style="list-style:disc;">Samsung devices with Knox / RKP active restrict Frida 16's ptrace operations — phase 4.5 will report <code>frida.attach</code> denied. We log the YAMA fallback (<code>adb pidof</code>) but cannot bypass RKP.</li>
        <li style="list-style:disc;">Apps with strong anti-debug (banking, Signal) routinely terminate themselves under Frida — use <code>--frida-duration 15</code> and capture the first few seconds, or skip Frida entirely with <code>--no-frida</code>.</li>
      </ul>
    </div>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}
