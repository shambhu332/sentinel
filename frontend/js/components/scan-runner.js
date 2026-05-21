/**
 * scan-runner.js — simulated scan animation.
 *
 * Two exports:
 *   - openNewScanModal()  : opens the modal launched from the topbar
 *   - runScan(opts)       : drives the timeline + log + findings reveal
 *                           (used by demo.js and the New-Scan modal)
 *
 * Pacing target: 14–18s end-to-end.
 */

import { openModal } from './modal.js';
import { toast } from './toast.js';
import { PROJECTS } from '../data/projects.js';
import { FINDINGS } from '../data/findings.js';
import { severityChip } from './severity-chip.js';
import { triageChip } from './triage-chip.js';

const SAMPLE_APKS = [
  { id: 'campus',  name: 'campus.apk',         pkg: 'com.global.edu.campus',     size: '28.4 MB' },
  { id: 'signal',  name: 'signal.apk',         pkg: 'org.thoughtcrime.securesms', size: '75.2 MB' },
  { id: 'ibank2',  name: 'InsecureBankv2.apk', pkg: 'com.android.insecurebankv2', size: '4.1 MB' },
];

const PHASES = [
  { id: 'p0',   name: 'Phase 0 · Ingestion',         desc: 'SHA-256 hash · workspace setup · manifest extraction', dur: 1100 },
  { id: 'p1',   name: 'Phase 1 · Parallel Recon',    desc: 'JADX · Androguard · apktool · manifest (async)',       dur: 2200 },
  { id: 'p2',   name: 'Phase 2 · 20 Analysis Agents', desc: 'Static analysis across 14 SAST + 2 meta agents',       dur: 3800 },
  { id: 'p3',   name: 'Phase 3 · LLM Triage',         desc: 'FreeProviderRouter · Groq → Cerebras → Ollama',         dur: 2400 },
  { id: 'p4',   name: 'Phase 4 · Dynamic Analysis',   desc: 'mitmproxy capture · cleartext + PII inspection',        dur: 3000 },
  { id: 'p4_5', name: 'Phase 4.5 · Frida Runtime',    desc: 'CipherHooks · 6 pinning libraries probed',              dur: 3000 },
];

/** Build the CLI preview string from form state. */
function previewCli(state) {
  const flags = [];
  if (state.dynamic) flags.push('--dynamic');
  if (state.frida)   flags.push('--frida');
  if (state.noProxy) flags.push('--no-proxy');
  if (state.private) flags.push('--private');
  if (state.triage)  flags.push('--triage');
  if (state.dynDur)  flags.push(`--dynamic-duration ${state.dynDur}`);
  if (state.fridaDur)flags.push(`--frida-duration ${state.fridaDur}`);
  const apk = state.apk || 'corpus/campus.apk';
  return `poetry run sentinel scan ${apk}${flags.length ? ' ' + flags.join(' ') : ''}`;
}

/** Open the topbar New-Scan modal. */
export function openNewScanModal(prefill = {}) {
  const projects = PROJECTS.filter((p) => p.status !== 'Completed');
  const state = {
    apk: 'corpus/campus.apk',
    project: prefill.projectId || projects[0]?.id || '',
    scope: '',
    dynamic: true, frida: true, noProxy: false, private: false, triage: true,
    dynDur: 30, fridaDur: 60,
  };

  const body = `
    <div class="stack">
      <div class="form-group">
        <label class="label">APK <span class="label-hint">drag-drop or pick a sample</span></label>
        <div class="drop-zone" id="drop-zone">
          <i data-lucide="upload-cloud" style="width:24px;height:24px;display:inline-block;"></i>
          <div class="mt-2">Drop an APK here</div>
          <div class="text-xs text-mute mt-2">Demo only — APK selection is mocked</div>
        </div>
        <select class="select" id="apk-pick">
          <option value="corpus/campus.apk">campus.apk · com.global.edu.campus</option>
          <option value="corpus/signal.apk">signal.apk · org.thoughtcrime.securesms</option>
          <option value="corpus/InsecureBankv2.apk">InsecureBankv2.apk · com.android.insecurebankv2</option>
        </select>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label class="label">Project</label>
          <select class="select" id="proj-pick">
            ${projects.map((p) => `<option value="${p.id}" ${p.id === state.project ? 'selected' : ''}>${p.name}</option>`).join('')}
            <option value="__new__">+ Create new project…</option>
          </select>
        </div>
        <div class="form-group">
          <label class="label">LLM provider</label>
          <select class="select" id="llm-pick">
            <option value="auto">Auto-rotate (Groq → Cerebras → Ollama)</option>
            <option value="groq">Groq only</option>
            <option value="cerebras">Cerebras only</option>
            <option value="ollama">Ollama (local) — private</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label class="label">Bug bounty scope <span class="label-hint">URL · file path · inline rules</span></label>
        <textarea class="textarea" id="scope-text" placeholder="https://hackerone.com/programs/example or inline JSON…"></textarea>
      </div>

      <div class="form-group">
        <label class="label">Analysis options</label>
        <div class="grid-2" style="gap: var(--space-3);">
          <label class="row-sm"><span class="toggle"><input type="checkbox" id="opt-dyn" checked/><span class="toggle-slider"></span></span> Dynamic analysis (<code class="mono">--dynamic</code>)</label>
          <label class="row-sm"><span class="toggle"><input type="checkbox" id="opt-frida" checked/><span class="toggle-slider"></span></span> Frida hooks (<code class="mono">--frida</code>)</label>
          <label class="row-sm"><span class="toggle"><input type="checkbox" id="opt-noproxy"/><span class="toggle-slider"></span></span> No proxy (<code class="mono">--no-proxy</code>)</label>
          <label class="row-sm"><span class="toggle"><input type="checkbox" id="opt-private"/><span class="toggle-slider"></span></span> Privacy mode (<code class="mono">--private</code>)</label>
          <label class="row-sm"><span class="toggle"><input type="checkbox" id="opt-triage" checked/><span class="toggle-slider"></span></span> LLM triage (<code class="mono">--triage</code>)</label>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label class="label">Dynamic duration (s)</label>
          <input class="input" type="number" id="opt-dyndur" value="30" min="5" max="600"/>
        </div>
        <div class="form-group">
          <label class="label">Frida duration (s)</label>
          <input class="input" type="number" id="opt-fridadur" value="60" min="5" max="600"/>
        </div>
      </div>

      <div class="form-group">
        <label class="label">CLI preview</label>
        <code class="mono" id="cli-preview" style="display:block; padding: var(--space-3); background:#04060C; border:1px solid var(--border); border-radius: var(--radius-md); white-space:pre-wrap; word-break:break-all;">${previewCli(state)}</code>
      </div>
    </div>
  `;

  const footer = `
    <button class="btn btn-ghost" data-close>Cancel</button>
    <button class="btn btn-primary" id="start-scan-btn"><i data-lucide="play"></i> Start scan</button>
  `;

  const m = openModal({ title: 'Start a new scan', body, footer, width: 720 });

  /* Wire form state */
  const $ = (sel) => m.el.querySelector(sel);
  const preview = $('#cli-preview');
  const refresh = () => {
    state.apk     = $('#apk-pick').value;
    state.project = $('#proj-pick').value;
    state.dynamic = $('#opt-dyn').checked;
    state.frida   = $('#opt-frida').checked;
    state.noProxy = $('#opt-noproxy').checked;
    state.private = $('#opt-private').checked;
    state.triage  = $('#opt-triage').checked;
    state.dynDur  = +$('#opt-dyndur').value;
    state.fridaDur= +$('#opt-fridadur').value;
    preview.textContent = previewCli(state);
  };
  m.el.addEventListener('change', refresh);
  m.el.addEventListener('input',  refresh);
  m.el.querySelector('#drop-zone').addEventListener('click', () => {
    toast('Demo only — APK selection is mocked', { type: 'warning' });
  });
  m.el.querySelector('[data-close]').addEventListener('click', () => m.close());

  m.el.querySelector('#start-scan-btn').addEventListener('click', () => {
    m.close();
    toast('Scan queued — navigating to Dashboard', { type: 'success' });
    /* Switch to dashboard and start a fake run */
    if (location.hash !== '#dashboard') location.hash = 'dashboard';
    setTimeout(() => {
      const target = document.getElementById('dashboard-runner-target');
      if (target) {
        runScan(target, state);
      }
    }, 250);
  });
}

/**
 * Run the simulated scan animation into `mount`.
 * Renders a phase timeline, live log, summary + findings table.
 */
export function runScan(mount, opts = {}) {
  const dynamic = opts.dynamic !== false;
  const frida   = opts.frida   !== false;
  const phases  = PHASES.filter((p) => {
    if (p.id === 'p4'   && !dynamic) return false;
    if (p.id === 'p4_5' && !frida)   return false;
    return true;
  });

  mount.innerHTML = `
    <div class="card" style="padding: var(--space-5);">
      <div class="row-between mb-4">
        <div>
          <div class="text-dim text-xs uppercase" style="letter-spacing:.08em;">In progress</div>
          <div style="font-size: var(--fs-md); font-weight:600;">Simulated scan run</div>
        </div>
        <div class="row-sm">
          <span class="chip chip-status-running"><span class="sev-dot sev-dot-medium"></span> running</span>
        </div>
      </div>
      <div class="scan-timeline" id="scan-timeline">
        ${phases.map((p) => `
          <div class="scan-phase" data-phase="${p.id}" data-state="pending">
            <span class="scan-phase-marker"><i data-lucide="circle"></i></span>
            <div class="scan-phase-body">
              <div class="scan-phase-name">${p.name}</div>
              <div class="scan-phase-desc">${p.desc}</div>
            </div>
            <span class="scan-phase-time">—</span>
          </div>
        `).join('')}
      </div>

      <div class="log-stream" id="log-stream"></div>

      <div id="scan-summary" class="hidden mt-6">
        <div class="row-between mb-4">
          <div>
            <div style="font-size: var(--fs-md); font-weight:600;">Scan complete</div>
            <div class="text-dim text-sm" id="scan-summary-meta"></div>
          </div>
          <div class="row-sm">
            <button class="btn btn-secondary btn-sm" onclick="location.hash='reports'"><i data-lucide="file-text"></i> Generate report</button>
          </div>
        </div>
        <div id="scan-findings"></div>
      </div>
    </div>
  `;
  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  const log = mount.querySelector('#log-stream');
  const appendLog = (line, cls = '') => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    const el = document.createElement('div');
    el.className = 'line';
    el.innerHTML = `<span class="ts">[${ts}]</span> <span class="${cls}">${line}</span>`;
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
  };

  appendLog('phase=0 hash=sha256:0d4e3a… size=28.4MB', 'info');

  let total = 0;
  phases.forEach((p, idx) => {
    setTimeout(() => {
      const row = mount.querySelector(`[data-phase="${p.id}"]`);
      row.dataset.state = 'running';
      row.querySelector('.scan-phase-marker i').setAttribute('data-lucide', 'loader-2');
      if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
      appendLog(`▸ entering ${p.name}`, 'info');

      /* mid-phase log lines for flavor */
      if (p.id === 'p2') setTimeout(() => appendLog('[A_001] match LoginActivity.java:142 key=auth_token', ''), p.dur * 0.4);
      if (p.id === 'p3') setTimeout(() => appendLog('Groq 429 (rate limit), attempt 1 — switching cerebras', 'warn'), p.dur * 0.5);
      if (p.id === 'p4') setTimeout(() => appendLog('mitmproxy capture: 14 reqs · 2 cleartext', ''), p.dur * 0.5);
      if (p.id === 'p4_5') {
        setTimeout(() => appendLog('Frida attached to com.global.edu.campus pid=12288', 'ok'), p.dur * 0.3);
        setTimeout(() => appendLog('[N_005] X509TrustManagerExtensions bypass_success', 'err'), p.dur * 0.7);
      }

      setTimeout(() => {
        row.dataset.state = 'done';
        row.querySelector('.scan-phase-marker i').setAttribute('data-lucide', 'check');
        row.querySelector('.scan-phase-time').textContent = (p.dur / 1000).toFixed(1) + 's';
        if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
      }, p.dur);
    }, total);
    total += p.dur;
  });

  /* When everything done, reveal findings panel */
  setTimeout(() => {
    appendLog('✓ scan complete — 12 findings produced (6 verified)', 'ok');
    const summary = mount.querySelector('#scan-summary');
    summary.classList.remove('hidden');
    const meta = mount.querySelector('#scan-summary-meta');
    meta.textContent = `Pacing simulated · ${(total / 1000).toFixed(1)}s total · 6 verified · 4 filtered · 2 uncertain`;

    /* Show campus findings as the demo payload */
    const demoFindings = FINDINGS.filter((f) => f.scanId === 'aL1xV3Tmz8KrnQH7').slice(0, 8);
    const target = mount.querySelector('#scan-findings');
    target.innerHTML = `
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Severity</th><th>Triage</th><th>Agent</th><th>Finding</th></tr></thead>
        <tbody>
          ${demoFindings.map((f) => `
            <tr>
              <td>${severityChip(f.severity)}</td>
              <td>${triageChip(f.triage)}</td>
              <td><span class="mono" style="color:var(--accent-2);">${f.agentId}</span></td>
              <td>${f.vulnClass}</td>
            </tr>
          `).join('')}
        </tbody>
      </table></div>`;
  }, total + 400);
}

export { SAMPLE_APKS, PHASES };
