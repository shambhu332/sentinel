/**
 * demo.js — interactive scan demo.
 * Left: config column (sample APK, scope, toggles).
 * Right: phase timeline + live log + animated findings table.
 * Pacing comes from scan-runner.js (~14–18s end-to-end).
 */

import { runScan, SAMPLE_APKS } from '../components/scan-runner.js';

export function renderDemo(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Demo</h1>
        <div class="page-sub">Run a simulated end-to-end scan in your browser — no install required.</div>
      </div>
    </div>

    <div class="grid" style="grid-template-columns: 1fr 1.6fr; gap: var(--space-6); align-items: start;">

      <!-- LEFT: configuration column -->
      <div class="card">
        <div class="card-title mb-4">Configuration</div>

        <div class="form-group">
          <label class="label">Sample APK</label>
          <div class="stack-sm">
            ${SAMPLE_APKS.map((a, i) => `
              <label class="card-flat row-sm" style="padding: var(--space-3); cursor:pointer; border:1px solid var(--border); border-radius: var(--radius-md);">
                <input type="radio" name="demo-apk" value="${a.id}" ${i === 0 ? 'checked' : ''}/>
                <div class="flex-1">
                  <div style="font-weight:500;">${a.name}</div>
                  <code class="mono text-xs">${a.pkg}</code>
                </div>
                <span class="text-xs text-mute">${a.size}</span>
              </label>`).join('')}
          </div>
        </div>

        <div class="form-group mt-4">
          <label class="label">Bug bounty scope</label>
          <textarea class="textarea" placeholder="https://hackerone.com/programs/example or inline JSON…">https://hackerone.com/programs/example-bank</textarea>
        </div>

        <div class="form-group mt-4">
          <label class="label">Analysis options</label>
          <div class="stack-sm" style="gap: var(--space-3);">
            <label class="row-sm"><span class="toggle"><input type="checkbox" id="d-dyn" checked/><span class="toggle-slider"></span></span> Dynamic (<code class="mono">--dynamic</code>)</label>
            <label class="row-sm"><span class="toggle"><input type="checkbox" id="d-fri" checked/><span class="toggle-slider"></span></span> Frida (<code class="mono">--frida</code>)</label>
            <label class="row-sm"><span class="toggle"><input type="checkbox" id="d-nop"/><span class="toggle-slider"></span></span> No proxy (<code class="mono">--no-proxy</code>)</label>
            <label class="row-sm"><span class="toggle"><input type="checkbox" id="d-pri"/><span class="toggle-slider"></span></span> Privacy mode (<code class="mono">--private</code>)</label>
            <label class="row-sm"><span class="toggle"><input type="checkbox" id="d-tri" checked/><span class="toggle-slider"></span></span> LLM triage (<code class="mono">--triage</code>)</label>
          </div>
        </div>

        <button class="btn btn-primary btn-lg btn-block mt-6" id="demo-run">
          <i data-lucide="play"></i> Run scan
        </button>
        <p class="text-mute text-xs mt-3 text-center">Animation runs entirely in your browser — no data leaves this page.</p>
      </div>

      <!-- RIGHT: result column -->
      <div id="demo-result-pane">
        <div class="empty">
          <i data-lucide="play-circle"></i>
          <h3>Press <strong>Run scan</strong> to begin</h3>
          <p>The simulation walks through the 5 SENTINEL phases — Ingestion → Recon → 20 agents → Triage → Dynamic + Frida — and reveals findings as triage completes.</p>
        </div>
      </div>
    </div>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  mount.querySelector('#demo-run').addEventListener('click', () => {
    const opts = {
      dynamic: mount.querySelector('#d-dyn').checked,
      frida:   mount.querySelector('#d-fri').checked,
      noProxy: mount.querySelector('#d-nop').checked,
      private: mount.querySelector('#d-pri').checked,
      triage:  mount.querySelector('#d-tri').checked,
    };
    const target = mount.querySelector('#demo-result-pane');
    target.innerHTML = '';
    runScan(target, opts);
  });
}
