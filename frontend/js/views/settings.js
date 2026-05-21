/**
 * settings.js — user + instance settings.
 * Sections: Profile · LLM providers · Privacy & data · Notifications
 * · Scan defaults · API tokens · About.
 */

import { rateLimitBar } from '../components/charts.js';
import { toast } from '../components/toast.js';

const PROVIDERS = [
  { id: 'groq',     name: 'Groq',     status: 'Connected',     usage: [4,6,5,8,12,9,11,7,5,4,3,8,10,7] },
  { id: 'cerebras', name: 'Cerebras', status: 'Connected',     usage: [2,3,4,3,5,7,6,4,3,2,3,5,4,3] },
  { id: 'ollama',   name: 'Ollama',   status: 'Not configured',usage: [0,0,0,0,0,0,0,0,0,0,0,0,0,0] },
];

const TOKENS = [
  { id: 't_ci',   name: 'CI runner',    lastUsed: '2 h ago',  scopes: ['scan:read', 'scan:write'] },
  { id: 't_lint', name: 'Linter bot',   lastUsed: 'yesterday',scopes: ['scan:read'] },
  { id: 't_dev',  name: 'Local dev',    lastUsed: '5 d ago',  scopes: ['scan:read', 'scan:write', 'reports:write'] },
];

export function renderSettings(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Settings</h1>
        <div class="page-sub">Profile · providers · privacy · tokens</div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Profile -->
      <div class="card">
        <div class="card-title mb-4">Profile</div>
        <div class="row gap-4 mb-4">
          <span class="avatar avatar-lg" style="background: var(--gradient); color: #0B0F1E;">NK</span>
          <div class="flex-1">
            <div class="form-group mb-2"><label class="label">Name</label><input class="input" value="Nehal Mehta"/></div>
            <div class="form-group"><label class="label">Email</label><input class="input" value="nehal@sentinel.dev"/></div>
          </div>
        </div>
        <div class="form-group"><label class="label">Timezone</label>
          <select class="select"><option>Asia/Kathmandu (UTC+5:45)</option><option>UTC</option><option>America/New_York</option></select>
        </div>
      </div>

      <!-- About -->
      <div class="card">
        <div class="card-title mb-4">About</div>
        <table class="table" style="font-size:13px;">
          <tbody>
            <tr><td class="text-mute">Version</td><td><code class="mono">0.1.0</code></td></tr>
            <tr><td class="text-mute">Commit</td><td><code class="mono">04352a1f</code></td></tr>
            <tr><td class="text-mute">License</td><td>MIT</td></tr>
            <tr><td class="text-mute">Source</td><td><a class="text-sm" href="https://github.com/shambhu332/sentinel" target="_blank" rel="noopener">github.com/shambhu332/sentinel ↗</a></td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- LLM providers -->
    <h6 class="mt-8 mb-4">LLM providers</h6>
    <div class="grid-3">
      ${PROVIDERS.map((p) => `
        <div class="card">
          <div class="row-between mb-3">
            <strong>${p.name}</strong>
            <span class="chip ${p.status === 'Connected' ? 'chip-status-active' : 'chip-cat'}">${p.status}</span>
          </div>
          <div class="form-group">
            <label class="label">API key</label>
            <input class="input" type="password" value="${p.status === 'Connected' ? '•'.repeat(28) : ''}" placeholder="paste key…"/>
          </div>
          <div class="text-xs text-mute mt-3" style="margin-bottom: 4px;">Last 14d usage</div>
          <div style="height: 36px;"><canvas data-rl="${p.id}"></canvas></div>
        </div>`).join('')}
    </div>

    <!-- Privacy + Notifications + Scan defaults -->
    <div class="grid-2 mt-8">
      <div class="card">
        <div class="card-title mb-4">Privacy & data</div>
        <label class="row-sm mb-3"><span class="toggle"><input type="checkbox"/><span class="toggle-slider"></span></span> Default to privacy mode (local Ollama only)</label>
        <div class="form-group"><label class="label">Data retention</label>
          <select class="select"><option>30 days</option><option>90 days</option><option selected>180 days</option><option>365 days</option></select>
        </div>
        <div class="row gap-2 mt-4">
          <button class="btn btn-secondary btn-sm"><i data-lucide="download"></i> Export all data</button>
          <button class="btn btn-danger btn-sm"><i data-lucide="trash-2"></i> Delete account</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title mb-4">Notifications</div>
        <label class="row-sm mb-3"><span class="toggle"><input type="checkbox" checked/><span class="toggle-slider"></span></span> Email on scan completion</label>
        <label class="row-sm mb-3"><span class="toggle"><input type="checkbox" checked/><span class="toggle-slider"></span></span> Email on Critical findings</label>
        <label class="row-sm"><span class="toggle"><input type="checkbox"/><span class="toggle-slider"></span></span> Weekly digest</label>
      </div>
    </div>

    <div class="card mt-6">
      <div class="card-title mb-4">Scan defaults</div>
      <div class="grid-2" style="gap: var(--space-3);">
        <label class="row-sm"><span class="toggle"><input type="checkbox" checked/><span class="toggle-slider"></span></span> Dynamic analysis</label>
        <label class="row-sm"><span class="toggle"><input type="checkbox" checked/><span class="toggle-slider"></span></span> Frida hooks</label>
        <label class="row-sm"><span class="toggle"><input type="checkbox"/><span class="toggle-slider"></span></span> No proxy</label>
        <label class="row-sm"><span class="toggle"><input type="checkbox"/><span class="toggle-slider"></span></span> Privacy mode</label>
        <label class="row-sm"><span class="toggle"><input type="checkbox" checked/><span class="toggle-slider"></span></span> LLM triage</label>
      </div>
    </div>

    <!-- API tokens -->
    <h6 class="mt-8 mb-4">API tokens</h6>
    <div class="card p-0" style="padding:0;">
      <table class="table">
        <thead><tr><th>Name</th><th>Last used</th><th>Scopes</th><th></th></tr></thead>
        <tbody>
          ${TOKENS.map((t) => `<tr>
            <td><strong>${t.name}</strong></td>
            <td class="text-dim text-xs">${t.lastUsed}</td>
            <td>${t.scopes.map((s) => `<span class="chip chip-cat">${s}</span>`).join(' ')}</td>
            <td class="col-actions"><button class="btn btn-ghost btn-sm">Revoke</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
      <div class="p-4"><button class="btn btn-secondary btn-sm" id="set-create-token"><i data-lucide="key"></i> Create token</button></div>
    </div>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  /* Render mini-bar charts once Chart.js is ready */
  const init = () => {
    if (!window.Chart) return setTimeout(init, 80);
    PROVIDERS.forEach((p) => {
      const canvas = mount.querySelector(`canvas[data-rl="${p.id}"]`);
      if (canvas) rateLimitBar(canvas, { labels: p.usage.map((_, i) => i), values: p.usage });
    });
  };
  init();

  mount.querySelector('#set-create-token').addEventListener('click', () => toast('Token created (mock)', { type: 'success' }));
}
