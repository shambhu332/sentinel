/**
 * projects.js — Projects grid + Project detail.
 *
 * Detail tabs: Overview · Scans · Findings · Scope · Team · Settings.
 */

import { PROJECTS, getProject } from '../data/projects.js';
import { WORKSPACES, MEMBERS, getWorkspace } from '../data/workspaces.js';
import { SCANS, scansByProject, aggregateCounts } from '../data/scans.js';
import { findingsByProject } from '../data/findings.js';
import { severityChipsRow } from '../components/severity-chip.js';
import { renderFindingsTable } from '../components/findings-table.js';
import { openNewScanModal } from '../components/scan-runner.js';
import { toast } from '../components/toast.js';

const STATUS_CHIP = {
  Active:    '<span class="chip chip-status-active">Active</span>',
  Paused:    '<span class="chip chip-status-paused">Paused</span>',
  Completed: '<span class="chip chip-status-completed">Completed</span>',
};

function relative(ts) {
  if (!ts) return '—';
  const now = new Date('2026-05-21T10:00:00Z');
  const t   = new Date(ts.replace(' ', 'T') + 'Z');
  const mins = Math.round((now - t) / 60_000);
  if (mins < 60)            return `${mins} min ago`;
  if (mins < 60 * 24)       return `${Math.round(mins / 60)} h ago`;
  if (mins < 60 * 24 * 7)   return `${Math.round(mins / 1440)} d ago`;
  return ts.slice(0, 10);
}

function avatarStack(memberIds) {
  return `<div class="avatar-stack">${memberIds.slice(0, 4).map((id) => {
    const m = Object.values(MEMBERS).find((x) => x.id === id);
    if (!m) return '';
    return `<span class="avatar avatar-sm" style="background:${m.avatarColor}; color:#0B0F1E;" title="${m.name}">${m.initials}</span>`;
  }).join('')}</div>`;
}

const state = { search: '', status: 'all', workspace: 'all' };

function filtered() {
  return PROJECTS.filter((p) => {
    if (state.status !== 'all' && p.status !== state.status) return false;
    if (state.workspace !== 'all' && p.workspaceId !== state.workspace) return false;
    if (state.search) {
      const q = state.search.toLowerCase();
      if (!`${p.name} ${p.targetPackage} ${p.description}`.toLowerCase().includes(q)) return false;
    }
    return true;
  });
}

function renderGrid(mount) {
  const grid = mount.querySelector('#proj-grid');
  const list = filtered();
  if (!list.length) {
    grid.innerHTML = `<div class="empty"><i data-lucide="search-x"></i><h3>No projects match</h3><p>Adjust filters above.</p></div>`;
    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
    return;
  }
  grid.innerHTML = list.map((p) => {
    const ws = getWorkspace(p.workspaceId);
    const scans = scansByProject(p.id);
    const totalFindings = scans.reduce((n, s) => n + s.counts.critical + s.counts.high + s.counts.medium + s.counts.low + s.counts.info, 0);
    return `
      <article class="card card-hoverable" data-proj="${p.id}" style="cursor:pointer;">
        <div class="row-between mb-3">
          <span class="chip chip-cat">${ws?.name || ''}</span>
          ${STATUS_CHIP[p.status]}
        </div>
        <h3 style="font-size: var(--fs-md); margin-bottom: 6px;">${p.name}</h3>
        <code class="mono" style="font-size:12px;">${p.targetPackage}</code>
        <p class="text-dim text-sm mt-2" style="line-height:1.5;">${p.description}</p>
        <div class="row-between mt-4">
          <div class="row-sm text-xs text-mute">
            <span><strong style="color:var(--text);">${scans.length}</strong> scans</span>
            <span>·</span>
            <span><strong style="color:var(--text);">${totalFindings}</strong> findings</span>
            <span>·</span>
            <span>${relative(p.lastScanAt)}</span>
          </div>
          ${avatarStack(p.teamIds)}
        </div>
      </article>`;
  }).join('');

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  grid.querySelectorAll('[data-proj]').forEach((card) => {
    card.addEventListener('click', () => { location.hash = `projects/${card.dataset.proj}`; });
  });
}

export function renderProjects(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Projects</h1>
        <div class="page-sub">${PROJECTS.length} projects across ${WORKSPACES.length} workspaces</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm" id="proj-new"><i data-lucide="plus"></i> New project</button>
      </div>
    </div>

    <div class="filters-bar">
      <div class="input-search" style="flex:1;">
        <i data-lucide="search"></i>
        <input class="input" id="proj-search" placeholder="Search by name, package, description…"/>
      </div>
      <select class="select" id="proj-status">
        <option value="all">All statuses</option>
        <option value="Active">Active</option>
        <option value="Paused">Paused</option>
        <option value="Completed">Completed</option>
      </select>
      <select class="select" id="proj-ws">
        <option value="all">All workspaces</option>
        ${WORKSPACES.map((w) => `<option value="${w.id}">${w.name}</option>`).join('')}
      </select>
    </div>

    <div class="grid-3" id="proj-grid"></div>
  `;

  renderGrid(mount);

  mount.querySelector('#proj-search').addEventListener('input', (e) => { state.search = e.target.value; renderGrid(mount); });
  mount.querySelector('#proj-status').addEventListener('change', (e) => { state.status = e.target.value; renderGrid(mount); });
  mount.querySelector('#proj-ws').addEventListener('change', (e) => { state.workspace = e.target.value; renderGrid(mount); });
  mount.querySelector('#proj-new').addEventListener('click', () => toast('New project flow is mocked — use the existing 8 in the grid', { type: 'info' }));
}

/* ---------- Detail view ---------------------------------------- */

export function renderProjectDetail(mount, params = []) {
  const p = getProject(params[0]);
  if (!p) { mount.innerHTML = `<div class="empty"><h3>Project not found</h3><a class="btn btn-secondary" href="#projects">Back to projects</a></div>`; return; }
  const ws = getWorkspace(p.workspaceId);
  const scans = scansByProject(p.id);
  const findings = findingsByProject(p.id, SCANS);
  const counts = aggregateCounts(scans);

  let activeTab = 'overview';

  mount.innerHTML = `
    <div class="page-head">
      <div>
        <a href="#projects" class="text-dim text-sm row-sm"><i data-lucide="arrow-left" style="width:14px;height:14px;"></i> Back to projects</a>
        <h1 class="page-title mt-2">${p.name}</h1>
        <div class="row-sm mt-2">
          ${STATUS_CHIP[p.status]}
          <span class="chip chip-cat">${ws?.name || ''}</span>
          <code class="mono" style="font-size:12px;">${p.targetPackage}</code>
        </div>
      </div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm"><i data-lucide="edit"></i> Edit</button>
        <button class="btn btn-primary btn-sm" id="pd-scan"><i data-lucide="play"></i> Scan now</button>
      </div>
    </div>

    <div class="tabs mb-6" id="pd-tabs">
      <button class="tab is-active" data-tab="overview">Overview</button>
      <button class="tab" data-tab="scans">Scans <span class="text-mute">· ${scans.length}</span></button>
      <button class="tab" data-tab="findings">Findings <span class="text-mute">· ${findings.length}</span></button>
      <button class="tab" data-tab="scope">Scope</button>
      <button class="tab" data-tab="team">Team <span class="text-mute">· ${p.teamIds.length}</span></button>
      <button class="tab" data-tab="settings">Settings</button>
    </div>

    <div id="pd-tab-body"></div>
  `;

  const body = mount.querySelector('#pd-tab-body');

  function paint(tab) {
    activeTab = tab;
    mount.querySelectorAll('#pd-tabs .tab').forEach((t) => t.classList.toggle('is-active', t.dataset.tab === tab));

    if (tab === 'overview') {
      body.innerHTML = `
        <div class="grid-2 mb-6">
          <div class="card">
            <div class="card-title mb-4">Project metrics</div>
            <div class="grid-2" style="gap: var(--space-3);">
              ${[['scans', scans.length], ['findings', findings.length], ['critical', counts.critical], ['high', counts.high]].map(([k, v]) => `
                <div class="card-flat" style="padding: var(--space-3); text-align:center;">
                  <div style="font-size: var(--fs-2xl); font-weight:700;">${v}</div>
                  <div class="text-xs text-mute uppercase">${k}</div>
                </div>`).join('')}
            </div>
            <hr/>
            <div class="card-title mb-2">Severity distribution</div>
            ${severityChipsRow(counts)}
          </div>
          <div class="card">
            <div class="card-title mb-2">Description</div>
            <p>${p.description}</p>
            <hr/>
            <div class="card-title mb-2">Latest scan</div>
            ${scans[0] ? `
              <div class="text-dim text-sm">${scans[0].apkName} · ${relative(scans[0].startedAt)}</div>
              <div class="mt-2">${severityChipsRow(scans[0].counts)}</div>
              <a class="btn btn-ghost btn-sm mt-3" href="#history/${scans[0].id}"><i data-lucide="arrow-right"></i> Open detail</a>
            ` : '<p class="text-mute">No scans yet.</p>'}
          </div>
        </div>`;
    } else if (tab === 'scans') {
      body.innerHTML = `<div class="table-wrap"><table class="table">
        <thead><tr><th>Scan ID</th><th>APK</th><th>Findings</th><th>Started</th><th>Status</th></tr></thead>
        <tbody>
          ${scans.map((s) => `
            <tr onclick="location.hash='history/${s.id}'">
              <td><span class="mono" style="color:var(--accent-2); font-size:12px;">${s.id}</span></td>
              <td><code class="mono" style="font-size:12px;">${s.apkName}</code></td>
              <td>${severityChipsRow(s.counts)}</td>
              <td class="text-dim text-xs">${relative(s.startedAt)}</td>
              <td>${s.status}</td>
            </tr>`).join('')}
        </tbody></table></div>`;
    } else if (tab === 'findings') {
      renderFindingsTable(body, findings);
    } else if (tab === 'scope') {
      const sc = p.scope;
      body.innerHTML = `
        <div class="grid-2">
          <div class="card">
            <div class="card-title mb-3">Source</div>
            ${sc.url ? `<a href="${sc.url}" target="_blank" rel="noopener" class="row-sm"><i data-lucide="external-link" style="width:14px;height:14px;"></i> <span class="mono text-sm">${sc.url}</span></a>` : `<span class="chip chip-cat">${sc.source}</span>`}
            <hr/>
            <h6 class="mb-2">In-scope packages</h6>
            <ul class="scope-list">${sc.packages.map((x) => `<li>${x}</li>`).join('')}</ul>
            <h6 class="mt-4 mb-2">Domains</h6>
            <ul class="scope-list">${(sc.domains || []).map((x) => `<li>${x}</li>`).join('') || '<li class="text-mute" style="list-style:none;">none</li>'}</ul>
            <h6 class="mt-4 mb-2">Exclusions</h6>
            <ul class="scope-list">${(sc.exclusions || []).map((x) => `<li>${x}</li>`).join('') || '<li class="text-mute" style="list-style:none;">none</li>'}</ul>
          </div>
          <div class="card">
            <div class="card-title mb-3">Forbidden techniques</div>
            <ul class="scope-list">${(sc.forbidden || []).map((x) => `<li>${x}</li>`).join('') || '<li class="text-mute" style="list-style:none;">none specified</li>'}</ul>
            <hr/>
            <div class="card-title mb-3">Reward ranges</div>
            ${sc.rewards ? `<div class="grid-2" style="gap: var(--space-2);">
              ${Object.entries(sc.rewards).map(([k, v]) => `<div class="row-between"><span class="chip chip-sev-${k}">${k}</span> <span class="mono">${v}</span></div>`).join('')}
            </div>` : '<p class="text-mute">Not a paid program.</p>'}
          </div>
        </div>`;
    } else if (tab === 'team') {
      body.innerHTML = `<div class="card"><table class="table">
        <thead><tr><th>Member</th><th>Email</th><th>Role</th><th></th></tr></thead>
        <tbody>
          ${p.teamIds.map((id) => {
            const m = Object.values(MEMBERS).find((x) => x.id === id);
            const role = ws?.members.find((mm) => mm.id === id)?.role || 'Viewer';
            return `<tr>
              <td><div class="row-sm"><span class="avatar avatar-sm" style="background:${m.avatarColor};color:#0B0F1E;">${m.initials}</span> ${m.name}</div></td>
              <td class="text-dim text-sm">${m.email}</td>
              <td><span class="chip chip-cat">${role}</span></td>
              <td class="col-actions"><button class="btn btn-ghost btn-sm">Remove</button></td>
            </tr>`;
          }).join('')}
        </tbody></table>
        <div class="mt-4"><button class="btn btn-secondary btn-sm"><i data-lucide="user-plus"></i> Invite member</button></div>
      </div>`;
    } else if (tab === 'settings') {
      body.innerHTML = `
        <div class="card">
          <div class="card-title mb-4">Project name</div>
          <input class="input" value="${p.name}"/>
          <div class="card-title mt-6 mb-2">Description</div>
          <textarea class="textarea" rows="3">${p.description}</textarea>
          <div class="card-title mt-6 mb-2">Default LLM provider</div>
          <select class="select">
            <option ${p.llmPreference==='auto'?'selected':''}>Auto (Groq → Cerebras → Ollama)</option>
            <option ${p.llmPreference==='groq'?'selected':''}>Groq only</option>
            <option ${p.llmPreference==='cerebras'?'selected':''}>Cerebras only</option>
            <option ${p.llmPreference==='ollama'?'selected':''}>Ollama (local) — private</option>
          </select>
          <hr/>
          <div class="card-title mb-2">Danger zone</div>
          <p class="text-dim text-sm mb-3">Archiving a project hides it from all views but preserves its scans and findings.</p>
          <button class="btn btn-danger btn-sm"><i data-lucide="archive"></i> Archive project</button>
        </div>`;
    }
    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
  }
  paint(activeTab);

  mount.querySelectorAll('#pd-tabs .tab').forEach((btn) => btn.addEventListener('click', () => paint(btn.dataset.tab)));
  mount.querySelector('#pd-scan').addEventListener('click', () => openNewScanModal({ projectId: p.id }));
}
