/**
 * history.js — Scan history view (table + scan detail sheet).
 *
 * Filters bar · bulk action bar · paginated scan table · slide-over
 * sheet with Summary / Findings / Frida events / Raw JSON / Warnings.
 */

import { SCANS, getScan } from '../data/scans.js';
import { PROJECTS, getProject } from '../data/projects.js';
import { findingsByScan } from '../data/findings.js';
import { severityChipsRow } from '../components/severity-chip.js';
import { triageChip } from '../components/triage-chip.js';
import { renderFindingsTable } from '../components/findings-table.js';
import { openSheet } from '../components/modal.js';
import { toast } from '../components/toast.js';

const PAGE_SIZES = [10, 25, 50];

const STATUS_CHIP = {
  completed: '<span class="chip chip-status-completed">completed</span>',
  running:   '<span class="chip chip-status-running"><span class="sev-dot sev-dot-medium pulse-ring"></span> running</span>',
  failed:    '<span class="chip chip-status-failed">failed</span>',
};

const PHASE_KEYS = ['p0', 'p1', 'p2', 'p3', 'p4', 'p4_5'];

function phaseDots(phases) {
  return `<span class="phase-dots">${PHASE_KEYS.map((k) => {
    const v = phases[k];
    const cls = v === 'ok' ? 'sev-dot-low'      // blue dot for OK is too generic — recolor below
              : v === 'skipped' ? 'sev-dot-skipped'
              : v === 'failed'  ? 'sev-dot-failed'
              : v === 'running' ? 'sev-dot-medium pulse-ring'
              : 'sev-dot-info';
    /* Use green for ok */
    const style = v === 'ok' ? 'background: var(--triage-verified); box-shadow: 0 0 8px rgba(16,185,129,0.45);' : '';
    return `<span class="sev-dot ${cls}" style="${style}" title="${k}: ${v}"></span>`;
  }).join('')}</span>`;
}

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

function fmtDuration(s) {
  if (!s) return '—';
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

const state = {
  search:    '',
  project:   'all',
  status:    'all',
  page:      1,
  pageSize:  10,
  selected:  new Set(),
};

function filtered() {
  return SCANS.filter((s) => {
    if (state.project !== 'all' && s.projectId !== state.project) return false;
    if (state.status  !== 'all' && s.status    !== state.status)  return false;
    if (state.search) {
      const q = state.search.toLowerCase();
      const p = getProject(s.projectId);
      const hay = `${s.id} ${s.apkName} ${p?.name || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => (b.startedAt > a.startedAt ? 1 : -1));
}

function renderTable(mount) {
  const list = filtered();
  const start = (state.page - 1) * state.pageSize;
  const slice = list.slice(start, start + state.pageSize);
  const totalPages = Math.max(1, Math.ceil(list.length / state.pageSize));

  const tbody = slice.map((s) => {
    const p = getProject(s.projectId);
    const isSel = state.selected.has(s.id);
    return `
      <tr data-scan="${s.id}" class="${isSel ? 'is-selected' : ''}">
        <td class="table-checkbox" onclick="event.stopPropagation();">
          <label class="checkbox"><input type="checkbox" data-row-check ${isSel ? 'checked' : ''}/></label>
        </td>
        <td><span class="mono" style="font-size:12px; color: var(--accent-2);">${s.id}</span></td>
        <td>${p?.name || '—'}</td>
        <td>
          <code class="mono" style="font-size:12px;">${s.apkName}</code>
          <div class="text-xs text-mute">${s.apkSize} MB</div>
        </td>
        <td>${phaseDots(s.phases)}</td>
        <td>${severityChipsRow(s.counts)}</td>
        <td class="text-dim text-xs" title="${s.startedAt}">${relative(s.startedAt)}</td>
        <td class="text-dim text-xs">${fmtDuration(s.duration)}</td>
        <td>${STATUS_CHIP[s.status]}</td>
        <td class="col-actions" onclick="event.stopPropagation();">
          <button class="btn-icon" aria-label="Row actions"><i data-lucide="more-vertical"></i></button>
        </td>
      </tr>`;
  }).join('');

  const tbl = mount.querySelector('#hist-table tbody');
  tbl.innerHTML = tbody || `<tr><td colspan="10"><div class="empty"><i data-lucide="search-x"></i><h3>No scans match</h3><p>Adjust filters above.</p></div></td></tr>`;

  /* Pagination */
  const pag = mount.querySelector('#hist-pagination');
  pag.innerHTML = `
    <span class="text-dim text-sm">${list.length ? `${start + 1}–${Math.min(start + state.pageSize, list.length)} of ${list.length}` : '0 of 0'}</span>
    <select class="select" id="hist-pagesize" style="width:auto;">
      ${PAGE_SIZES.map((n) => `<option value="${n}" ${n === state.pageSize ? 'selected' : ''}>${n} / page</option>`).join('')}
    </select>
    <div class="row-sm">
      <button class="btn btn-ghost btn-sm" id="hist-prev" ${state.page === 1 ? 'disabled' : ''}><i data-lucide="chevron-left"></i></button>
      <span class="text-sm mono">${state.page} / ${totalPages}</span>
      <button class="btn btn-ghost btn-sm" id="hist-next" ${state.page === totalPages ? 'disabled' : ''}><i data-lucide="chevron-right"></i></button>
    </div>
  `;

  /* Bulk bar */
  const bulk = mount.querySelector('#hist-bulk');
  if (state.selected.size) {
    bulk.classList.remove('hidden');
    bulk.querySelector('.bulk-bar-count').textContent = `${state.selected.size} selected`;
  } else {
    bulk.classList.add('hidden');
  }

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  /* Bind row interactions */
  tbl.querySelectorAll('tr[data-scan]').forEach((row) => {
    row.addEventListener('click', () => openScanSheet(row.dataset.scan));
    const cb = row.querySelector('[data-row-check]');
    if (cb) cb.addEventListener('change', () => {
      const id = row.dataset.scan;
      if (cb.checked) state.selected.add(id);
      else state.selected.delete(id);
      renderTable(mount);
    });
  });
  mount.querySelector('#hist-pagesize').addEventListener('change', (e) => { state.pageSize = +e.target.value; state.page = 1; renderTable(mount); });
  mount.querySelector('#hist-prev').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); renderTable(mount); });
  mount.querySelector('#hist-next').addEventListener('click', () => { state.page = Math.min(totalPages, state.page + 1); renderTable(mount); });
}

/* ---------- Detail sheet (Summary / Findings / Frida / JSON) ---- */

function highlightJson(obj) {
  const json = JSON.stringify(obj, null, 2);
  return json
    .replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))
    .replace(/"([^"\\]+)":/g, '<span class="k">"$1"</span>:')
    .replace(/: "([^"\\]*)"/g, ': <span class="s">"$1"</span>')
    .replace(/: (-?\d+(\.\d+)?)/g, ': <span class="n">$1</span>')
    .replace(/: (true|false|null)/g, ': <span class="b">$1</span>');
}

export function openScanSheet(scanId) {
  const s = getScan(scanId);
  if (!s) { toast('Scan not found', { type: 'error' }); return; }
  const p = getProject(s.projectId);

  const sheet = openSheet({
    title: `Scan ${s.id}`,
    subtitle: `${p?.name || ''} · ${s.apkName} · ${s.startedAt}`,
    body: `
      <div class="tabs mb-6" id="sheet-tabs">
        <button class="tab is-active" data-tab="summary">Summary</button>
        <button class="tab" data-tab="findings">Findings</button>
        ${s.fridaEvents ? '<button class="tab" data-tab="frida">Frida events</button>' : ''}
        <button class="tab" data-tab="json">Raw JSON</button>
        <button class="tab" data-tab="warnings">Warnings</button>
      </div>
      <div id="sheet-tab-body"></div>
    `,
    actions: `
      <button class="btn btn-ghost btn-sm" id="sheet-rerun"><i data-lucide="refresh-cw"></i> Re-run</button>
      <button class="btn btn-secondary btn-sm" id="sheet-report"><i data-lucide="file-text"></i> Open report</button>
    `,
    width: 760,
  });

  const root = sheet.el;
  const body = root.querySelector('#sheet-tab-body');

  function paint(tab) {
    root.querySelectorAll('[data-tab]').forEach((t) => t.classList.toggle('is-active', t.dataset.tab === tab));

    if (tab === 'summary') {
      body.innerHTML = `
        <div class="grid-2 mb-6">
          <div class="card">
            <div class="card-title mb-2">Phase timings</div>
            <table class="table" style="font-size:13px;">
              <tbody>
                ${Object.entries(s.phaseTimings).map(([k, v]) => `<tr><td class="mono" style="color: var(--accent-2);">${k}</td><td>${v.toFixed(1)}s</td></tr>`).join('')}
              </tbody>
            </table>
          </div>
          <div class="card">
            <div class="card-title mb-2">Severity totals</div>
            <div class="stack-sm">
              ${[['critical','Critical'],['high','High'],['medium','Medium'],['low','Low'],['info','Info']].map(([k, label]) => `
                <div class="row-between">
                  <span class="row-sm"><span class="sev-dot sev-dot-${k}"></span> ${label}</span>
                  <span class="mono">${s.counts[k]}</span>
                </div>`).join('')}
            </div>
            <hr/>
            <div class="card-title mb-2">Triage</div>
            <div class="row gap-2 row-wrap">
              ${Object.entries(s.triageBreakdown).map(([k, v]) => `${triageChip(k)} <span class="text-dim text-xs">${v}</span>`).join(' · ')}
            </div>
          </div>
        </div>
      `;
    } else if (tab === 'findings') {
      const list = findingsByScan(s.id);
      renderFindingsTable(body, list);
    } else if (tab === 'frida') {
      const ev = s.fridaEvents || [];
      body.innerHTML = `
        <div class="card">
          <div class="card-title mb-4">Frida event timeline</div>
          <table class="table">
            <thead><tr><th>ts</th><th>Library</th><th>Method</th><th>Outcome</th><th>Payload</th></tr></thead>
            <tbody>
              ${ev.map((e) => `
                <tr>
                  <td class="mono text-xs">${e.ts}</td>
                  <td>${e.library}</td>
                  <td class="mono text-xs">${e.method}</td>
                  <td>${outcomeBadge(e.outcome)}</td>
                  <td class="text-dim text-xs">${e.payload || ''}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>`;
    } else if (tab === 'json') {
      body.innerHTML = `<pre class="json-block">${highlightJson(s)}</pre>`;
    } else if (tab === 'warnings') {
      if (!s.warnings?.length) {
        body.innerHTML = `<div class="empty"><i data-lucide="check-circle-2"></i><h3>No warnings</h3><p>Scan completed cleanly.</p></div>`;
      } else {
        body.innerHTML = `<div class="stack">${s.warnings.map((w) => `
          <div class="card row-sm" style="gap: var(--space-3); border-color: rgba(251,191,36,0.30);">
            <i data-lucide="alert-triangle" style="color: var(--sev-medium); width:18px;height:18px;"></i>
            <span>${w}</span>
          </div>`).join('')}</div>`;
      }
    }

    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
  }

  paint('summary');
  root.querySelectorAll('[data-tab]').forEach((btn) => btn.addEventListener('click', () => paint(btn.dataset.tab)));
  root.querySelector('#sheet-rerun').addEventListener('click', () => { toast('Re-queueing scan (demo)', { type: 'info' }); sheet.close(); });
  root.querySelector('#sheet-report').addEventListener('click', () => { sheet.close(); location.hash = 'reports'; });
}

function outcomeBadge(o) {
  if (o === 'bypass_success') return '<span class="chip chip-sev-high">bypass_success</span>';
  if (o === 'survived')       return '<span class="chip chip-triage-verified">survived</span>';
  if (o === 'absent')         return '<span class="chip chip-cat">absent</span>';
  if (o === 'observed')       return '<span class="chip chip-sev-medium">observed</span>';
  return `<span class="chip chip-cat">${o}</span>`;
}

/* ---------- Top-level view render -------------------------------- */

export function renderHistory(mount, params = []) {
  /* If a scan id was passed via #history/<id>, open the sheet on mount */
  const openId = params?.[0];

  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Scan history</h1>
        <div class="page-sub">${SCANS.length} total scans across ${PROJECTS.length} projects</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm"><i data-lucide="download"></i> Export CSV</button>
      </div>
    </div>

    <div class="filters-bar">
      <div class="input-search" style="flex:1;">
        <i data-lucide="search"></i>
        <input class="input" id="hist-search" placeholder="Search by scan id, APK, project…"/>
      </div>
      <select class="select" id="hist-project">
        <option value="all">All projects</option>
        ${PROJECTS.map((p) => `<option value="${p.id}">${p.name}</option>`).join('')}
      </select>
      <select class="select" id="hist-status">
        <option value="all">All statuses</option>
        <option value="completed">Completed</option>
        <option value="running">Running</option>
        <option value="failed">Failed</option>
      </select>
      <button class="btn btn-ghost btn-sm"><i data-lucide="calendar"></i> Date range</button>
    </div>

    <div class="bulk-bar hidden" id="hist-bulk">
      <span class="bulk-bar-count">0 selected</span>
      <div class="row-sm" style="margin-left:auto;">
        <button class="btn btn-ghost btn-sm"><i data-lucide="download"></i> Export CSV</button>
        <button class="btn btn-ghost btn-sm"><i data-lucide="file-text"></i> Generate report</button>
        <button class="btn btn-danger btn-sm"><i data-lucide="trash-2"></i> Delete</button>
      </div>
    </div>

    <div class="table-wrap">
      <table class="table" id="hist-table">
        <thead>
          <tr>
            <th class="table-checkbox"><label class="checkbox"><input type="checkbox" id="hist-check-all"/></label></th>
            <th>Scan ID</th>
            <th>Project</th>
            <th>APK</th>
            <th>Phases</th>
            <th>Findings</th>
            <th>Started</th>
            <th>Duration</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="row-between mt-4" id="hist-pagination"></div>
  `;

  renderTable(mount);

  /* Filter inputs */
  mount.querySelector('#hist-search').addEventListener('input', (e) => { state.search = e.target.value; state.page = 1; renderTable(mount); });
  mount.querySelector('#hist-project').addEventListener('change', (e) => { state.project = e.target.value; state.page = 1; renderTable(mount); });
  mount.querySelector('#hist-status').addEventListener('change', (e) => { state.status = e.target.value; state.page = 1; renderTable(mount); });
  mount.querySelector('#hist-check-all').addEventListener('change', (e) => {
    const list = filtered().slice((state.page - 1) * state.pageSize, state.page * state.pageSize);
    if (e.target.checked) list.forEach((s) => state.selected.add(s.id));
    else                  list.forEach((s) => state.selected.delete(s.id));
    renderTable(mount);
  });

  if (openId) setTimeout(() => openScanSheet(openId), 200);
}
