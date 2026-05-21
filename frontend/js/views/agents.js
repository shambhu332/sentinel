/**
 * agents.js — full catalogue view.
 * Left filter sidebar (search, category, severity, phase) +
 * dense agent card grid with expandable details.
 */

import { AGENTS, CATEGORIES, SEVERITY_ORDER, PHASES } from '../data/agents.js';
import { severityDot } from '../components/severity-chip.js';

const state = {
  search:   '',
  cats:     new Set(),
  sevs:     new Set(),
  phases:   new Set(),
  expanded: new Set(),
};

function escape(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function matches(a) {
  if (state.search) {
    const q = state.search.toLowerCase();
    const hay = `${a.id} ${a.name} ${a.category} ${a.description} ${a.detects}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  if (state.cats.size   && !state.cats.has(a.category)) return false;
  if (state.sevs.size   && !a.severity.some((s) => state.sevs.has(s))) return false;
  if (state.phases.size && !state.phases.has(a.phase)) return false;
  return true;
}

function renderGrid(mount) {
  const grid = mount.querySelector('#agents-grid');
  const list = AGENTS.filter(matches);
  if (!list.length) {
    grid.innerHTML = `<div class="empty"><i data-lucide="search-x"></i><h3>No agents match</h3><p>Loosen the filter to see more.</p></div>`;
    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
    return;
  }
  grid.innerHTML = list.map((a) => {
    const isExp = state.expanded.has(a.id);
    return `
      <article class="agent-card" data-agent="${a.id}">
        <div class="agent-card-head">
          <span class="agent-id">${a.id}</span>
          <span class="chip chip-phase">${a.phase}</span>
        </div>
        <div class="row-between">
          <div class="agent-name">${a.name}</div>
          <span class="chip chip-cat">${a.category}</span>
        </div>
        <p class="agent-desc">${escape(a.description)}</p>
        <div class="agent-meta">
          <div class="row-sm">
            ${a.severity.map((s) => severityDot(s)).join('')}
            <span class="text-xs text-mute">${a.severity.join(' → ')}</span>
          </div>
          <button class="btn btn-ghost btn-sm" data-expand>${isExp ? 'Hide details' : 'Show details'}</button>
        </div>
        ${isExp ? `
          <div class="card-flat mt-4" style="padding: var(--space-4); background: var(--surface-2);">
            <h6 class="mb-2">What it detects</h6>
            <p class="text-sm">${escape(a.detects)}</p>

            <h6 class="mt-4 mb-2">Sample finding</h6>
            <pre><code>${escape(a.sampleFinding)}</code></pre>

            <h6 class="mt-4 mb-2">Key heuristics</h6>
            <ul class="text-sm" style="padding-left: var(--space-5);">
              ${a.heuristics.map((h) => `<li style="list-style:disc;">${escape(h)}</li>`).join('')}
            </ul>

            <h6 class="mt-4 mb-2">False-positive notes</h6>
            <div class="row-sm mb-2">
              <span class="chip chip-cat">FP rate: ${a.fpRate}</span>
            </div>
            <p class="text-sm text-dim">${escape(a.fpNotes)}</p>

            <div class="mt-4">
              <a class="btn btn-secondary btn-sm" href="#history">
                <i data-lucide="external-link"></i> View findings produced by this agent
              </a>
            </div>
          </div>
        ` : ''}
      </article>`;
  }).join('');

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  grid.querySelectorAll('[data-expand]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const card = btn.closest('[data-agent]');
      const id = card.dataset.agent;
      if (state.expanded.has(id)) state.expanded.delete(id);
      else                        state.expanded.add(id);
      renderGrid(mount);
    });
  });
}

export function renderAgents(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Agents</h1>
        <div class="page-sub">All ${AGENTS.length} analysis agents · 14 SAST · 3 DAST · 2 meta · 1 Frida runtime</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm" id="agents-reset"><i data-lucide="rotate-ccw"></i> Reset filters</button>
      </div>
    </div>

    <div class="agents-layout">
      <aside class="filter-sidebar">
        <div class="input-search mb-4">
          <i data-lucide="search"></i>
          <input class="input" id="agents-search" placeholder="Search agents…"/>
        </div>

        <div class="filter-group">
          <h6>Category</h6>
          ${CATEGORIES.map((c) => `<label class="checkbox"><input type="checkbox" data-cat="${c}"/> ${c}</label>`).join('<br>')}
        </div>

        <div class="filter-group">
          <h6>Severity</h6>
          ${SEVERITY_ORDER.map((s) => `<label class="checkbox"><input type="checkbox" data-sev="${s}"/> ${severityDot(s)} ${s}</label>`).join('<br>')}
        </div>

        <div class="filter-group">
          <h6>Phase</h6>
          ${PHASES.map((p) => `<label class="checkbox"><input type="checkbox" data-phase="${p}"/> ${p}</label>`).join('<br>')}
        </div>
      </aside>

      <div class="grid" id="agents-grid" style="grid-template-columns: repeat(2, 1fr);"></div>
    </div>
  `;

  /* Responsive grid: collapse to 1 col on narrow */
  const grid = mount.querySelector('#agents-grid');
  const adjustGrid = () => {
    grid.style.gridTemplateColumns = window.innerWidth < 900 ? '1fr' : 'repeat(2, 1fr)';
  };
  adjustGrid();
  window.addEventListener('resize', adjustGrid);

  renderGrid(mount);

  mount.querySelector('#agents-search').addEventListener('input', (e) => { state.search = e.target.value; renderGrid(mount); });
  mount.querySelectorAll('[data-cat]').forEach((cb) => cb.addEventListener('change', () => {
    const v = cb.dataset.cat;
    if (cb.checked) state.cats.add(v); else state.cats.delete(v);
    renderGrid(mount);
  }));
  mount.querySelectorAll('[data-sev]').forEach((cb) => cb.addEventListener('change', () => {
    const v = cb.dataset.sev;
    if (cb.checked) state.sevs.add(v); else state.sevs.delete(v);
    renderGrid(mount);
  }));
  mount.querySelectorAll('[data-phase]').forEach((cb) => cb.addEventListener('change', () => {
    const v = cb.dataset.phase;
    if (cb.checked) state.phases.add(v); else state.phases.delete(v);
    renderGrid(mount);
  }));
  mount.querySelector('#agents-reset').addEventListener('click', () => {
    state.search = ''; state.cats.clear(); state.sevs.clear(); state.phases.clear(); state.expanded.clear();
    renderAgents(mount);
  });
}
