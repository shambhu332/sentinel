// Agents catalog page — primary source is the live /agents API (derived
// from the in-process Python class registry, so every CLI-runnable agent
// appears here automatically). Static AGENTS array is used as a fallback
// + as a source of enriched descriptions for IDs the API also exposes.
import { el, refreshIcons, debounce } from '../utils.js';
import { AGENTS as STATIC_AGENTS, CATEGORIES, PHASES, SEVERITIES } from '../data/agents.js';
import { api } from '../api.js';

let LIVE_AGENTS = STATIC_AGENTS;     // replaced once /agents responds
let CATALOG_SOURCE = 'static';       // 'static' | 'live' | 'merged'

let state = {
  q: '',
  categories: new Set(),
  severities: new Set(),
  phases: new Set(),
  expanded: new Set(),
};

function mergeWithStatic(liveList) {
  // The /agents endpoint emits {id, name, category, phase, severity,
  // description}. Static catalog has per-agent severities arrays +
  // richer descriptions. Merge so the UI keeps its severity dots while
  // still picking up every agent the live registry exposes.
  const staticById = new Map(STATIC_AGENTS.map(a => [a.id, a]));
  return liveList.map(a => {
    const fallback = staticById.get(a.id);
    return {
      id: a.id,
      name: a.name?.replace(/Agent$/, '') || (fallback?.name || a.id),
      vuln_class: fallback?.vuln_class || a.description?.split('.')[0] || '',
      phase: a.phase || fallback?.phase || 'Phase 2',
      category: (a.category || fallback?.category || 'other').toLowerCase().replace(/\s+/g, '-'),
      severities: fallback?.severities || ['info'],
      description: fallback?.description || a.description || '',
    };
  });
}

export function renderAgentsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Agents'),
      el('div', { class: 'page-subtitle', id: 'agents-subtitle' },
        `${LIVE_AGENTS.length} agents · loading live registry…`),
    ),
    el('div', { class: 'page-actions' },
      el('div', { class: 'search-input', style: 'min-width: 240px;' },
        el('i', { 'data-lucide': 'search' }),
        el('input', { type: 'text', placeholder: 'Search agents…',
          oninput: debounce((e) => { state.q = e.target.value.toLowerCase(); renderGrid(); }, 150) }),
      ),
    ),
  ));

  const layout = el('div', { class: 'agents-layout' });

  // Sidebar filters
  const sidebar = el('aside', { class: 'agents-sidebar' });
  sidebar.append(buildFilterSection('Category', CATEGORIES.map(c => ({ id: c.id, label: c.label })), 'categories'));
  sidebar.append(buildFilterSection('Severity', SEVERITIES.map(s => ({ id: s, label: s.charAt(0).toUpperCase() + s.slice(1) })), 'severities'));
  sidebar.append(buildFilterSection('Phase', PHASES.map(p => ({ id: p, label: p })), 'phases'));

  const clearBtn = el('button', { class: 'btn btn-ghost btn-sm', style: 'width: 100%; margin-top: 12px;' }, 'Clear filters');
  clearBtn.addEventListener('click', () => {
    state.categories.clear();
    state.severities.clear();
    state.phases.clear();
    sidebar.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
    renderGrid();
  });
  sidebar.appendChild(clearBtn);

  layout.appendChild(sidebar);
  layout.appendChild(el('div', { class: 'agents-grid', id: 'agents-grid' }));
  main.appendChild(layout);

  renderGrid();
  refreshIcons();

  // Fetch live registry. Failure is non-fatal — the static catalog
  // ships every agent that was known at frontend build time.
  api.listAgents().then(live => {
    if (!Array.isArray(live) || live.length === 0) return;
    LIVE_AGENTS = mergeWithStatic(live);
    CATALOG_SOURCE = 'live';
    const sub = document.getElementById('agents-subtitle');
    if (sub) sub.textContent = `${LIVE_AGENTS.length} agents (live registry) · ${CATEGORIES.length} categories`;
    renderGrid();
  }).catch(() => {
    const sub = document.getElementById('agents-subtitle');
    if (sub) sub.textContent = `${LIVE_AGENTS.length} agents (offline catalog) · ${CATEGORIES.length} categories`;
  });
}

function buildFilterSection(title, items, key) {
  const wrap = el('div');
  wrap.appendChild(el('h4', {}, title));
  items.forEach(item => {
    const label = el('label', { class: 'checkbox' },
      el('input', { type: 'checkbox', value: item.id }),
      item.label,
    );
    label.querySelector('input').addEventListener('change', (e) => {
      if (e.target.checked) state[key].add(item.id);
      else state[key].delete(item.id);
      renderGrid();
    });
    wrap.appendChild(label);
  });
  return wrap;
}

function renderGrid() {
  const grid = document.getElementById('agents-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const filtered = LIVE_AGENTS.filter(a => {
    if (state.q) {
      const txt = `${a.id} ${a.name} ${a.description} ${a.category}`.toLowerCase();
      if (!txt.includes(state.q)) return false;
    }
    if (state.categories.size > 0 && !state.categories.has(a.category)) return false;
    if (state.phases.size > 0 && !state.phases.has(a.phase)) return false;
    if (state.severities.size > 0) {
      const hit = a.severities.some(s => state.severities.has(s));
      if (!hit) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    grid.appendChild(el('div', { class: 'empty-state', style: 'grid-column: 1 / -1;' },
      el('i', { 'data-lucide': 'search-x' }),
      el('h3', {}, 'No agents match'),
      el('p', {}, 'Try clearing some filters.'),
    ));
    refreshIcons();
    return;
  }

  filtered.forEach(agent => grid.appendChild(buildAgentCard(agent)));
  refreshIcons();
}

function buildAgentCard(agent) {
  const card = el('div', { class: `agent-card ${state.expanded.has(agent.id) ? 'expanded' : ''}` });

  card.appendChild(el('div', { class: 'agent-head' },
    el('span', { class: 'agent-id-badge' }, agent.id),
    el('span', { class: 'badge sev-info badge-sm' }, agent.phase),
  ));

  card.appendChild(el('div', { class: 'agent-name' }, agent.name));

  card.appendChild(el('div', { class: 'agent-meta' },
    el('span', {}, agent.category),
    el('span', { style: 'opacity: 0.5;' }, '·'),
    el('span', { class: 'sev-list' },
      ...agent.severities.map(s => el('span', { class: `sev-dot sev-${s}`, 'data-tip': s })),
    ),
  ));

  card.appendChild(el('div', { class: 'agent-desc' }, agent.description));

  const toggleBtn = el('button', { class: 'toggle-more' },
    state.expanded.has(agent.id) ? 'Hide details' : 'More info',
    el('i', { 'data-lucide': state.expanded.has(agent.id) ? 'chevron-up' : 'chevron-down' }),
  );
  toggleBtn.addEventListener('click', () => {
    if (state.expanded.has(agent.id)) state.expanded.delete(agent.id);
    else state.expanded.add(agent.id);
    renderGrid();
  });

  const more = el('div', { class: 'agent-more' });
  more.append(
    el('h5', {}, 'Vulnerability class'),
    el('p', { class: 'mono', style: 'font-size: 12px;' }, agent.vuln_class || '—'),
    el('h5', {}, 'Description'),
    el('p', {}, agent.description || '—'),
    el('h5', {}, 'Phase'),
    el('p', { class: 'mono', style: 'font-size: 12px;' }, agent.phase || '—'),
    el('h5', {}, 'Severities'),
    el('p', { class: 'mono', style: 'font-size: 12px;' },
      (agent.severities || []).join(' · ') || '—'),
  );
  card.appendChild(toggleBtn);
  card.appendChild(more);
  return card;
}
