// Agents catalog page
import { el, refreshIcons, debounce } from '../utils.js';
import { AGENTS, CATEGORIES, PHASES, SEVERITIES } from '../data/agents.js';

let state = {
  q: '',
  categories: new Set(),
  severities: new Set(),
  phases: new Set(),
  expanded: new Set(),
};

export function renderAgentsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Agents'),
      el('div', { class: 'page-subtitle' }, `${AGENTS.length} specialized agents across ${CATEGORIES.length} categories`),
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

  const filtered = AGENTS.filter(a => {
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
    el('h5', {}, 'What it detects'),
    el('p', {}, agent.detects),
    el('h5', {}, 'Example finding'),
    el('p', { class: 'mono', style: 'font-size: 12px; color: var(--text-muted);' }, agent.example),
    el('h5', {}, 'False-positive rate'),
    el('p', {}, agent.fpRate),
    el('h5', {}, 'Key heuristics'),
    el('ul', { style: 'list-style: disc; padding-left: 20px;' },
      ...agent.heuristics.map(h => el('li', { class: 'mono text-secondary', style: 'font-size: 12px; margin: 2px 0;' }, h)),
    ),
  );
  card.appendChild(toggleBtn);
  card.appendChild(more);
  return card;
}
