// Topbar component — breadcrumb, search, notifications, user menu
import { el, refreshIcons } from '../utils.js';
import { API_BASE } from '../api.js';

export function renderTopbar(container) {
  container.innerHTML = '';

  const toggle = el('button', { class: 'topbar-toggle', id: 'sidebar-toggle', 'aria-label': 'Toggle sidebar' },
    el('i', { 'data-lucide': 'menu' }),
  );

  const breadcrumb = el('nav', { class: 'breadcrumb', id: 'breadcrumb' },
    el('a', { href: '#dashboard' }, 'SENTINEL'),
    el('span', { class: 'crumb-divider' }, '/'),
    el('span', { class: 'crumb-current' }, 'Dashboard'),
  );

  const spacer = el('div', { class: 'topbar-spacer' });

  const search = el('div', { class: 'search-input topbar-search' },
    el('i', { 'data-lucide': 'search' }),
    el('input', { type: 'text', placeholder: 'Search scans, findings, agents…' }),
  );

  // Connection status pill — clicks straight through to Settings ▸ Connection
  const statusPill = el('a', {
    class: 'topbar-status topbar-status-unknown',
    id: 'topbar-status',
    href: '#settings',
    'data-tip': 'Open Settings ▸ Connection',
  },
    el('span', { class: 'topbar-status-dot' }),
    el('span', { class: 'topbar-status-text' }, 'checking…'),
  );

  const actions = el('div', { class: 'topbar-actions' },
    statusPill,
    el('button', { class: 'topbar-action', 'data-tip': 'Notifications', 'aria-label': 'Notifications' },
      el('i', { 'data-lucide': 'bell' }),
      el('span', { class: 'notif-dot' }),
    ),
    el('button', { class: 'topbar-action', 'data-tip': 'New Scan', id: 'topbar-new-scan', 'aria-label': 'New scan' },
      el('i', { 'data-lucide': 'plus-circle' }),
    ),
    el('button', { class: 'topbar-action', 'data-tip': 'Help', 'aria-label': 'Help' },
      el('i', { 'data-lucide': 'help-circle' }),
    ),
  );

  container.append(toggle, breadcrumb, spacer, search, actions);
  refreshIcons();

  // Begin polling /health every 30s.
  pollHealth();
}

// ---------- /health poller ----------

let _healthTimer = null;

async function pollHealth() {
  await tickHealth();
  if (_healthTimer) clearInterval(_healthTimer);
  _healthTimer = setInterval(tickHealth, 30_000);
}

async function tickHealth() {
  const pill = document.getElementById('topbar-status');
  if (!pill) return;
  const text = pill.querySelector('.topbar-status-text');
  try {
    const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
    if (!res.ok) {
      pill.className = 'topbar-status topbar-status-error';
      pill.setAttribute('data-tip', `Gateway returned ${res.status}. Click to configure.`);
      if (text) text.textContent = `HTTP ${res.status}`;
      return;
    }
    pill.className = 'topbar-status topbar-status-ok';
    pill.setAttribute('data-tip', `API online — ${API_BASE}`);
    if (text) text.textContent = 'API online';
  } catch (_) {
    pill.className = 'topbar-status topbar-status-error';
    pill.setAttribute('data-tip', `Cannot reach ${API_BASE}. Click to configure.`);
    if (text) text.textContent = 'API offline';
  }
}

export function setBreadcrumb(crumbs) {
  const bc = document.getElementById('breadcrumb');
  if (!bc) return;
  bc.innerHTML = '';
  bc.appendChild(el('a', { href: '#dashboard' }, 'SENTINEL'));
  crumbs.forEach((c, i) => {
    bc.appendChild(el('span', { class: 'crumb-divider' }, '/'));
    if (i === crumbs.length - 1) {
      bc.appendChild(el('span', { class: 'crumb-current' }, c.label));
    } else {
      bc.appendChild(el('a', { href: c.href || '#' }, c.label));
    }
  });
}
