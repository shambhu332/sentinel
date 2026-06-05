// Topbar component — breadcrumb, search, notifications, user menu
import { el, refreshIcons } from '../utils.js';

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

  const actions = el('div', { class: 'topbar-actions' },
    el('button', { class: 'topbar-action', 'data-tip': 'Notifications' },
      el('i', { 'data-lucide': 'bell' }),
      el('span', { class: 'notif-dot' }),
    ),
    el('button', { class: 'topbar-action', 'data-tip': 'New Scan', id: 'topbar-new-scan' },
      el('i', { 'data-lucide': 'plus-circle' }),
    ),
    el('button', { class: 'topbar-action', 'data-tip': 'Help' },
      el('i', { 'data-lucide': 'help-circle' }),
    ),
  );

  container.append(toggle, breadcrumb, spacer, search, actions);
  refreshIcons();
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
