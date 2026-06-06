// Sidebar component — navigation + collapse + mobile drawer
import { el, refreshIcons } from '../utils.js';

const NAV_GROUPS = [
  {
    title: 'Workspace',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: 'layout-dashboard', href: '#dashboard' },
      { id: 'scans',     label: 'Scans',     icon: 'shield-check',     href: '#scans', badge: '40' },
      { id: 'agents',    label: 'Agents',    icon: 'cpu',              href: '#agents', badge: '69' },
    ],
  },
  {
    title: 'Analyze',
    items: [
      { id: 'projects',  label: 'Projects',  icon: 'folder',           href: '#projects' },
      { id: 'reports',   label: 'Reports',   icon: 'file-text',        href: '#reports' },
      { id: 'history',   label: 'History',   icon: 'history',          href: '#history' },
    ],
  },
  {
    title: 'AI Platform',
    items: [
      { id: 'rag',       label: 'Knowledge', icon: 'library',          href: '#rag',     badge: '61' },
      { id: 'verify',    label: 'Verify',    icon: 'badge-check',      href: '#verify' },
      { id: 'exploit',   label: 'PoC',       icon: 'flame',            href: '#exploit' },
    ],
  },
  {
    title: 'Configure',
    items: [
      { id: 'settings',  label: 'Settings',  icon: 'settings',         href: '#settings' },
      { id: 'docs',      label: 'Docs',      icon: 'book-open',        href: '#docs' },
    ],
  },
];

export function renderSidebar(container, activeId = 'dashboard') {
  container.innerHTML = '';

  const logo = el('a', { class: 'sidebar-logo', href: '#dashboard' },
    el('span', { html: `
      <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
        <defs>
          <linearGradient id="lg1" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#00D4FF"/>
            <stop offset="100%" stop-color="#0099FF"/>
          </linearGradient>
        </defs>
        <path d="M16 2 L28 7 V17 C28 23 22.5 28 16 30 C9.5 28 4 23 4 17 V7 Z"
              fill="url(#lg1)" stroke="#00F0FF" stroke-width="1" opacity="0.95"/>
        <path d="M16 9 L12 14 L16 19 L20 14 Z M16 19 L12 24 L16 24 L20 24 Z" fill="#0A0E27"/>
      </svg>` }),
    el('span', { class: 'logo-text' }, 'SENTINEL'),
  );
  container.appendChild(logo);

  for (const group of NAV_GROUPS) {
    const section = el('div', { class: 'sidebar-section' });
    section.appendChild(el('div', { class: 'sidebar-section-title' }, group.title));
    const nav = el('nav', { class: 'sidebar-nav' });
    for (const item of group.items) {
      const link = el('a', {
        class: `sidebar-link ${item.id === activeId ? 'active' : ''}`,
        href: item.href,
        'data-route': item.id,
      },
        el('i', { 'data-lucide': item.icon }),
        el('span', { class: 'link-text' }, item.label),
        item.badge ? el('span', { class: 'link-badge' }, item.badge) : null,
      );
      nav.appendChild(link);
    }
    section.appendChild(nav);
    container.appendChild(section);
  }

  // Footer with workspace badge (no personal details)
  const footer = el('div', { class: 'sidebar-footer' });
  const user = el('div', { class: 'sidebar-user' },
    el('div', { class: 'avatar' },
      el('i', { 'data-lucide': 'user' }),
    ),
    el('div', { class: 'user-info' },
      el('div', { class: 'user-name' }, 'Local Workspace'),
      el('div', { class: 'user-email' }, 'Self-hosted'),
    ),
    el('i', { 'data-lucide': 'chevron-up' }),
  );
  footer.appendChild(user);
  container.appendChild(footer);

  refreshIcons();
}

export function setActiveSidebarLink(routeId) {
  document.querySelectorAll('.sidebar-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeId);
  });
}
