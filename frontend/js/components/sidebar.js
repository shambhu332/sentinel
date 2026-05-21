/**
 * sidebar.js — renders the app shell sidebar and handles nav state.
 *
 * Exports:
 *   renderSidebar(mountEl, { currentWorkspaceId, onWorkspaceSwitch })
 *   setActiveNav(viewName)
 */

import { WORKSPACES } from '../data/workspaces.js';

const NAV = [
  { view: 'dashboard',    label: 'Dashboard',     icon: 'layout-dashboard' },
  { view: 'projects',     label: 'Projects',      icon: 'folder-kanban' },
  { view: 'history',      label: 'Scan history',  icon: 'history' },
  { view: 'reports',      label: 'Reports',       icon: 'file-text' },
  { view: 'agents',       label: 'Agents',        icon: 'bot' },
  { view: 'architecture', label: 'Architecture',  icon: 'network' },
  { view: 'workspaces',   label: 'Workspaces',    icon: 'users' },
  { view: 'settings',     label: 'Settings',      icon: 'settings' },
];

export function renderSidebar(mount, { currentWorkspaceId = 'ws_personal', onWorkspaceSwitch } = {}) {
  const ws = WORKSPACES.find((w) => w.id === currentWorkspaceId) || WORKSPACES[0];

  mount.innerHTML = `
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <a class="sidebar-logo" href="./index.html" aria-label="SENTINEL home">
          <img src="./assets/logo.svg" alt="" width="24" height="24"/>
          <span class="sidebar-label">SENTINEL</span>
        </a>
      </div>

      <button class="workspace-switcher" id="workspace-switcher" aria-haspopup="listbox">
        <span class="row-sm">
          <i data-lucide="layers" style="width:14px;height:14px;"></i>
          <span class="workspace-name sidebar-label">${ws.name}</span>
        </span>
        <i data-lucide="chevrons-up-down" style="width:14px;height:14px;color: var(--text-mute);"></i>
      </button>
      <div class="dropdown" id="workspace-dropdown" style="position:relative;">
        <div class="dropdown-menu" style="left:12px; right:12px; top:0; position:absolute;">
          ${WORKSPACES.map((w) => `
            <button class="dropdown-item" data-ws="${w.id}">
              <i data-lucide="${w.id === currentWorkspaceId ? 'check' : 'circle'}" style="width:14px;height:14px;"></i>
              <span>${w.name}</span>
              <span class="text-xs text-mute" style="margin-left:auto;">${w.members.length} member${w.members.length>1?'s':''}</span>
            </button>
          `).join('')}
        </div>
      </div>

      <nav class="sidebar-nav" aria-label="Primary">
        ${NAV.map((n) => `
          <a class="nav-item" href="#${n.view}" data-view="${n.view}">
            <i data-lucide="${n.icon}"></i>
            <span class="sidebar-label">${n.label}</span>
          </a>
        `).join('')}
      </nav>

      <div class="sidebar-footer">
        <div class="user-card">
          <span class="avatar" aria-hidden="true">NK</span>
          <div class="sidebar-label user-card-meta" style="flex:1; min-width:0;">
            <div style="font-weight:600; font-size: var(--fs-sm);">Nehal</div>
            <div class="text-xs text-mute">${ws.name}</div>
          </div>
        </div>
        <button class="btn btn-ghost btn-sm btn-block sidebar-label">
          <i data-lucide="log-out"></i> Sign out
        </button>
      </div>
    </aside>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  /* Workspace dropdown toggle */
  const wsBtn  = mount.querySelector('#workspace-switcher');
  const wsDrop = mount.querySelector('#workspace-dropdown');
  wsBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    wsDrop.classList.toggle('is-open');
  });
  document.addEventListener('click', () => wsDrop.classList.remove('is-open'));
  wsDrop.querySelectorAll('[data-ws]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.ws;
      wsDrop.classList.remove('is-open');
      onWorkspaceSwitch?.(id);
    });
  });
}

/** Highlight the active nav row by view name. */
export function setActiveNav(viewName) {
  const root = document.getElementById('sidebar');
  if (!root) return;
  root.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('is-active', el.dataset.view === viewName);
  });
}

/** Toggle the collapsed/mini state (icon-only). */
export function toggleSidebarMini() {
  document.getElementById('sidebar')?.classList.toggle('is-mini');
}

/** Toggle the mobile drawer state. */
export function toggleSidebarDrawer() {
  document.getElementById('sidebar')?.classList.toggle('is-drawer-open');
}
