/**
 * topbar.js — sticky topbar with breadcrumb, search, notifications,
 * help, and the "+ New scan" CTA that opens the New Scan modal.
 */

import { toggleSidebarDrawer } from './sidebar.js';
import { openNewScanModal } from './scan-runner.js';

const VIEW_LABELS = {
  dashboard:    'Dashboard',
  projects:     'Projects',
  history:      'Scan history',
  reports:      'Reports',
  agents:       'Agents',
  architecture: 'Architecture',
  workspaces:   'Workspaces',
  settings:     'Settings',
  demo:         'Demo',
};

export function renderTopbar(mount) {
  mount.innerHTML = `
    <header class="topbar" id="topbar">
      <button class="btn-icon" id="drawer-toggle" aria-label="Open menu" style="display:none;">
        <i data-lucide="menu"></i>
      </button>

      <div class="topbar-breadcrumb">
        <i data-lucide="chevron-right" style="width:14px;height:14px;color: var(--text-mute);"></i>
        <strong id="topbar-view-label">Dashboard</strong>
      </div>

      <div class="topbar-search input-search" style="min-width:220px;">
        <i data-lucide="search"></i>
        <input class="input" id="topbar-search" placeholder="Search scans, projects, findings…" />
      </div>

      <div class="topbar-actions">
        <button class="btn-icon topbar-badge" data-count="3" aria-label="Notifications">
          <i data-lucide="bell"></i>
        </button>
        <button class="btn-icon" aria-label="Help">
          <i data-lucide="help-circle"></i>
        </button>
        <button class="btn btn-primary btn-sm" id="new-scan-btn">
          <i data-lucide="plus"></i> New scan
        </button>
      </div>
    </header>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  /* Mobile drawer toggle visibility */
  const drawer = mount.querySelector('#drawer-toggle');
  const updateDrawerVis = () => {
    drawer.style.display = window.matchMedia('(max-width: 768px)').matches ? 'inline-flex' : 'none';
  };
  updateDrawerVis();
  window.addEventListener('resize', updateDrawerVis);
  drawer.addEventListener('click', toggleSidebarDrawer);

  mount.querySelector('#new-scan-btn').addEventListener('click', () => openNewScanModal());
}

/** Update the breadcrumb label when the route changes. */
export function setTopbarView(viewName) {
  const el = document.getElementById('topbar-view-label');
  if (el) el.textContent = VIEW_LABELS[viewName] || viewName;
}
