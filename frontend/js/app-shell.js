// App shell — sidebar + topbar + router bootstrap
import { renderSidebar } from './components/sidebar.js';
import { renderTopbar } from './components/topbar.js';
import { initRouter, registerRoute } from './router.js';
import { openScanModal } from './components/scan-modal.js';

import { renderDashboard }     from './pages/dashboard.js';
import { renderScansPage }     from './pages/scans.js';
import { renderScanDetail }    from './pages/scan-detail.js';
import { renderAgentsPage }    from './pages/agents.js';
import { renderSettingsPage }  from './pages/settings.js';
import { renderProjectsPage }  from './pages/projects.js';
import { renderReportsPage }   from './pages/reports.js';
import { renderHistoryPage }   from './pages/history.js';
import { renderDevicesPage }   from './pages/devices.js';

document.addEventListener('DOMContentLoaded', () => {
  const shell = document.getElementById('app-shell');
  renderSidebar(document.getElementById('sidebar'), parseInitialRoute());
  renderTopbar(document.getElementById('topbar'));

  // Sidebar toggle
  const toggle = document.getElementById('sidebar-toggle');
  toggle.addEventListener('click', () => {
    if (window.matchMedia('(max-width: 768px)').matches) {
      shell.classList.toggle('sidebar-open');
    } else {
      shell.classList.toggle('sidebar-collapsed');
    }
  });

  // Backdrop to close mobile drawer
  const backdrop = document.createElement('div');
  backdrop.className = 'sidebar-backdrop';
  backdrop.addEventListener('click', () => shell.classList.remove('sidebar-open'));
  shell.appendChild(backdrop);

  // Top "New Scan" button
  document.getElementById('topbar-new-scan').addEventListener('click', () => openScanModal());

  // Register all routes
  registerRoute('dashboard', renderDashboard);
  registerRoute('scans',     (main, params) => params[0] ? renderScanDetail(main, params[0]) : renderScansPage(main));
  registerRoute('agents',    renderAgentsPage);
  registerRoute('settings',  renderSettingsPage);
  registerRoute('projects',  renderProjectsPage);
  registerRoute('reports',   renderReportsPage);
  registerRoute('history',   renderHistoryPage);
  registerRoute('devices',   renderDevicesPage);

  // Deferred features: routes removed from IA but URL aliases kept for one
  // release so existing bookmarks still land on the dashboard.
  const redirectToDashboard = () => { location.hash = '#dashboard'; };
  registerRoute('docs',      redirectToDashboard);    // TODO(redesign): remove URL alias in next minor version
  registerRoute('rag',       redirectToDashboard);    // TODO(redesign): remove URL alias in next minor version
  registerRoute('verify',    redirectToDashboard);    // TODO(redesign): remove URL alias in next minor version
  registerRoute('exploit',   redirectToDashboard);    // TODO(redesign): remove URL alias in next minor version

  initRouter();

  // close mobile drawer on nav click
  document.querySelectorAll('.sidebar-link').forEach(l => {
    l.addEventListener('click', () => shell.classList.remove('sidebar-open'));
  });
});

function parseInitialRoute() {
  const raw = (location.hash || '#dashboard').replace(/^#/, '');
  return raw.split('/')[0] || 'dashboard';
}
