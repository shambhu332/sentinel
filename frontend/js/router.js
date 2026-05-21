/**
 * router.js — hash-based router for app.html.
 *
 * Routes (window.location.hash):
 *   #dashboard
 *   #projects, #projects/[id]
 *   #history,  #history/[scanId]
 *   #reports
 *   #agents
 *   #architecture
 *   #workspaces, #workspaces/[id]
 *   #settings
 *   #demo
 */

import { renderDashboard }    from './views/dashboard.js';
import { renderProjects, renderProjectDetail }   from './views/projects.js';
import { renderHistory }      from './views/history.js';
import { renderReports }      from './views/reports.js';
import { renderAgents }       from './views/agents.js';
import { renderArchitecture } from './views/architecture.js';
import { renderWorkspaces, renderWorkspaceDetail } from './views/workspaces.js';
import { renderSettings }     from './views/settings.js';
import { renderDemo }         from './views/demo.js';

import { setActiveNav } from './components/sidebar.js';
import { setTopbarView } from './components/topbar.js';

const ROUTES = {
  dashboard:    renderDashboard,
  projects:     renderProjects,
  history:      renderHistory,
  reports:      renderReports,
  agents:       renderAgents,
  architecture: renderArchitecture,
  workspaces:   renderWorkspaces,
  settings:     renderSettings,
  demo:         renderDemo,
};

const SUB_ROUTES = {
  projects:   renderProjectDetail,
  workspaces: renderWorkspaceDetail,
  history:    renderHistory,   /* history handles a scanId itself */
};

function parseHash() {
  const raw = window.location.hash.replace(/^#/, '') || 'dashboard';
  const [view, ...rest] = raw.split('/');
  return { view, params: rest };
}

function mount(viewFn, params) {
  const target = document.getElementById('view-container');
  if (!target) return;
  target.innerHTML = '';
  /* Restart the view-in animation by re-flow */
  void target.offsetWidth;
  try {
    viewFn(target, params);
  } catch (err) {
    console.error('[router] view crashed:', err);
    target.innerHTML = `<div class="empty"><h3>Something broke</h3><p>${err.message}</p></div>`;
  }
  /* Re-init Lucide whenever a new view mounts */
  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
  /* Scroll to top */
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}

export function startRouter() {
  const route = () => {
    const { view, params } = parseHash();
    const root = view in ROUTES ? ROUTES[view] : ROUTES.dashboard;
    const sub  = SUB_ROUTES[view];
    setActiveNav(view in ROUTES ? view : 'dashboard');
    setTopbarView(view);
    if (sub && params.length) mount(sub, params);
    else                       mount(root, params);
  };
  window.addEventListener('hashchange', route);
  route();
}
