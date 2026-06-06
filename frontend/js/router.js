// Hash-based router
import { setActiveSidebarLink } from './components/sidebar.js';
import { setBreadcrumb } from './components/topbar.js';

const routes = new Map();

export function registerRoute(name, handler) {
  routes.set(name, handler);
}

export function navigate(hash) {
  location.hash = hash;
}

function parseHash() {
  const raw = location.hash.replace(/^#/, '') || 'dashboard';
  const [path, ...rest] = raw.split('/');
  return { name: path || 'dashboard', params: rest };
}

function dispatch() {
  const { name, params } = parseHash();
  const handler = routes.get(name);
  const main = document.getElementById('main-view');
  if (!main) return;

  setActiveSidebarLink(name);

  // breadcrumb default
  const labels = {
    dashboard: 'Dashboard',
    scans: 'Scans',
    agents: 'Agents',
    projects: 'Projects',
    reports: 'Reports',
    history: 'History',
    settings: 'Settings',
    docs: 'Docs',
    rag: 'Knowledge Base',
    verify: 'Verify Engine',
    exploit: 'PoC Generator',
  };
  const crumbs = [{ label: labels[name] || name }];
  if (params.length > 0 && name === 'scans') {
    crumbs[0] = { label: 'Scans', href: '#scans' };
    crumbs.push({ label: params[0] });
  }
  setBreadcrumb(crumbs);

  if (!handler) {
    main.innerHTML = `<div class="card"><h2>Not found</h2><p>Route <code class="inline">${name}</code> is not registered.</p></div>`;
    return;
  }

  main.innerHTML = '';
  handler(main, params);
  window.scrollTo({ top: 0 });
}

export function initRouter() {
  window.addEventListener('hashchange', dispatch);
  dispatch();
}
