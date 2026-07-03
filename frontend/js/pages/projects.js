// Projects page — derives projects from real scans grouped by package.
// "New project" opens the scan modal (a project is just "an app you've scanned").
import { el, refreshIcons, timeAgo, statusLabel } from '../utils.js';
import { openScanModal } from '../components/scan-modal.js';
import { offlineBanner } from '../components/offline-banner.js';
import { api } from '../api.js';

export async function renderProjectsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Projects'),
      el('div', { class: 'page-subtitle', id: 'projects-sub' }, 'Loading…'),
    ),
    el('div', { class: 'page-actions' },
      el('button', { class: 'btn btn-primary', onclick: () => openScanModal() },
        el('i', { 'data-lucide': 'plus' }), 'New project'),
    ),
  ));

  const banner = el('div', { id: 'projects-banner' });
  const body = el('div', { id: 'projects-body' });
  main.appendChild(banner);
  main.appendChild(body);
  refreshIcons();

  let scans = [];
  try {
    scans = await api.listScans();
  } catch (e) {
    banner.innerHTML = '';
    banner.appendChild(offlineBanner(e));
    refreshIcons();
  }

  // Group scans by package (or filename if no manifest)
  const groups = new Map();
  scans.forEach(scan => {
    const m = scan.manifest || {};
    const key = m.package || scan.apk_filename || scan.session_id;
    if (!groups.has(key)) {
      groups.set(key, {
        package: m.package || null,
        appName: deriveAppName(m, scan),
        scans: [],
      });
    }
    groups.get(key).scans.push(scan);
  });

  const projects = [...groups.values()].map(g => {
    g.scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const latest = g.scans[0];
    return {
      ...g,
      scanCount: g.scans.length,
      lastScan: latest.completed_at || latest.started_at || latest.created_at,
      lastStatus: latest.status,
      latestId: latest.session_id,
    };
  }).sort((a, b) => new Date(b.lastScan) - new Date(a.lastScan));

  const sub = document.getElementById('projects-sub');
  if (sub) {
    sub.textContent = projects.length
      ? `${projects.length} app${projects.length === 1 ? '' : 's'} tracked across ${scans.length} scan${scans.length === 1 ? '' : 's'}`
      : 'No apps scanned yet';
  }

  if (projects.length === 0) {
    body.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'folder-plus' }),
      el('h3', {}, 'No projects yet'),
      el('p', {}, 'Each APK you scan becomes a project automatically. Click "New project" to upload your first APK.'),
      el('div', { style: 'margin-top: 16px;' },
        el('button', { class: 'btn btn-primary', onclick: () => openScanModal() },
          el('i', { 'data-lucide': 'plus' }), 'New project'),
      ),
    ));
    refreshIcons();
    return;
  }

  const grid = el('div', { class: 'agents-grid' });
  projects.forEach(p => grid.appendChild(buildProjectCard(p)));
  body.appendChild(grid);
  refreshIcons();
}

function deriveAppName(manifest, scan) {
  if (manifest.package) {
    const tail = manifest.package.split('.').slice(-1)[0];
    return tail.replace(/^./, c => c.toUpperCase());
  }
  return (scan.apk_filename || scan.session_id).replace(/\.(apk|aab|xapk)$/i, '');
}

function buildProjectCard(p) {
  const initial = p.appName.slice(0, 1).toUpperCase();
  const card = el('div', { class: 'agent-card card-hover', style: 'cursor: pointer;',
    onclick: () => location.hash = `#scans/${p.latestId}` });

  card.append(
    el('div', { class: 'agent-head' },
      el('div', { style: 'display: flex; align-items: center; gap: 12px;' },
        el('div', { class: 'avatar', style: `background: var(--accent-bg-soft); color: var(--accent-primary);` }, initial),
        el('div', {},
          el('div', { class: 'agent-name' }, p.appName),
          el('div', { class: 'mono text-muted', style: 'font-size: 11px;' }, p.package || '—'),
        ),
      ),
      el('span', { class: 'badge accent badge-sm' }, `${p.scanCount} scan${p.scanCount === 1 ? '' : 's'}`),
    ),
    el('div', { class: 'agent-desc' },
      `Last scan: ${timeAgo(p.lastScan)} · ${statusLabel(p.lastStatus)}`),
    el('div', { style: 'display: flex; gap: 6px; margin-top: 8px;' },
      el('button', { class: 'btn btn-secondary btn-sm',
        onclick: (ev) => { ev.stopPropagation(); openScanModal(); } },
        el('i', { 'data-lucide': 'play' }), 'New scan'),
      el('button', { class: 'btn btn-ghost btn-sm',
        onclick: (ev) => { ev.stopPropagation(); location.hash = `#scans/${p.latestId}`; } },
        'View latest →'),
    ),
  );
  return card;
}
