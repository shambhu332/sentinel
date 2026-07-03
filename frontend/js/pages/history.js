// History page — chronological scan timeline backed by the real /scans endpoint.
import { el, refreshIcons, timeAgo, statusLabel, formatDuration } from '../utils.js';
import { SCANS as MOCK_SCANS } from '../data/scans.js';
import { statusBadge, sevRow } from '../components/severity-badge.js';
import { offlineBanner } from '../components/offline-banner.js';
import { api } from '../api.js';

export async function renderHistoryPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'History'),
      el('div', { class: 'page-subtitle', id: 'history-sub' }, 'Loading scans…'),
    ),
    el('div', { class: 'page-actions' },
      el('button', { class: 'btn btn-secondary', onclick: () => renderHistoryPage(main.parentElement ? main : main), title: 'Reload' },
        el('i', { 'data-lucide': 'refresh-cw' }), 'Refresh'),
    ),
  ));

  const banner = el('div', { id: 'history-banner' });
  const body = el('div', { id: 'history-body' });
  main.appendChild(banner);
  main.appendChild(body);
  refreshIcons();

  let scans = [];
  let apiOnline = true;
  try {
    const live = await api.listScans();
    scans = live.map(toView);
  } catch (e) {
    apiOnline = false;
    scans = MOCK_SCANS.slice();
    banner.innerHTML = '';
    banner.appendChild(offlineBanner(e));
    refreshIcons();
  }

  const sub = document.getElementById('history-sub');
  if (sub) {
    sub.textContent = apiOnline
      ? `${scans.length} scan${scans.length === 1 ? '' : 's'} on this instance`
      : `${scans.length} sample scan${scans.length === 1 ? '' : 's'} (gateway offline)`;
  }

  if (scans.length === 0) {
    body.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'shield-off' }),
      el('h3', {}, 'No scans yet'),
      el('p', {}, 'Click + New scan in the topbar to upload your first APK.'),
    ));
    refreshIcons();
    return;
  }

  // Group by day
  const byDay = {};
  scans.forEach(scan => {
    const day = (scan.startedAt ? new Date(scan.startedAt) : new Date()).toISOString().slice(0, 10);
    (byDay[day] = byDay[day] || []).push(scan);
  });
  const sortedDays = Object.keys(byDay).sort().reverse();

  sortedDays.forEach(day => {
    body.appendChild(el('h4', { style: 'font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin: 24px 0 8px;' },
      new Date(day).toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' })));

    const card = el('div', { class: 'card', style: 'padding: 0;' });
    const list = el('div', { class: 'activity-list', style: 'padding: 8px; max-height: none;' });
    byDay[day].forEach(scan => {
      list.appendChild(el('div', { class: 'activity-item', style: 'cursor: pointer;',
        onclick: () => location.hash = `#scans/${scan.id}` },
        el('div', { class: `activity-icon ${scan.status === 'completed' ? 'ok' : scan.status === 'failed' ? 'err' : ''}` },
          el('i', { 'data-lucide':
            scan.status === 'failed' ? 'x-circle' :
            (scan.status === 'running' || scan.status === 'in_progress' || scan.status === 'queued') ? 'activity' :
            'shield-check' })),
        el('div', { class: 'activity-content' },
          el('div', { class: 'activity-title', style: 'display: flex; gap: 8px; align-items: center; flex-wrap: wrap;' },
            scan.appName, ' ',
            el('span', { class: 'mono text-muted', style: 'font-size: 11px;' }, scan.id),
            statusBadge(scan.status, statusLabel(scan.status)),
          ),
          el('div', { class: 'activity-meta', style: 'display: flex; gap: 8px; align-items: center; flex-wrap: wrap;' },
            timeAgo(scan.startedAt), ' · ',
            sevRow(scan.severity),
          ),
        ),
      ));
    });
    card.appendChild(list);
    body.appendChild(card);
  });
  refreshIcons();
}

function toView(row) {
  const m = row.manifest || {};
  const sev = row.severity_counts || {};
  const appName = m.package
    ? m.package.split('.').slice(-1)[0].replace(/^./, c => c.toUpperCase())
    : (row.apk_filename || row.session_id).replace(/\.(apk|aab|xapk)$/i, '');
  return {
    id: row.session_id,
    appName,
    package: m.package || row.apk_filename || '—',
    version: m.version_name || '',
    status: row.status,
    startedAt: row.started_at || row.created_at,
    duration: row.completed_at && row.started_at
      ? formatDuration(Math.max(0, Math.round((new Date(row.completed_at) - new Date(row.started_at)) / 1000)))
      : null,
    severity: {
      critical: sev.critical || 0,
      high:     sev.high || 0,
      medium:   sev.medium || 0,
      low:      sev.low || 0,
      info:     sev.info || 0,
    },
  };
}
