// Scans list page — backed by the real /scans endpoint.
// Falls back to the seeded mock data if the gateway is unreachable, so the
// page still tells the user what's wrong without going blank.
import { el, refreshIcons, timeAgo, statusLabel, debounce, formatDuration } from '../utils.js';
import { SCANS as MOCK_SCANS } from '../data/scans.js';
import { sevRow, statusBadge } from '../components/severity-badge.js';
import { openScanModal } from '../components/scan-modal.js';
import { api, ApiError } from '../api.js';

let filters = {
  q: '',
  status: 'all',
  severities: new Set(),
  page: 1,
  sortKey: 'startedAt',
  sortDir: 'desc',
};
const PAGE_SIZE = 20;
let SCANS = [];
let apiOnline = true;

export async function renderScansPage(main) {
  // Header
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Scans'),
      el('div', { class: 'page-subtitle', id: 'scans-subtitle' }, 'Loading scans…'),
    ),
    el('div', { class: 'page-actions' },
      el('button', { class: 'btn btn-secondary', onclick: () => loadScans(true) },
        el('i', { 'data-lucide': 'refresh-cw' }), 'Refresh'),
      el('button', { class: 'btn btn-primary', onclick: () => openScanModal() },
        el('i', { 'data-lucide': 'plus' }), 'New scan'),
    ),
  ));

  main.appendChild(buildFilters());
  main.appendChild(el('div', { id: 'api-banner' }));
  main.appendChild(el('div', { id: 'scans-table-holder' }));
  main.appendChild(el('div', { id: 'scans-pagination' }));

  refreshIcons();
  await loadScans(false);
}

async function loadScans(showToast) {
  try {
    const rows = await api.listScans();
    SCANS = rows.map(toViewModel);
    apiOnline = true;
    document.getElementById('api-banner').innerHTML = '';
  } catch (e) {
    apiOnline = false;
    const msg = e instanceof ApiError ? e.message : String(e);
    SCANS = MOCK_SCANS.slice(); // visible-but-flagged fallback
    const banner = document.getElementById('api-banner');
    banner.innerHTML = '';
    banner.appendChild(el('div', { class: 'card', style: 'padding: 14px 16px; margin-bottom: 16px; border-color: var(--sev-medium);' },
      el('div', { style: 'display: flex; gap: 12px; align-items: flex-start;' },
        el('i', { 'data-lucide': 'wifi-off', style: 'color: var(--sev-medium); flex-shrink: 0;' }),
        el('div', { style: 'flex: 1;' },
          el('div', { style: 'font-weight: 600;' }, 'SENTINEL API unreachable — showing seeded sample data'),
          el('div', { class: 'text-muted', style: 'font-size: 12px; margin-top: 4px;' },
            msg, ' · Start it with ', el('span', { class: 'mono' }, 'poetry run sentinel serve')),
        ),
      ),
    ));
    refreshIcons();
  }
  const sub = document.getElementById('scans-subtitle');
  if (sub) sub.textContent = `${SCANS.length} scan${SCANS.length === 1 ? '' : 's'}${apiOnline ? '' : ' (offline)'}`;
  applyFilters();
}

function toViewModel(row) {
  const m = row.manifest || {};
  const appName = m.package
    ? m.package.split('.').slice(-1)[0].replace(/^./, c => c.toUpperCase())
    : (row.apk_filename || row.session_id).replace(/\.apk$|\.aab$|\.xapk$/i, '');
  const sev = row.severity_counts || {};
  return {
    id: row.session_id,
    appName,
    apkFilename: row.apk_filename,
    package: m.package || row.apk_filename || '—',
    version: m.version_name || '',
    platform: 'Android',
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
    triage: row.triage_counts || {},
    warnings: [],
    scanFlags: optsToFlags(row.options || {}),
    sizeMB: row.apk_size_bytes ? row.apk_size_bytes / (1024 * 1024) : null,
    _live: true,
  };
}

function optsToFlags(o) {
  const f = [];
  if (o.dynamic) f.push('--dynamic');
  if (o.frida) f.push('--frida');
  if (o.no_proxy) f.push('--no-proxy');
  if (o.privacy) f.push('--private');
  if (o.llm_triage) f.push('--llm-triage');
  return f;
}

function buildFilters() {
  const bar = el('div', { class: 'filters-bar' });

  const search = el('div', { class: 'search-input', style: 'flex: 1; min-width: 220px;' },
    el('i', { 'data-lucide': 'search' }),
    el('input', { type: 'text', placeholder: 'Search by app, package, scan ID' }),
  );
  search.querySelector('input').addEventListener('input', debounce((e) => {
    filters.q = e.target.value.toLowerCase();
    filters.page = 1;
    applyFilters();
  }, 200));
  bar.appendChild(search);

  const statusSel = el('div', { class: 'filter-group' },
    el('label', {}, 'Status'),
    el('select', { class: 'select', style: 'min-width: 140px;' },
      el('option', { value: 'all' }, 'All'),
      el('option', { value: 'completed' }, 'Completed'),
      el('option', { value: 'running' }, 'Running'),
      el('option', { value: 'queued' }, 'Queued'),
      el('option', { value: 'failed' }, 'Failed'),
    ),
  );
  statusSel.querySelector('select').addEventListener('change', (e) => {
    filters.status = e.target.value;
    filters.page = 1;
    applyFilters();
  });
  bar.appendChild(statusSel);

  const sevGroup = el('div', { class: 'filter-group' },
    el('label', {}, 'Severity'),
    ...['critical', 'high', 'medium', 'low'].map(s => el('label', { class: 'checkbox' },
      el('input', { type: 'checkbox', value: s }), s,
    )),
  );
  sevGroup.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', (e) => {
      if (e.target.checked) filters.severities.add(e.target.value);
      else filters.severities.delete(e.target.value);
      filters.page = 1;
      applyFilters();
    });
  });
  bar.appendChild(sevGroup);

  const clearBtn = el('button', { class: 'btn btn-ghost btn-sm', style: 'margin-left: auto;' }, 'Clear');
  clearBtn.addEventListener('click', () => {
    filters = { q: '', status: 'all', severities: new Set(), page: 1, sortKey: 'startedAt', sortDir: 'desc' };
    bar.querySelector('input[type="text"]').value = '';
    bar.querySelector('select').value = 'all';
    bar.querySelectorAll('input[type="checkbox"]').forEach(c => c.checked = false);
    applyFilters();
  });
  bar.appendChild(clearBtn);

  refreshIcons();
  return bar;
}

function applyFilters() {
  const filtered = SCANS.filter(scan => {
    if (filters.q) {
      const t = `${scan.appName} ${scan.package} ${scan.id}`.toLowerCase();
      if (!t.includes(filters.q)) return false;
    }
    if (filters.status !== 'all' && scan.status !== filters.status) {
      // accept "in_progress" alias for "running"
      if (!(filters.status === 'running' && scan.status === 'in_progress')) return false;
    }
    if (filters.severities.size > 0) {
      const hits = [...filters.severities].some(s => (scan.severity?.[s] || 0) > 0);
      if (!hits) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    const k = filters.sortKey;
    let av = a[k];
    let bv = b[k];
    if (k === 'severity') {
      av = totalSev(a.severity); bv = totalSev(b.severity);
    }
    if (av < bv) return filters.sortDir === 'asc' ? -1 : 1;
    if (av > bv) return filters.sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (filters.page > totalPages) filters.page = totalPages;
  const start = (filters.page - 1) * PAGE_SIZE;
  const pageRows = filtered.slice(start, start + PAGE_SIZE);

  renderTable(pageRows);
  renderPagination(filtered.length, totalPages);
}

function totalSev(sev) {
  return (sev?.critical || 0) + (sev?.high || 0) + (sev?.medium || 0) + (sev?.low || 0);
}

function renderTable(rows) {
  const holder = document.getElementById('scans-table-holder');
  holder.innerHTML = '';

  if (rows.length === 0) {
    holder.appendChild(el('div', { class: 'card' },
      el('div', { class: 'empty-state' },
        el('i', { 'data-lucide': 'search-x' }),
        el('h3', {}, apiOnline ? 'No scans yet' : 'No scans match your filters'),
        el('p', {}, apiOnline
          ? 'Click "+ New scan" to upload an APK and run your first scan.'
          : 'Try clearing filters or check the API connection above.'),
      )));
    refreshIcons();
    return;
  }

  const wrap = el('div', { class: 'table-wrap' });
  const table = el('table', { class: 'table' });

  const sortableHeader = (key, label) => {
    const sorted = filters.sortKey === key;
    const arrow = sorted ? (filters.sortDir === 'asc' ? '▲' : '▼') : '';
    const th = el('th', { class: `sortable ${sorted ? 'sorted' : ''}` }, label, ' ',
      el('span', { class: 'sort-icon', style: 'font-size: 10px;' }, arrow));
    th.addEventListener('click', () => {
      if (filters.sortKey === key) filters.sortDir = filters.sortDir === 'asc' ? 'desc' : 'asc';
      else { filters.sortKey = key; filters.sortDir = 'desc'; }
      applyFilters();
    });
    return th;
  };

  table.appendChild(el('thead', {}, el('tr', {},
    sortableHeader('appName', 'App'),
    el('th', {}, 'Package'),
    sortableHeader('severity', 'Severity'),
    el('th', {}, 'Status'),
    sortableHeader('startedAt', 'Started'),
    el('th', {}, 'Duration'),
    el('th', { style: 'width: 30px;' }, ''),
  )));

  const tbody = el('tbody');
  rows.forEach(scan => {
    const tr = el('tr', { class: 'clickable', onclick: () => location.hash = `#scans/${scan.id}` });
    tr.append(
      el('td', {}, el('div', { style: 'display: flex; align-items: center; gap: 10px;' },
        el('div', { class: 'avatar', style: 'width: 28px; height: 28px; font-size: 11px;' }, scan.appName.slice(0, 1).toUpperCase()),
        el('span', { style: 'font-weight: 500;' }, scan.appName),
        scan.version ? el('span', { class: 'mono text-muted', style: 'font-size: 11px;' }, scan.version) : null,
      )),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 12px;' }, scan.package)),
      el('td', {}, sevRow(scan.severity)),
      el('td', {}, statusBadge(scan.status, statusLabel(scan.status))),
      el('td', {}, el('span', { class: 'text-muted', style: 'font-size: 12px;' }, timeAgo(scan.startedAt))),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 12px;' }, scan.duration || '—')),
      el('td', { onclick: (ev) => ev.stopPropagation() }, el('button', { class: 'btn-icon' },
        el('i', { 'data-lucide': 'more-horizontal' }))),
    );
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  holder.appendChild(wrap);
  refreshIcons();
}

function renderPagination(total, totalPages) {
  const holder = document.getElementById('scans-pagination');
  holder.innerHTML = '';
  if (total === 0) return;
  const showingFrom = (filters.page - 1) * PAGE_SIZE + 1;
  const showingTo = Math.min(filters.page * PAGE_SIZE, total);

  const bar = el('div', { class: 'pagination' });
  bar.appendChild(el('div', { class: 'pagination-info' },
    `Showing ${showingFrom}–${showingTo} of ${total}`));

  const controls = el('div', { class: 'pagination-controls' });
  const prev = el('button', { disabled: filters.page === 1 ? true : null }, '‹ Prev');
  prev.addEventListener('click', () => { filters.page--; applyFilters(); });
  controls.appendChild(prev);
  for (let i = 1; i <= totalPages; i++) {
    if (totalPages > 7 && (i > 3 && i < totalPages - 2 && Math.abs(i - filters.page) > 1)) {
      if (i === 4 || i === totalPages - 3) controls.appendChild(el('span', { class: 'text-muted' }, '…'));
      continue;
    }
    const btn = el('button', { class: filters.page === i ? 'active' : '' }, String(i));
    btn.addEventListener('click', () => { filters.page = i; applyFilters(); });
    controls.appendChild(btn);
  }
  const next = el('button', { disabled: filters.page === totalPages ? true : null }, 'Next ›');
  next.addEventListener('click', () => { filters.page++; applyFilters(); });
  controls.appendChild(next);

  bar.appendChild(controls);
  holder.appendChild(bar);
}
