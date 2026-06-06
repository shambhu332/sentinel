// Dashboard / Overview page — backed by the real /scans endpoint when reachable.
import { el, refreshIcons, formatDate, timeAgo, statusLabel, formatDuration } from '../utils.js';
import { SCANS as MOCK_SCANS } from '../data/scans.js';
import { openScanModal } from '../components/scan-modal.js';
import { sevRow, statusBadge } from '../components/severity-badge.js';
import { api, ApiError } from '../api.js';

let SCANS = [];
let apiOnline = false;

export async function renderDashboard(main) {
  // Welcome row
  main.appendChild(el('div', { class: 'welcome-row' },
    el('div', { class: 'welcome' },
      el('h2', {}, 'SENTINEL Dashboard'),
      el('div', { class: 'welcome-sub', id: 'welcome-sub' }, 'Loading…'),
    ),
    el('div', { class: 'page-actions' },
      el('button', { class: 'btn btn-secondary', onclick: () => location.hash = '#scans' },
        el('i', { 'data-lucide': 'list' }), 'View all scans'),
      el('button', { class: 'btn btn-primary', onclick: () => openScanModal() },
        el('i', { 'data-lucide': 'plus' }), 'New scan'),
    ),
  ));

  main.appendChild(el('div', { class: 'stats-grid', id: 'dash-stats' }));
  main.appendChild(el('div', { id: 'dash-api-banner' }));

  // Upload card
  const uploadCard = el('div', { class: 'card upload-card' });
  uploadCard.appendChild(el('div', { class: 'card-header', style: 'padding: 16px 20px; margin: 0; border-bottom: 1px solid var(--border);' },
    el('div', { class: 'card-title' },
      el('i', { 'data-lucide': 'upload-cloud' }),
      'Upload APK',
    ),
    el('span', { class: 'text-muted', style: 'font-size: 12px;' }, 'Supports .apk · .aab · .xapk'),
  ));
  const uploadZone = el('div', { class: 'upload-zone' },
    el('i', { 'data-lucide': 'file-up' }),
    el('div', { class: 'upload-title' }, 'Drop your APK/AAB/XAPK here'),
    el('div', { class: 'upload-sub' }, 'or'),
    el('button', { class: 'btn btn-primary btn-sm' }, 'Choose File'),
    el('div', { class: 'upload-formats' }, 'Max 500 MB · runs on the local SENTINEL gateway'),
  );
  uploadZone.addEventListener('click', () => openScanModal());
  uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('dragover'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) openScanModal({ file: f });
  });
  uploadCard.appendChild(uploadZone);

  const chartsRow = el('div', { class: 'dashboard-grid' });
  chartsRow.appendChild(uploadCard);
  const donutCard = el('div', { class: 'card chart-card' },
    el('div', { class: 'card-header', style: 'margin-bottom: 8px;' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'pie-chart' }), 'Severity distribution'),
      el('span', { class: 'text-muted', style: 'font-size: 12px;', id: 'donut-source' }, 'All scans'),
    ),
    el('div', { class: 'chart-wrap' }, el('canvas', { id: 'donut-chart' })),
  );
  chartsRow.appendChild(donutCard);
  main.appendChild(chartsRow);

  const bottomRow = el('div', { class: 'dashboard-bottom' });
  bottomRow.appendChild(el('div', { class: 'card chart-card' },
    el('div', { class: 'card-header', style: 'margin-bottom: 8px;' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'trending-up' }), 'Findings trend'),
      el('span', { class: 'text-muted', style: 'font-size: 12px;' }, 'Last 14 days'),
    ),
    el('div', { class: 'chart-wrap' }, el('canvas', { id: 'trend-chart' })),
  ));
  bottomRow.appendChild(buildActivityFeed());
  main.appendChild(bottomRow);

  main.appendChild(el('div', { id: 'dash-recent' }));

  refreshIcons();

  await loadData();
}

async function loadData() {
  const banner = document.getElementById('dash-api-banner');
  try {
    const live = await api.listScans();
    SCANS = live.map(liveToView);
    apiOnline = true;
    // Clear any stale offline banner left over from a previous failed
    // load — otherwise it stays visible even after the user starts the
    // gateway and the page successfully refreshes.
    if (banner) banner.innerHTML = '';
  } catch (e) {
    SCANS = MOCK_SCANS.slice();
    apiOnline = false;
    if (banner) {
      banner.innerHTML = '';
      banner.appendChild(buildOfflineBanner(
        'SENTINEL API offline.',
        'Showing sample data — start the gateway or change the API URL in ',
      ));
    }
  }
  paintDash();
}

function buildOfflineBanner(strongText, prefix) {
  return el('div', { class: 'card offline-banner' },
    el('div', { class: 'offline-banner-row' },
      el('i', { 'data-lucide': 'wifi-off', class: 'offline-banner-icon' }),
      el('div', { style: 'font-size: 13px; flex: 1;' },
        el('strong', {}, strongText, ' '),
        prefix,
        el('a', { href: '#settings', class: 'offline-banner-link' },
          el('i', { 'data-lucide': 'settings', style: 'width: 14px; height: 14px;' }),
          'Settings ▸ Connection',
        ),
        '. Or run ',
        el('span', { class: 'mono' }, 'poetry run sentinel serve'),
        '.',
      ),
      el('button', {
        class: 'btn btn-sm btn-ghost',
        onclick: () => location.reload(),
      },
        el('i', { 'data-lucide': 'rotate-cw' }),
        'Retry',
      ),
    ),
  );
}

function liveToView(row) {
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

function paintDash() {
  const totalScans = SCANS.length;
  const completed = SCANS.filter(s => s.status === 'completed').length;
  const running = SCANS.filter(s => s.status === 'running' || s.status === 'in_progress' || s.status === 'queued').length;
  let critTotal = 0, highTotal = 0, medTotal = 0, lowTotal = 0, infoTotal = 0;
  SCANS.forEach(s => {
    critTotal += s.severity.critical || 0;
    highTotal += s.severity.high || 0;
    medTotal  += s.severity.medium || 0;
    lowTotal  += s.severity.low || 0;
    infoTotal += s.severity.info || 0;
  });
  const appCount = new Set(SCANS.map(s => s.package)).size;

  const sub = document.getElementById('welcome-sub');
  if (sub) {
    sub.textContent = apiOnline
      ? `${totalScans} live scan${totalScans === 1 ? '' : 's'} on this SENTINEL instance.`
      : 'Showing sample data — SENTINEL gateway is offline.';
  }

  const stats = document.getElementById('dash-stats');
  stats.innerHTML = '';
  stats.append(
    statCard('Total scans', totalScans, `${completed} completed`, 'shield-check'),
    statCard('Critical findings', critTotal, `${highTotal} high`, 'alert-octagon', critTotal > 0 ? 'crit' : null),
    statCard('Apps analyzed', appCount, 'unique packages', 'box'),
    statCard('Active now', running, running ? 'in progress' : 'idle', 'activity', running ? 'live' : null),
  );

  const recent = document.getElementById('dash-recent');
  recent.innerHTML = '';
  recent.appendChild(buildRecentScans());

  refreshIcons();
  requestAnimationFrame(() => {
    drawDonut({ critical: critTotal, high: highTotal, medium: medTotal, low: lowTotal, info: infoTotal });
    drawTrend();
  });
}

function statCard(label, value, sub, icon, accent) {
  const card = el('div', { class: 'stat-card' },
    el('div', { style: 'display: flex; align-items: flex-start; justify-content: space-between;' },
      el('span', { class: 'stat-label' }, label),
      el('div', { class: 'avatar',
        style: `width: 28px; height: 28px; background: ${accent === 'crit' ? 'var(--sev-critical-bg)' : 'var(--accent-bg-soft)'}; color: ${accent === 'crit' ? 'var(--sev-critical)' : 'var(--accent-primary)'};` },
        el('i', { 'data-lucide': icon, style: 'width: 14px; height: 14px;' }),
      ),
    ),
    el('span', { class: 'stat-value', style: accent === 'crit' ? 'color: var(--sev-critical);' : '' }, String(value)),
    el('span', { class: 'stat-trend' },
      accent === 'live' ? el('span', { class: 'live-dot' }) : null,
      sub,
    ),
  );
  return card;
}

function buildActivityFeed() {
  const recent = [
    { icon: 'shield-check', cls: 'ok',  title: 'Open the scans page',  meta: 'see live scans submitted via the API' },
    { icon: 'upload-cloud', cls: '',    title: 'Click +New Scan to upload an APK',  meta: 'campus.apk, signal.apk, etc.' },
    { icon: 'cpu',          cls: '',    title: 'Phase 2 agents run in parallel', meta: 'A_001, A_004, N_002, P_001 …' },
    { icon: 'sparkles',     cls: 'warn', title: 'LLM triage filters false positives', meta: 'Groq → Cerebras → Ollama' },
    { icon: 'shield-alert', cls: 'err', title: 'Findings stream into the scan-detail view', meta: 'with full evidence + recommendations' },
  ];
  const card = el('div', { class: 'card', style: 'padding: 0;' },
    el('div', { class: 'card-header', style: 'padding: 16px 20px; margin: 0; border-bottom: 1px solid var(--border);' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'rss' }), 'How it works'),
      el('span', { class: 'badge accent', style: 'font-size: 10px;' }, 'Quick tour'),
    ),
    el('div', { class: 'activity-list', style: 'padding: 12px;' },
      ...recent.map(item => el('div', { class: 'activity-item' },
        el('div', { class: `activity-icon ${item.cls}` }, el('i', { 'data-lucide': item.icon })),
        el('div', { class: 'activity-content' },
          el('div', { class: 'activity-title' }, item.title),
          el('div', { class: 'activity-meta' }, item.meta),
        ),
      )),
    ),
  );
  return card;
}

function buildRecentScans() {
  const card = el('div', { class: 'card', style: 'padding: 0;' });
  card.appendChild(el('div', { class: 'card-header', style: 'padding: 16px 20px; margin: 0; border-bottom: 1px solid var(--border);' },
    el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'history' }), 'Recent scans'),
    el('a', { href: '#scans', style: 'font-size: 13px;' }, 'View all →'),
  ));

  if (SCANS.length === 0) {
    card.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'shield-off' }),
      el('h3', {}, 'No scans yet'),
      el('p', {}, 'Click + New scan to upload your first APK.'),
    ));
    refreshIcons();
    return card;
  }

  const wrap = el('div', { class: 'table-wrap', style: 'border: none; border-radius: 0;' });
  const table = el('table', { class: 'table' });
  table.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'App'),
    el('th', {}, 'Package'),
    el('th', {}, 'Severity'),
    el('th', {}, 'Status'),
    el('th', {}, 'Started'),
    el('th', {}, 'Duration'),
    el('th', { style: 'width: 40px;' }, ''),
  )));

  const tbody = el('tbody');
  SCANS.slice(0, 6).forEach(scan => {
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
      el('td', {}, el('button', { class: 'btn-icon', onclick: (ev) => ev.stopPropagation() },
        el('i', { 'data-lucide': 'more-horizontal' }))),
    );
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  card.appendChild(wrap);
  return card;
}

// ---------- Charts ----------
function drawDonut({ critical, high, medium, low, info }) {
  const ctx = document.getElementById('donut-chart');
  if (!ctx || !window.Chart) return;
  if (ctx._chart) ctx._chart.destroy();

  const all = critical + high + medium + low + info;
  if (all === 0) {
    // Draw a placeholder ring
    ctx._chart = new Chart(ctx, {
      type: 'doughnut',
      data: { labels: ['No findings'], datasets: [{ data: [1], backgroundColor: [getCss('--border')], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '68%',
        plugins: { legend: { display: false }, tooltip: { enabled: false } } },
    });
    return;
  }

  ctx._chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [critical, high, medium, low, info],
        backgroundColor: [
          getCss('--sev-critical'),
          getCss('--sev-high'),
          getCss('--sev-medium'),
          getCss('--sev-low'),
          getCss('--sev-info') || '#6B7280',
        ],
        borderColor: getCss('--bg-primary'),
        borderWidth: 3,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'right', align: 'center',
          labels: { color: getCss('--text-secondary'), font: { family: 'Inter', size: 12 },
            padding: 12, boxWidth: 8, boxHeight: 8, usePointStyle: true, pointStyle: 'circle' },
        },
        tooltip: { backgroundColor: getCss('--bg-elevated'), borderColor: getCss('--border-strong'),
          borderWidth: 1, titleColor: getCss('--text-primary'), bodyColor: getCss('--text-secondary') },
      },
    },
  });
}

function drawTrend() {
  const ctx = document.getElementById('trend-chart');
  if (!ctx || !window.Chart) return;
  if (ctx._chart) ctx._chart.destroy();

  // Bucket SCANS by day for 14 days
  const labels = [];
  const days = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    labels.push(d.toLocaleString(undefined, { month: 'short', day: 'numeric' }));
    days.push({ critical: 0, high: 0, medium: 0 });
  }
  SCANS.forEach(s => {
    if (!s.startedAt) return;
    const d = new Date(s.startedAt);
    d.setHours(0, 0, 0, 0);
    const idx = Math.round((d - today) / 86400000) + 13;
    if (idx >= 0 && idx < 14) {
      days[idx].critical += s.severity.critical || 0;
      days[idx].high += s.severity.high || 0;
      days[idx].medium += s.severity.medium || 0;
    }
  });

  ctx._chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Critical', data: days.map(d => d.critical), borderColor: getCss('--sev-critical'),
          backgroundColor: 'rgba(255, 59, 48, 0.10)', borderWidth: 2, fill: true, tension: 0.35,
          pointRadius: 0, pointHoverRadius: 4 },
        { label: 'High', data: days.map(d => d.high), borderColor: getCss('--sev-high'),
          backgroundColor: 'rgba(255, 149, 0, 0.08)', borderWidth: 2, fill: true, tension: 0.35,
          pointRadius: 0, pointHoverRadius: 4 },
        { label: 'Medium', data: days.map(d => d.medium), borderColor: getCss('--sev-medium'),
          backgroundColor: 'rgba(255, 204, 0, 0.06)', borderWidth: 2, fill: true, tension: 0.35,
          pointRadius: 0, pointHoverRadius: 4 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', align: 'end',
          labels: { color: getCss('--text-secondary'), font: { family: 'Inter', size: 12 },
            boxWidth: 8, boxHeight: 8, usePointStyle: true, pointStyle: 'circle' } },
        tooltip: { backgroundColor: getCss('--bg-elevated'), borderColor: getCss('--border-strong'),
          borderWidth: 1, titleColor: getCss('--text-primary'), bodyColor: getCss('--text-secondary') },
      },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: getCss('--text-muted'), font: { size: 11 } } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: getCss('--text-muted'), font: { size: 11 }, precision: 0 } },
      },
    },
  });
}

function getCss(varName) {
  return getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
}
