// Reports page — lists VAPT artifacts produced by R_001 (Phase 8).
// Falls back to a clear offline banner with a "Settings ▸ Connection"
// link so the user can recover when the gateway is down.

import { el, refreshIcons, timeAgo } from '../utils.js';
import { api, ApiError } from '../api.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'C', high: 'H', medium: 'M', low: 'L', info: 'I' };

export function renderReportsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'VAPT Reports'),
      el('div', { class: 'page-subtitle' },
        'Markdown, HTML, and JSON artifacts produced by Phase 8 (R_001). One bundle per completed scan.',
      ),
    ),
    el('div', { class: 'page-actions' },
      el('button', {
        class: 'btn btn-secondary',
        onclick: () => location.reload(),
      },
        el('i', { 'data-lucide': 'rotate-cw' }),
        'Refresh',
      ),
    ),
  ));

  const status = el('div', { id: 'reports-status' });
  const container = el('div', { id: 'reports-container' });
  main.appendChild(status);
  main.appendChild(container);

  loadReports(status, container);
  refreshIcons();
}

async function loadReports(statusEl, container) {
  statusEl.innerHTML = '';
  container.innerHTML = '';

  let reports;
  try {
    reports = await api.listReports();
  } catch (e) {
    container.appendChild(buildOfflineBanner(e));
    refreshIcons();
    return;
  }

  if (!Array.isArray(reports) || reports.length === 0) {
    container.appendChild(buildEmptyState());
    refreshIcons();
    return;
  }

  statusEl.appendChild(el('div', { class: 'reports-summary' },
    el('span', { class: 'reports-summary-count' }, `${reports.length}`),
    ' report', reports.length === 1 ? '' : 's',
    ' generated · click any artifact to open in a new tab',
  ));

  const grid = el('div', { class: 'reports-grid' });
  for (const r of reports) {
    grid.appendChild(buildReportCard(r));
  }
  container.appendChild(grid);
  refreshIcons();
}

function buildReportCard(r) {
  const total = r.total_findings || 0;
  const sev = r.severity_counts || {};
  const riskBand = (r.risk_band || 'low').toLowerCase();
  const riskScore = r.risk_score != null ? r.risk_score : '—';

  const card = el('div', { class: 'card reports-card' });

  card.appendChild(el('div', { class: 'reports-card-head' },
    el('div', { class: 'reports-card-package' },
      el('div', { class: 'reports-card-pkg-name' },
        r.package || el('span', { class: 'reports-card-pkg-placeholder' }, '(unknown package)'),
      ),
      r.version ? el('div', { class: 'reports-card-pkg-version mono' }, `v${r.version}`) : null,
    ),
    el('div', { class: `reports-card-risk reports-card-risk-${riskBand}` },
      el('div', { class: 'reports-card-risk-score' }, `${riskScore}`),
      el('div', { class: 'reports-card-risk-band' }, riskBand),
    ),
  ));

  const chips = el('div', { class: 'reports-card-sev' });
  for (const k of SEV_ORDER) {
    const n = sev[k] || 0;
    if (n === 0 && k !== 'critical' && k !== 'high') continue;
    chips.appendChild(el('span', { class: `sev-pill sev-pill-${k}` },
      `${SEV_LABEL[k]}:${n}`,
    ));
  }
  card.appendChild(chips);

  card.appendChild(el('div', { class: 'reports-card-meta' },
    el('span', {},
      el('i', { 'data-lucide': 'clock' }), ' ', timeAgoSafe(r.generated_at),
    ),
    el('span', {},
      el('i', { 'data-lucide': 'shield-check' }),
      ' ', `${total} finding${total === 1 ? '' : 's'}`,
    ),
    el('span', { class: 'mono reports-card-session', title: r.session_id },
      r.session_id.slice(0, 12), '…',
    ),
  ));

  const formats = r.formats || {};
  const btns = el('div', { class: 'reports-card-buttons' });
  const order = [
    { key: 'html', label: 'Open HTML', icon: 'external-link', primary: true },
    { key: 'markdown', label: 'Markdown', icon: 'file-text', ext: '.md' },
    { key: 'json', label: 'JSON', icon: 'braces', ext: '.json' },
    { key: 'sarif', label: 'SARIF', icon: 'shield-check', ext: '.sarif' },
  ];
  // Always-available extras (generated on-demand from the JSON report
  // by /reports/{session}/{siem.zip,poc/index.json} so they don't
  // need a slot in `formats`).
  const extras = [
    { key: 'siem.zip', label: 'SIEM rules', icon: 'shield',
      filename: `sentinel-siem-${r.session_id}.zip` },
    { key: 'poc/index.json', label: 'PoCs', icon: 'play',
      filename: `poc-index-${r.session_id}.json` },
  ];

  for (const f of order) {
    const meta = formats[f.key];
    if (!meta || !meta.available) {
      btns.appendChild(el('button', {
        class: 'btn btn-ghost btn-sm',
        disabled: true,
        title: `${f.key} not generated for this scan`,
      },
        el('i', { 'data-lucide': f.icon }),
        f.label,
      ));
      continue;
    }
    const target = api.reportUrl(r.session_id, f.key);
    btns.appendChild(el('a', {
      class: `btn ${f.primary ? 'btn-primary' : 'btn-secondary'} btn-sm`,
      href: target,
      target: '_blank',
      rel: 'noopener',
      ...(f.ext ? { download: `VAPT_Report_${r.session_id}${f.ext}` } : {}),
    },
      el('i', { 'data-lucide': f.icon }),
      f.label,
      meta.size_bytes
        ? el('span', { class: 'reports-card-size' }, formatBytes(meta.size_bytes))
        : null,
    ));
  }
  for (const ex of extras) {
    btns.appendChild(el('a', {
      class: 'btn btn-ghost btn-sm',
      href: `/reports/${encodeURIComponent(r.session_id)}/${ex.key}`,
      target: '_blank',
      rel: 'noopener',
      download: ex.filename,
      title: ex.label,
    },
      el('i', { 'data-lucide': ex.icon }),
      ex.label,
    ));
  }
  card.appendChild(btns);

  return card;
}

function buildEmptyState() {
  return el('div', { class: 'card reports-empty' },
    el('i', { 'data-lucide': 'file-search', class: 'reports-empty-icon' }),
    el('h3', {}, 'No VAPT reports yet'),
    el('p', { class: 'reports-empty-text' },
      'Run a scan with ',
      el('code', { class: 'inline' }, 'poetry run sentinel scan path/to/app.apk'),
      ' or use the ',
      el('strong', {}, '+ New scan'),
      ' button — Phase 8 of every completed scan writes a markdown, ',
      'HTML, and JSON report to the workspace and they show up here ',
      'automatically.',
    ),
    el('a', { class: 'btn btn-primary', href: '#scans' },
      el('i', { 'data-lucide': 'shield-check' }),
      'Go to scans',
    ),
  );
}

function buildOfflineBanner(err) {
  const msg = err instanceof ApiError ? err.message : String(err);
  return el('div', { class: 'card offline-banner' },
    el('div', { class: 'offline-banner-row' },
      el('i', { 'data-lucide': 'wifi-off', class: 'offline-banner-icon' }),
      el('div', { style: 'font-size: 13px; flex: 1;' },
        el('strong', {}, 'Cannot load reports. '),
        msg, ' · ',
        el('a', { href: '#settings', class: 'offline-banner-link' },
          el('i', { 'data-lucide': 'settings', style: 'width: 14px; height: 14px;' }),
          'Settings ▸ Connection',
        ),
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

function timeAgoSafe(iso) {
  if (!iso) return 'unknown';
  try { return timeAgo(new Date(iso)); }
  catch (_) { return iso; }
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
