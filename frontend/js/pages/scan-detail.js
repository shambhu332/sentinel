// Scan Detail page — live view of a real scan via the API.
import { el, refreshIcons, formatDate, formatDuration, statusLabel, toast } from '../utils.js';
import { sevBadge, statusBadge } from '../components/severity-badge.js';
import { codeBlock } from '../components/code-block.js';
import { api, ApiError } from '../api.js';

const POLL_MS = 1500;
const ACTIVE_STATES = new Set(['queued', 'running']);
const PHASE_LABELS = {
  phase0: 'Phase 0 · Ingestion',
  phase1: 'Phase 1 · Recon (parallel)',
  phase2: 'Phase 2 · Agents',
  phase3: 'Phase 3 · LLM triage',
  phase4: 'Phase 4 · Dynamic / Frida',
};

let pollHandle = null;

export function renderScanDetail(main, scanId) {
  // Clear any pending poll from a previous render
  if (pollHandle) { clearTimeout(pollHandle); pollHandle = null; }

  main.appendChild(el('div', { id: `scan-shell-${scanId}` },
    el('div', { class: 'scan-loading' },
      el('div', { class: 'spinner' }),
      el('div', { class: 'text-muted', style: 'margin-top: 12px;' },
        'Fetching scan ', el('span', { class: 'mono' }, scanId), '…'),
    ),
  ));

  refreshIcons();
  loadAndRender(scanId).catch(err => renderError(scanId, err));
}

async function loadAndRender(scanId) {
  let summary;
  try {
    summary = await api.getScan(scanId);
  } catch (e) {
    return renderError(scanId, e);
  }
  paint(scanId, summary);

  if (ACTIVE_STATES.has(summary.status)) {
    pollHandle = setTimeout(() => loadAndRender(scanId), POLL_MS);
  }
}

function renderError(scanId, err) {
  const shell = document.getElementById(`scan-shell-${scanId}`);
  if (!shell) return;
  shell.innerHTML = '';
  const msg = err instanceof ApiError ? err.message : String(err);
  shell.appendChild(el('div', { class: 'empty-state' },
    el('i', { 'data-lucide': 'wifi-off' }),
    el('h3', {}, 'Could not load scan'),
    el('p', {}, msg),
    el('div', { style: 'display: flex; gap: 8px; margin-top: 16px;' },
      el('a', { href: '#scans', class: 'btn btn-secondary' }, 'Back to scans'),
      el('button', { class: 'btn btn-primary', onclick: () => loadAndRender(scanId) }, 'Retry'),
    ),
  ));
  refreshIcons();
}

async function paint(scanId, summary) {
  const shell = document.getElementById(`scan-shell-${scanId}`);
  if (!shell) return;

  // Findings + warnings come from /findings + /result. Only fetch them
  // when we actually have data — saves traffic during early phases.
  let findings = [];
  let result = null;
  if (summary.findings_count > 0 || summary.status === 'completed' || summary.status === 'failed') {
    try {
      const data = await api.getFindings(scanId);
      findings = data.findings || [];
    } catch (_) { /* ignore */ }
    try { result = await api.getResult(scanId); } catch (_) {}
  }

  shell.innerHTML = '';
  shell.appendChild(buildHeader(summary, findings));
  shell.appendChild(buildProgress(summary));

  // Tabs
  const tabs = el('div', { class: 'tabs' });
  const panes = el('div', { class: 'tab-panes' });
  const tabsConfig = [
    { id: 'summary',  label: 'Summary',  icon: 'layout-grid' },
    { id: 'findings', label: 'Findings', icon: 'shield-alert', count: findings.length },
    { id: 'vapt',     label: 'VAPT Report', icon: 'file-text' },
    { id: 'json',     label: 'Raw JSON', icon: 'braces' },
    { id: 'warn',     label: 'Warnings', icon: 'alert-triangle', count: (result?.warnings || []).length },
  ];
  tabsConfig.forEach((cfg, i) => {
    const tabBtn = el('button', { class: `tab ${i === 0 ? 'active' : ''}`, 'data-tab': cfg.id },
      el('i', { 'data-lucide': cfg.icon }),
      cfg.label,
      cfg.count !== undefined ? el('span', { class: 'tab-count' }, String(cfg.count)) : null,
    );
    tabBtn.addEventListener('click', () => activateTab(cfg.id));
    tabs.appendChild(tabBtn);
    panes.appendChild(el('div', { class: `tab-panel ${i === 0 ? 'active' : ''}`, 'data-pane': cfg.id }));
  });
  shell.appendChild(tabs);
  shell.appendChild(panes);

  renderSummaryPane(summary, findings, result);
  renderFindingsPane(findings, summary.status);
  renderVaptPane(scanId, summary);
  renderJsonPane(scanId, summary, result, findings);
  renderWarningsPane(result?.warnings || []);
  refreshIcons();
}

function activateTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === id));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.pane === id));
}

function buildHeader(summary, findings) {
  const manifest = summary.manifest || {};
  const pkg = manifest.package || '(package unknown)';
  const appName = summary.apk_filename || pkg;
  const initial = appName.replace(/\.apk$|\.aab$|\.xapk$/i, '').slice(0, 1).toUpperCase() || 'S';
  const sevCount = summary.severity_counts || {};
  const totalFindings = Object.values(sevCount).reduce((a, b) => a + (b || 0), 0);

  const header = el('div', { class: 'scan-detail-header' });
  const meta = el('div', { class: 'scan-meta' },
    el('a', { href: '#scans', class: 'text-muted', style: 'font-size: 12px;' }, '← All scans'),
    el('div', { class: 'scan-app' },
      el('div', { class: 'avatar avatar-lg' }, initial),
      appName,
      statusBadge(summary.status, statusLabel(summary.status)),
    ),
    el('div', { class: 'scan-pkg' }, `${pkg}${manifest.version_name ? ' · v' + manifest.version_name : ''}`),
    el('div', { class: 'scan-info' },
      el('span', {}, el('i', { 'data-lucide': 'hash', style: 'width: 12px; height: 12px; display: inline-block; vertical-align: middle;' }), ' ', el('span', { class: 'mono' }, summary.session_id)),
      el('span', { class: 'scan-info-dot' }),
      el('span', {}, formatDate(summary.created_at)),
      el('span', { class: 'scan-info-dot' }),
      el('span', {}, summary.completed_at ? `Duration: ${formatDuration(durationSec(summary))}` : 'Running…'),
      el('span', { class: 'scan-info-dot' }),
      el('span', {}, `${totalFindings} finding${totalFindings !== 1 ? 's' : ''}`),
    ),
  );

  const actions = el('div', { class: 'page-actions' },
    el('button', { class: 'btn btn-secondary', onclick: () => downloadJson(summary.session_id) },
      el('i', { 'data-lucide': 'braces' }), 'Download JSON'),
    el('button', { class: 'btn btn-secondary', onclick: () => { navigator.clipboard.writeText(location.href); toast('Share link copied', 'success'); } },
      el('i', { 'data-lucide': 'share-2' }), 'Share'),
  );
  header.append(meta, actions);
  return header;
}

function durationSec(summary) {
  if (!summary.started_at || !summary.completed_at) return 0;
  return Math.max(0, Math.round((new Date(summary.completed_at) - new Date(summary.started_at)) / 1000));
}

function buildProgress(summary) {
  // Live phase strip — green check for done, pulse for in-flight, dim for skipped.
  const phases = ['phase0', 'phase1', 'phase2', 'phase3', 'phase4'];
  const timings = summary.phase_timings || {};
  const card = el('div', { class: 'card', style: 'padding: 16px; margin-bottom: 16px;' },
    el('div', { class: 'card-header', style: 'margin: 0 0 12px;' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'activity' }), 'Pipeline progress'),
      el('span', { class: 'text-muted', style: 'font-size: 12px;' },
        summary.phase ? `phase: ${summary.phase}` : ''),
    ),
    el('div', { class: 'phase-progress' },
      ...phases.map(p => {
        const done = timings[p] !== undefined;
        const active = ACTIVE_STATES.has(summary.status) && !done;
        const cls = done ? 'done' : (active ? 'active' : 'pending');
        return el('div', { class: `phase-pill ${cls}` },
          el('div', { class: 'phase-pill-name' }, PHASE_LABELS[p].replace(/^Phase \d+ · /, '')),
          el('div', { class: 'phase-pill-time' },
            done ? formatDuration(Math.max(1, Math.round(timings[p]))) : (active ? '…' : '—')),
        );
      }),
    ),
  );
  return card;
}

function renderSummaryPane(summary, findings, result) {
  const pane = document.querySelector('[data-pane="summary"]');
  const sev = summary.severity_counts || {};

  pane.appendChild(el('div', { class: 'severity-cards' },
    sevCard('crit', 'Critical', sev.critical || 0),
    sevCard('high', 'High', sev.high || 0),
    sevCard('med',  'Medium', sev.medium || 0),
    sevCard('low',  'Low', sev.low || 0),
  ));

  const row = el('div', { style: 'display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;' });
  if (window.matchMedia && window.matchMedia('(max-width: 800px)').matches) {
    row.style.gridTemplateColumns = '1fr';
  }

  // Phase timings
  const timings = summary.phase_timings || {};
  const timingRows = Object.entries(timings).map(([k, v]) => ({ name: PHASE_LABELS[k] || k, sec: v }));
  const maxSec = Math.max(...timingRows.map(t => t.sec), 1);
  row.appendChild(el('div', { class: 'card' },
    el('div', { class: 'card-header' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'clock' }), 'Phase timings'),
    ),
    el('div', { class: 'phase-list' },
      ...(timingRows.length ? timingRows : [{ name: 'No phases completed yet', sec: 0 }]).map(t => el('div', { class: 'phase-row' },
        el('span', { class: 'phase-name' }, t.name),
        el('div', { class: 'phase-bar' }, el('div', { class: 'phase-bar-fill', style: `width: ${(t.sec / maxSec * 100).toFixed(1)}%` })),
        el('span', { class: 'phase-time' }, formatDuration(Math.max(0, Math.round(t.sec)))),
      )),
    ),
  ));

  // Triage breakdown
  const triage = summary.triage_counts || {};
  const triageMax = Math.max(triage.verified || 0, triage.filtered || 0, triage.uncertain || 0, triage.skipped || 0, 1);
  row.appendChild(el('div', { class: 'card' },
    el('div', { class: 'card-header' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'filter' }), 'LLM triage'),
      el('span', { class: 'badge accent' },
        (summary.options && summary.options.llm_triage) ? 'enabled' : 'skipped'),
    ),
    el('div', { class: 'phase-list' },
      ...[
        ['Verified',  'verified',  'var(--success)'],
        ['Uncertain', 'uncertain', 'var(--sev-medium)'],
        ['Filtered',  'filtered',  'var(--text-muted)'],
        ['Skipped',   'skipped',   'var(--text-muted)'],
      ].map(([label, key, color]) => el('div', { class: 'phase-row' },
        el('span', { class: 'phase-name', style: `color: ${color};` }, label),
        el('div', { class: 'phase-bar' }, el('div', { class: 'phase-bar-fill', style: `width: ${((triage[key] || 0) / triageMax * 100)}%; background: ${color};` })),
        el('span', { class: 'phase-time' }, String(triage[key] || 0)),
      )),
    ),
  ));
  pane.appendChild(row);

  // APK metadata
  const m = summary.manifest || {};
  const metaCard = el('div', { class: 'card' },
    el('div', { class: 'card-header' },
      el('div', { class: 'card-title' }, el('i', { 'data-lucide': 'package' }), 'APK metadata'),
    ),
    el('div', { class: 'kv-grid' },
      kv('Package',    m.package || '—'),
      kv('Version',    m.version_name || '—'),
      kv('Target SDK', m.target_sdk ? String(m.target_sdk) : '—'),
      kv('Permissions', m.permissions_count != null ? String(m.permissions_count) : '—'),
      kv('Activities',  m.activities_count  != null ? String(m.activities_count)  : '—'),
      kv('SHA-256',     summary.apk_sha256 ? summary.apk_sha256.slice(0, 16) + '…' : '—'),
      kv('Size',        summary.apk_size_bytes ? humanBytes(summary.apk_size_bytes) : '—'),
      kv('Started',     summary.started_at ? formatDate(summary.started_at) : '—'),
    ),
  );
  pane.appendChild(metaCard);

  // If still running, helpful hint
  if (ACTIVE_STATES.has(summary.status)) {
    pane.appendChild(el('div', { class: 'card', style: 'margin-top: 16px; border-color: var(--accent-primary); padding: 14px 16px;' },
      el('div', { style: 'display: flex; gap: 12px; align-items: center;' },
        el('div', { class: 'spinner-sm' }),
        el('div', {},
          el('div', { style: 'font-weight: 600;' }, 'Scan running'),
          el('div', { class: 'text-muted', style: 'font-size: 12px;' },
            'Progress polls every ' + (POLL_MS / 1000) + 's. Findings will populate as agents finish.'),
        ),
      ),
    ));
  } else if (summary.status === 'failed' && summary.error) {
    pane.appendChild(el('div', { class: 'card', style: 'margin-top: 16px; border-color: var(--sev-critical); padding: 14px 16px;' },
      el('div', { style: 'display: flex; gap: 10px; align-items: flex-start;' },
        el('i', { 'data-lucide': 'alert-octagon', style: 'color: var(--sev-critical); flex-shrink: 0;' }),
        el('div', {},
          el('div', { style: 'font-weight: 600; color: var(--sev-critical);' }, 'Scan failed'),
          el('div', { class: 'text-muted', style: 'font-size: 13px; margin-top: 4px;' }, summary.error),
        ),
      ),
    ));
  }

  refreshIcons();
}

function kv(k, v) {
  return el('div', { class: 'kv-row' },
    el('span', { class: 'kv-key' }, k),
    el('span', { class: 'kv-val mono' }, v),
  );
}

function humanBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function sevCard(cls, label, count) {
  return el('div', { class: `severity-card ${cls}` },
    el('div', { class: 'sev-label' }, label),
    el('div', { class: 'sev-count' }, String(count)),
  );
}

function renderFindingsPane(findings, status) {
  const pane = document.querySelector('[data-pane="findings"]');
  pane.innerHTML = '';

  if (!findings.length) {
    if (ACTIVE_STATES.has(status)) {
      pane.appendChild(el('div', { class: 'empty-state' },
        el('div', { class: 'spinner' }),
        el('h3', { style: 'margin-top: 14px;' }, 'No findings yet'),
        el('p', {}, 'Phase 2 agents are still running. This panel updates automatically.'),
      ));
    } else if (status === 'completed') {
      pane.appendChild(el('div', { class: 'empty-state' },
        el('i', { 'data-lucide': 'shield-check' }),
        el('h3', {}, 'No findings produced'),
        el('p', {}, 'Every applicable agent ran and returned clean.'),
      ));
    } else {
      pane.appendChild(el('div', { class: 'empty-state' },
        el('i', { 'data-lucide': 'shield-off' }),
        el('h3', {}, 'No findings'),
        el('p', {}, 'Scan did not produce any findings.'),
      ));
    }
    refreshIcons();
    return;
  }

  // sort: severity then confidence
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const rows = [...findings].sort((a, b) =>
    (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9) || (b.confidence - a.confidence));

  pane.appendChild(el('div', { style: 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; gap: 12px; flex-wrap: wrap;' },
    el('div', { class: 'text-secondary', style: 'font-size: 13px;' },
      `${rows.length} finding${rows.length !== 1 ? 's' : ''}`),
  ));

  const wrap = el('div', { class: 'table-wrap' });
  const table = el('table', { class: 'table' });
  table.appendChild(el('thead', {}, el('tr', {},
    el('th', { style: 'width: 90px;' }, 'Severity'),
    el('th', { style: 'width: 90px;' }, 'Agent'),
    el('th', {}, 'Vulnerability'),
    el('th', { style: 'width: 120px;' }, 'Triage'),
    el('th', { style: 'width: 120px;' }, 'Verify'),
    el('th', { style: 'width: 70px;' }, 'Conf.'),
    el('th', {}, 'Recommendation'),
  )));
  const tbody = el('tbody');
  rows.forEach(f => {
    const tr = el('tr', { class: 'clickable', onclick: () => showFindingDetail(f) });
    tr.append(
      el('td', {}, sevBadge(f.severity, f.severity_label || f.severity)),
      el('td', {}, el('span', { class: 'mono', style: 'font-size: 12px;' }, f.agent_id)),
      el('td', {}, f.vuln_class),
      el('td', {}, triageChip(f.triage)),
      el('td', {}, verifyChip(f)),
      el('td', {}, el('span', { class: 'mono', style: 'font-size: 12px;' }, (f.confidence * 100).toFixed(0) + '%')),
      el('td', {}, el('span', { class: 'text-muted', style: 'font-size: 13px;' },
        f.recommendation && f.recommendation.length > 100 ? f.recommendation.slice(0, 100) + '…' : f.recommendation)),
    );
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  pane.appendChild(wrap);
  refreshIcons();
}

function triageChip(t) {
  const map = {
    verified:  { label: '✓ verified',  cls: 'badge-success' },
    filtered:  { label: '✗ filtered',  cls: 'badge-muted' },
    uncertain: { label: '? uncertain', cls: 'badge-warning' },
    skipped:   { label: '— skipped',   cls: 'badge-muted' },
  };
  const c = map[t] || map.skipped;
  return el('span', { class: `badge ${c.cls}`, style: 'font-size: 11px;' }, c.label);
}

function verifyChip(f) {
  // The verify engine writes its result under evidence._verify.
  // Outcomes: verified / refuted / inconclusive / unsupported.
  const v = (f.evidence && f.evidence._verify) || null;
  if (!v) {
    return el('span', { class: 'badge badge-muted', style: 'font-size: 11px;', title: 'no verifier ran' },
      '—');
  }
  const out = String(v.outcome || '').toLowerCase();
  const method = v.method || '';
  const tooltip = method ? `${out} (${method})` : out;
  const map = {
    verified:     { label: '✓ verified',     cls: 'badge-success' },
    refuted:      { label: '✗ refuted',      cls: 'badge-muted' },
    inconclusive: { label: '? inconclusive', cls: 'badge-warning' },
    unsupported: { label: '— unsupported',  cls: 'badge-muted' },
  };
  const c = map[out] || map.unsupported;
  return el('span', { class: `badge ${c.cls}`, style: 'font-size: 11px;', title: tooltip },
    c.label);
}

function showFindingDetail(f) {
  const ev = f.evidence || {};
  const ordered = Object.entries(ev).filter(([k]) => !k.startsWith('_'));
  const evidenceText = ordered.length
    ? ordered.map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v, null, 2)}`).join('\n')
    : '(no evidence)';

  // Lightweight inline modal — reuse the existing modal helper via dynamic import
  import('../components/modal.js').then(({ openModal }) => {
    const body = el('div', {},
      el('div', { style: 'display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap;' },
        sevBadge(f.severity, f.severity_label || f.severity),
        el('span', { class: 'mono', style: 'font-size: 12px;' }, f.agent_id),
        triageChip(f.triage),
        verifyChip(f),
        el('span', { class: 'mono text-muted', style: 'font-size: 12px;' }, (f.confidence * 100).toFixed(0) + '% confidence'),
      ),
      el('h4', { style: 'margin-bottom: 8px;' }, f.vuln_class),
      el('div', { class: 'text-secondary', style: 'margin-bottom: 16px;' }, f.recommendation),
      el('h5', { style: 'margin: 12px 0 6px; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; color: var(--text-muted);' }, 'Evidence'),
      codeBlock(evidenceText, { showLineNumbers: false }),
    );
    // Verifier verdict block — outcome, method, notes, and any
    // evidence the verifier captured during its run.
    const verify = ev._verify;
    if (verify) {
      const verifyBody = `outcome: ${verify.outcome || '—'}\n`
        + `method:  ${verify.method || '—'}\n`
        + (verify.notes ? `notes:   ${verify.notes}\n` : '')
        + (verify.evidence && Object.keys(verify.evidence).length
            ? `evidence:\n${JSON.stringify(verify.evidence, null, 2)}`
            : '');
      body.appendChild(el('h5', {
        style: 'margin: 16px 0 6px; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; color: var(--text-muted);',
      }, 'Verifier'));
      body.appendChild(codeBlock(verifyBody, { showLineNumbers: false }));
    }
    if (f.owasp || f.masvs || f.cvss_vector) {
      const tags = el('div', { style: 'display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px;' });
      if (f.owasp)        tags.appendChild(el('span', { class: 'badge' }, 'OWASP ', f.owasp));
      if (f.masvs)        tags.appendChild(el('span', { class: 'badge' }, 'MASVS ', f.masvs));
      if (f.cvss_vector)  tags.appendChild(el('span', { class: 'badge mono', style: 'font-size: 11px;' }, f.cvss_vector));
      body.appendChild(tags);
    }
    openModal({ title: f.vuln_class, body, size: 'lg' });
  });
}

function renderJsonPane(scanId, summary, result, findings) {
  const pane = document.querySelector('[data-pane="json"]');
  pane.innerHTML = '';
  pane.appendChild(el('div', { style: 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;' },
    el('h3', { style: 'font-size: 18px;' }, 'Raw scan output'),
    el('div', { style: 'display: flex; gap: 8px;' },
      el('button', { class: 'btn btn-secondary btn-sm',
        onclick: () => { navigator.clipboard.writeText(JSON.stringify(result || summary, null, 2)); toast('JSON copied', 'success'); } },
        el('i', { 'data-lucide': 'copy' }), 'Copy'),
      el('button', { class: 'btn btn-secondary btn-sm', onclick: () => downloadJson(scanId) },
        el('i', { 'data-lucide': 'download' }), 'Download'),
    ),
  ));
  const json = JSON.stringify(result || { summary, findings }, null, 2);
  pane.appendChild(codeBlock(json, { showLineNumbers: true }));
  refreshIcons();
}

function renderVaptPane(scanId, summary) {
  const pane = document.querySelector('[data-pane="vapt"]');
  pane.innerHTML = '';

  // If the scan hasn't finished Phase 8 yet, the report isn't on disk.
  // Probe /reports first; the iframe fallback would only show a 404 page.
  api.listReports().then((reports) => {
    const found = (reports || []).some(r => r.session_id === scanId);
    if (!found) {
      pane.appendChild(el('div', { class: 'empty-state' },
        el('i', { 'data-lucide': 'file-clock' }),
        el('h3', {}, 'VAPT report not yet generated'),
        el('p', {}, ACTIVE_STATES.has(summary.status)
          ? 'The report is produced during Phase 8 (Reporting) after analysis completes. This pane will refresh when the scan finishes.'
          : 'No report artifact was found on disk for this scan. Re-run the scan or check workspace permissions.'),
      ));
      refreshIcons();
      return;
    }
    mountVaptIframe(pane, scanId);
  }).catch(() => {
    pane.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'wifi-off' }),
      el('h3', {}, 'Could not reach the reports service'),
      el('p', {}, 'Check that the gateway is running and try again.'),
    ));
    refreshIcons();
  });
}

function mountVaptIframe(pane, scanId) {
  const htmlUrl = api.reportUrl(scanId, 'html');
  const mdUrl   = api.reportUrl(scanId, 'markdown');
  const jsonUrl = api.reportUrl(scanId, 'json');

  const toolbar = el('div', {
    style: 'display:flex; justify-content:space-between; align-items:center; '
         + 'gap:12px; margin-bottom: 12px; flex-wrap: wrap;',
  },
    el('div', { style: 'display:flex; align-items:center; gap:8px;' },
      el('i', { 'data-lucide': 'shield-check', style: 'width:16px;height:16px;color:var(--accent-2,#22d3ee);' }),
      el('div', {},
        el('div', { style: 'font-weight:600;' }, 'Professional VAPT Report'),
        el('div', { class: 'text-muted', style: 'font-size:12px;' },
          'Client-ready engagement deliverable · ', el('span', { class: 'mono' }, scanId)),
      ),
    ),
    el('div', { style: 'display:flex; gap:8px;' },
      el('button', {
        class: 'btn btn-secondary btn-sm',
        onclick: () => printVaptIframe(),
      },
        el('i', { 'data-lucide': 'printer' }), 'Export PDF'),
      el('a', {
        class: 'btn btn-secondary btn-sm',
        href: htmlUrl, target: '_blank', rel: 'noopener',
      },
        el('i', { 'data-lucide': 'external-link' }), 'Open full'),
      el('a', {
        class: 'btn btn-secondary btn-sm',
        href: htmlUrl, download: `VAPT_Report_${scanId}.html`,
      },
        el('i', { 'data-lucide': 'download' }), 'HTML'),
      el('a', {
        class: 'btn btn-secondary btn-sm',
        href: mdUrl, download: `VAPT_Report_${scanId}.md`,
      },
        el('i', { 'data-lucide': 'file-down' }), 'Markdown'),
      el('a', {
        class: 'btn btn-secondary btn-sm',
        href: jsonUrl, download: `VAPT_Report_${scanId}.json`,
      },
        el('i', { 'data-lucide': 'braces' }), 'JSON'),
    ),
  );

  const frame = el('iframe', {
    id: 'vapt-frame',
    src: htmlUrl,
    title: 'VAPT Report',
    style: 'width:100%; height: calc(100vh - 240px); min-height: 600px; '
         + 'border: 1px solid var(--border, #1F2940); border-radius: 8px; '
         + 'background: white;',
  });

  pane.appendChild(toolbar);
  pane.appendChild(frame);
  refreshIcons();
}

function printVaptIframe() {
  const frame = document.getElementById('vapt-frame');
  if (!frame) return;
  try {
    frame.contentWindow.focus();
    frame.contentWindow.print();
  } catch (e) {
    toast('Print failed — opening report in a new tab instead', 'error');
    window.open(frame.src, '_blank');
  }
}

function renderWarningsPane(warnings) {
  const pane = document.querySelector('[data-pane="warn"]');
  pane.innerHTML = '';
  if (!warnings || !warnings.length) {
    pane.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'check-circle' }),
      el('h3', {}, 'No warnings'),
      el('p', {}, 'This scan completed cleanly.'),
    ));
    refreshIcons();
    return;
  }
  pane.appendChild(el('h3', { style: 'margin-bottom: 12px;' },
    `${warnings.length} warning${warnings.length > 1 ? 's' : ''}`));
  warnings.forEach(w => {
    pane.appendChild(el('div', { class: 'warning-item' },
      el('i', { 'data-lucide': 'alert-triangle' }),
      el('div', { style: 'flex: 1;' }, el('div', { class: 'warn-title' }, w)),
    ));
  });
  refreshIcons();
}

async function downloadJson(scanId) {
  try {
    const result = await api.getResult(scanId);
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    toast('Download failed: ' + (e.message || e), 'error');
  }
}
