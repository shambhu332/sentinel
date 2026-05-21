/**
 * dashboard.js — welcome dashboard.
 * Greeting + quick stats · active project · two charts ·
 * recent scans · activity feed · quickstart cards.
 */

import { SCANS, recentScans, aggregateCounts, trendSeries } from '../data/scans.js';
import { PROJECTS, getProject } from '../data/projects.js';
import { severityChipsRow } from '../components/severity-chip.js';
import { severityDonut, trendChart } from '../components/charts.js';
import { openNewScanModal } from '../components/scan-runner.js';

const STATUS_CHIP = {
  completed: '<span class="chip chip-status-completed">completed</span>',
  running:   '<span class="chip chip-status-running"><span class="sev-dot sev-dot-medium pulse-ring"></span> running</span>',
  failed:    '<span class="chip chip-status-failed">failed</span>',
};

function relative(ts) {
  if (!ts) return '—';
  const now = new Date('2026-05-21T10:00:00Z');
  const t   = new Date(ts.replace(' ', 'T') + 'Z');
  const mins = Math.round((now - t) / 60_000);
  if (mins < 60)            return `${mins} min ago`;
  if (mins < 60 * 24)       return `${Math.round(mins / 60)} h ago`;
  if (mins < 60 * 24 * 7)   return `${Math.round(mins / 1440)} d ago`;
  return ts.slice(0, 10);
}

export function renderDashboard(mount) {
  const totals = aggregateCounts(SCANS);
  const recent = recentScans(5);
  const active = getProject('p_banking') || PROJECTS[0];

  mount.innerHTML = `
    <div class="greeting">
      <div>
        <h1>Welcome back, <span class="gradient-text">Nehal</span></h1>
        <div class="greeting-date">Thursday · May 21, 2026</div>
      </div>
      <div class="quick-stats">
        <div class="quick-stat"><span class="quick-stat-num">${SCANS.length}</span><span class="quick-stat-label">Total scans</span></div>
        <div class="quick-stat"><span class="quick-stat-num" style="color: var(--sev-critical);">${totals.critical}</span><span class="quick-stat-label">Critical</span></div>
        <div class="quick-stat"><span class="quick-stat-num" style="color: var(--sev-high);">${totals.high}</span><span class="quick-stat-label">High</span></div>
        <div class="quick-stat"><span class="quick-stat-num" style="color: var(--sev-medium);">${totals.medium}</span><span class="quick-stat-label">Medium</span></div>
      </div>
    </div>

    <!-- ACTIVE PROJECT -->
    <div class="active-project">
      <div>
        <div class="row-sm mb-2">
          <span class="chip chip-status-active">Active project</span>
          <span class="text-mute text-xs">·</span>
          <span class="text-mute text-xs">last scan ${relative(active.lastScanAt)}</span>
        </div>
        <h3 style="font-size: var(--fs-lg); margin-bottom: 4px;">${active.name}</h3>
        <code class="mono" style="font-size:12px;">${active.targetPackage}</code>
        <div class="text-dim text-sm mt-2">${active.description}</div>
      </div>
      <div class="active-project-actions">
        <button class="btn btn-secondary btn-sm" onclick="location.hash='projects/${active.id}'">
          <i data-lucide="external-link"></i> View
        </button>
        <button class="btn btn-primary btn-sm" id="dash-scan-now"><i data-lucide="play"></i> Scan now</button>
      </div>
    </div>

    <!-- A target div the scan-runner mounts into when "Scan now" runs -->
    <div id="dashboard-runner-target" class="mb-6"></div>

    <!-- CHARTS -->
    <div class="dash-grid">
      <div class="chart-card">
        <div class="chart-card-head">
          <div>
            <div class="card-title">Severity distribution</div>
            <div class="card-subtitle">All scans this month</div>
          </div>
          <span class="chip chip-cat">${SCANS.length} scans</span>
        </div>
        <div class="chart-canvas-wrap"><canvas id="dash-donut"></canvas></div>
      </div>

      <div class="chart-card">
        <div class="chart-card-head">
          <div>
            <div class="card-title">Findings trend</div>
            <div class="card-subtitle">Last 14 days · Critical + High</div>
          </div>
          <span class="chip chip-cat">14 d</span>
        </div>
        <div class="chart-canvas-wrap"><canvas id="dash-trend"></canvas></div>
      </div>
    </div>

    <!-- RECENT SCANS + ACTIVITY FEED -->
    <div class="dash-grid">
      <div class="card" style="grid-column: span 1;">
        <div class="card-header">
          <div class="card-title">Recent scans</div>
          <a class="btn btn-ghost btn-sm" href="#history">All <i data-lucide="arrow-right"></i></a>
        </div>
        <div class="table-wrap" style="border:none;">
          <table class="table">
            <thead>
              <tr>
                <th>Project</th>
                <th>APK</th>
                <th>Findings</th>
                <th>Status</th>
                <th class="text-right">Started</th>
              </tr>
            </thead>
            <tbody>
              ${recent.map((s) => {
                const p = getProject(s.projectId);
                return `
                  <tr onclick="location.hash='history/${s.id}'">
                    <td>${p?.name || '—'}</td>
                    <td><code class="mono" style="font-size:12px;">${s.apkName}</code><div class="text-xs text-mute">${s.apkSize} MB</div></td>
                    <td>${severityChipsRow(s.counts)}</td>
                    <td>${STATUS_CHIP[s.status]}</td>
                    <td class="text-right text-dim text-xs" title="${s.startedAt}">${relative(s.startedAt)}</td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Recent activity</div>
          <span class="chip chip-cat">live</span>
        </div>
        <div class="activity-feed">
          <div class="activity-item">
            <span class="activity-icon"><i data-lucide="shield-alert"></i></span>
            <div class="activity-text">
              <strong>N_005</strong> found pinning bypass in <code class="mono" style="font-size:12px;">campus.apk</code>
              <div class="activity-time">2h ago</div>
            </div>
          </div>
          <div class="activity-item">
            <span class="activity-icon"><i data-lucide="check-circle-2"></i></span>
            <div class="activity-text">
              Scan <strong>twitter-android</strong> completed with 14 findings
              <div class="activity-time">yesterday</div>
            </div>
          </div>
          <div class="activity-item">
            <span class="activity-icon"><i data-lucide="zap"></i></span>
            <div class="activity-text">
              Groq rate-limited, fell back to Cerebras
              <div class="activity-time">yesterday</div>
            </div>
          </div>
          <div class="activity-item">
            <span class="activity-icon"><i data-lucide="target"></i></span>
            <div class="activity-text">
              Bug bounty scope updated for project <strong>Mobile Banking Audit</strong>
              <div class="activity-time">2 d ago</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- QUICKSTART -->
    <h6 class="mt-8 mb-4">Quickstart</h6>
    <div class="quickstart">
      <a class="quickstart-card" href="#demo">
        <span class="icon-tile"><i data-lucide="play-circle"></i></span>
        <div class="card-title">Try the demo</div>
        <div class="text-dim text-sm">Run a simulated end-to-end scan in your browser — no install.</div>
      </a>
      <a class="quickstart-card" href="#agents">
        <span class="icon-tile"><i data-lucide="bot"></i></span>
        <div class="card-title">Browse agents</div>
        <div class="text-dim text-sm">Catalog of all 20 analysis agents with detection logic and FP notes.</div>
      </a>
      <a class="quickstart-card" href="#architecture">
        <span class="icon-tile"><i data-lucide="network"></i></span>
        <div class="card-title">Read architecture</div>
        <div class="text-dim text-sm">Pipeline phases, tool layer, Frida hook script, and crash-proof design.</div>
      </a>
    </div>
  `;

  mount.querySelector('#dash-scan-now').addEventListener('click', () => openNewScanModal({ projectId: active.id }));

  /* Init charts once Chart.js + canvases are in DOM */
  const donutCanvas = mount.querySelector('#dash-donut');
  const trendCanvas = mount.querySelector('#dash-trend');
  const initCharts = () => {
    if (window.Chart) {
      severityDonut(donutCanvas, totals);
      trendChart(trendCanvas, trendSeries(14, '2026-05-21'));
    } else {
      setTimeout(initCharts, 80);
    }
  };
  initCharts();
}
