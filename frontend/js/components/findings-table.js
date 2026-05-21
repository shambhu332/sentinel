/**
 * findings-table.js — reusable findings table widget.
 * Renders an array of findings with severity + triage chips, agent id,
 * file/evidence preview, and a kebab actions menu.
 */

import { severityChip } from './severity-chip.js';
import { triageChip } from './triage-chip.js';
import { getAgent } from '../data/agents.js';

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

function evidencePreview(ev) {
  if (!ev) return '';
  if (ev.kind === 'frida') {
    return `<code class="mono">${escape(ev.fridaEvent || '')}</code>`;
  }
  if (ev.kind === 'request') {
    return `<code class="mono">${escape(ev.request || '')}</code>`;
  }
  return `<code class="mono">${escape(ev.file || '')}</code>`;
}

function escape(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

/**
 * Render the findings table into an existing container.
 * @param {HTMLElement} container
 * @param {Array} findings
 * @param {object} [opts]
 * @param {boolean} [opts.compact=false]
 */
export function renderFindingsTable(container, findings, opts = {}) {
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  if (!sorted.length) {
    container.innerHTML = `
      <div class="empty">
        <i data-lucide="search-x"></i>
        <h3>No findings in this view</h3>
        <p>Try widening the filter or re-running the scan.</p>
      </div>`;
    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
    return;
  }

  const rows = sorted.map((f) => {
    const agent = getAgent(f.agentId);
    return `
      <tr data-finding-id="${f.id}">
        <td>${severityChip(f.severity)}</td>
        <td>${triageChip(f.triage)}</td>
        <td>
          <div class="mono" style="font-size:12px; color: var(--accent-2);">${f.agentId}</div>
          <div class="text-dim text-xs">${agent?.name || ''}</div>
        </td>
        <td>
          <div style="font-weight:500;">${escape(f.vulnClass)}</div>
          <div class="text-xs text-mute mt-1" style="margin-top:4px;">${evidencePreview(f.evidence)}</div>
        </td>
        <td class="text-dim text-xs">${(f.confidence * 100).toFixed(0)}%</td>
      </tr>
    `;
  }).join('');

  container.innerHTML = `
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Triage</th>
            <th>Agent</th>
            <th>Finding</th>
            <th>Conf.</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}
