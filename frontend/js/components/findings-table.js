// Findings table with expandable detail rows
import { el, refreshIcons, escape } from '../utils.js';
import { sevBadge, triageBadge } from './severity-badge.js';
import { getAgentById } from '../data/agents.js';
import { complianceInlinePill } from './compliance-panel.js';
import { impactBadge } from './impact-badge.js';
import { renderFindingDetailView } from './finding-detail-view.js';

export function renderFindingsTable(container, findings, ctx = null) {
  container.innerHTML = '';

  if (!findings || findings.length === 0) {
    container.appendChild(el('div', { class: 'empty-state' },
      el('i', { 'data-lucide': 'shield-check' }),
      el('h3', {}, 'No findings'),
      el('p', {}, 'This scan turned up no findings or is still in progress.'),
    ));
    refreshIcons();
    return;
  }

  // sort: critical first
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) =>
    (sevOrder[a.severity] - sevOrder[b.severity]) || (b.confidence - a.confidence));

  const wrap = el('div', { class: 'table-wrap' });
  const table = el('table', { class: 'table' });
  table.appendChild(el('thead', {}, el('tr', {},
    el('th', { style: 'width:40px' }),
    el('th', {}, 'Severity'),
    el('th', {}, 'Agent'),
    el('th', {}, 'Vulnerability'),
    el('th', {}, 'Triage'),
    el('th', {}, 'Confidence'),
    el('th', {}, 'Evidence'),
  )));
  const tbody = el('tbody');

  sorted.forEach((finding) => {
    const agent = getAgentById(finding.agentId);

    // Inline badges: Dynamic Testing Target + Compliance pill, when applicable.
    const inlineBadges = [];
    if (finding.evidence?.dynamic_target === true) {
      inlineBadges.push(el('span', {
        class: 'badge dynamic-target',
        title: 'Forwarded to Frida agent as a runtime bypass target',
        style:
          'background:color-mix(in srgb, var(--badge-dynamic) 13%, transparent);' +
          'color:var(--badge-dynamic-text);' +
          'border:1px solid color-mix(in srgb, var(--badge-dynamic) 33%, transparent);' +
          'font-size:10px;margin-left:6px;',
      }, '⚡ Dynamic Target'));
    }
    const cPill = complianceInlinePill(finding);
    if (cPill) inlineBadges.push(cPill);
    const iPill = impactBadge(finding);
    if (iPill) inlineBadges.push(iPill);

    // CVSS v3.1 badge — only shown when the report layer stamped a
    // score onto the finding. Coloured by GitHub's security-severity
    // bands so it reads instantly.
    const cvssScore = finding.evidence?.cvss_v3_score;
    if (typeof cvssScore === 'number') {
      const band = cvssScore >= 9 ? 'var(--cvss-critical)'
        : cvssScore >= 7 ? 'var(--cvss-high)'
        : cvssScore >= 4 ? 'var(--cvss-medium)'
        : 'var(--cvss-low)';
      inlineBadges.push(el('span', {
        class: 'badge cvss',
        title: finding.cvss_vector || `CVSS:3.1 score ${cvssScore}`,
        style:
          `background:color-mix(in srgb, ${band} 13%, transparent);` +
          `color:${band};` +
          `border:1px solid color-mix(in srgb, ${band} 33%, transparent);` +
          'font-size:10px;margin-left:6px;font-family:var(--font-mono);',
      }, `CVSS ${cvssScore.toFixed(1)}`));
    }

    // PoC download link — appears when the orchestrator's PoC Studio
    // emitted a runnable artifact for this finding. Wires to
    // /reports/{session}/poc/{finding_id}.{ext}.
    if (finding.evidence?.poc_artifact) {
      const a = el('a', {
        class: 'badge poc',
        href: finding.evidence.poc_artifact,
        target: '_blank',
        title: 'Download the runnable PoC for this finding',
        style:
          'background:color-mix(in srgb, var(--badge-poc) 13%, transparent);' +
          'color:var(--badge-poc-text);' +
          'border:1px solid color-mix(in srgb, var(--badge-poc) 33%, transparent);' +
          'font-size:10px;margin-left:6px;text-decoration:none;',
        onclick: (e) => e.stopPropagation(),
      }, '⬇ PoC');
      inlineBadges.push(a);
    }

    const vulnCell = el('td', {}, finding.vulnClass, ...inlineBadges);

    const row = el('tr', { class: 'finding-row clickable', 'data-fid': finding.id },
      el('td', {}, el('i', { 'data-lucide': 'chevron-right', class: 'chev' })),
      el('td', {}, sevBadge(finding.severity)),
      el('td', {}, el('span', { class: 'mono', style: 'color: var(--accent-primary); font-size: 12px;' }, finding.agentId)),
      vulnCell,
      el('td', {}, triageBadge(finding.triage)),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 12px;' },
        (finding.confidence * 100).toFixed(0) + '%')),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 11px;' },
        truncate(finding.evidence?.file || '', 40))),
    );

    // Expansion row
    const expansion = el('tr', { class: 'finding-expansion hidden' });
    const detailCell = el('td', { colspan: 7, style: 'padding: 0;' });
    detailCell.appendChild(renderFindingDetailView(finding, agent, ctx));
    expansion.appendChild(detailCell);

    row.addEventListener('click', () => {
      const isOpen = !expansion.classList.contains('hidden');
      // close all open
      tbody.querySelectorAll('.finding-expansion').forEach(e => e.classList.add('hidden'));
      tbody.querySelectorAll('.finding-row').forEach(r => r.classList.remove('expanded'));
      tbody.querySelectorAll('.finding-row .chev').forEach(c => c.style.transform = '');
      if (!isOpen) {
        expansion.classList.remove('hidden');
        row.classList.add('expanded');
        const chev = row.querySelector('.chev');
        if (chev) chev.style.transform = 'rotate(90deg)';
      }
    });

    tbody.appendChild(row);
    tbody.appendChild(expansion);
  });

  table.appendChild(tbody);
  wrap.appendChild(table);
  container.appendChild(wrap);

  refreshIcons();
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? '…' + s.slice(-n + 1) : s;
}
