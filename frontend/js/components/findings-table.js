// Findings table with expandable detail rows
import { el, refreshIcons, escape } from '../utils.js';
import { sevBadge, triageBadge } from './severity-badge.js';
import { codeBlock } from './code-block.js';
import { getAgentById } from '../data/agents.js';

export function renderFindingsTable(container, findings) {
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

    const row = el('tr', { class: 'finding-row clickable', 'data-fid': finding.id },
      el('td', {}, el('i', { 'data-lucide': 'chevron-right', class: 'chev' })),
      el('td', {}, sevBadge(finding.severity)),
      el('td', {}, el('span', { class: 'mono', style: 'color: var(--accent-primary); font-size: 12px;' }, finding.agentId)),
      el('td', {}, finding.vulnClass),
      el('td', {}, triageBadge(finding.triage)),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 12px;' },
        (finding.confidence * 100).toFixed(0) + '%')),
      el('td', {}, el('span', { class: 'mono text-muted', style: 'font-size: 11px;' },
        truncate(finding.evidence?.file || '', 40))),
    );

    // Expansion row
    const expansion = el('tr', { class: 'finding-expansion hidden' });
    const detailCell = el('td', { colspan: 7, style: 'padding: 0;' });
    detailCell.appendChild(buildFindingDetail(finding, agent));
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

function buildFindingDetail(finding, agent) {
  const detail = el('div', { class: 'finding-detail' });

  // Left column — code evidence
  const left = el('div', { class: 'finding-section' },
    el('h4', {}, 'Evidence'),
    el('p', { class: 'mono text-muted', style: 'font-size: 12px; margin-bottom: 8px;' },
      `${finding.evidence?.file || '—'}:${finding.evidence?.line || '?'}`),
    codeBlock(finding.evidence?.snippet || '// (no snippet)', { showLineNumbers: false }),
  );

  // Right column — context
  const right = el('div', { style: 'display: flex; flex-direction: column; gap: 16px;' });

  if (agent) {
    right.appendChild(el('div', { class: 'finding-section' },
      el('h4', {}, 'Agent'),
      el('p', {}, `${agent.id} — ${agent.name}`),
      el('p', { class: 'text-muted', style: 'font-size: 12px;' }, agent.description),
    ));
  }

  right.appendChild(el('div', { class: 'finding-section rationale' },
    el('h4', {}, 'LLM Triage Rationale'),
    el('p', {}, finding.llmRationale || '—'),
  ));

  right.appendChild(el('div', { class: 'finding-section recommendation' },
    el('h4', {}, 'Recommendation'),
    el('p', {}, finding.recommendation || '—'),
  ));

  detail.append(left, right);
  return detail;
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? '…' + s.slice(-n + 1) : s;
}
