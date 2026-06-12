// Compliance citations panel — rendered inside the finding detail.
// Pure function: given a finding, returns a DOM node (or null if no citations).
import { el } from '../utils.js';
import { citationsFor } from '../data/compliance.js';

const FRAMEWORK_COLORS = {
  'GDPR':    '#5b8def',
  'HIPAA':   '#f97316',
  'PCI-DSS': '#10b981',
  'DPDP':    '#a855f7',
  'CCPA':    '#eab308',
};

export function renderCompliancePanel(finding) {
  const cites = citationsFor(finding.agentId);
  if (!cites.length) return null;

  const list = el('div', { class: 'compliance-list' });
  for (const c of cites) {
    const color = FRAMEWORK_COLORS[c.framework] || '#888';
    list.appendChild(
      el('div', { class: 'compliance-row' },
        el('span', {
          class: 'compliance-badge',
          style: `background:${color}22;color:${color};border:1px solid ${color}55`,
        }, c.framework),
        el('span', { class: 'compliance-ref mono' }, c.reference || ''),
        c.note
          ? el('span', { class: 'compliance-note text-muted' }, c.note)
          : null,
      ),
    );
  }
  return el('div', { class: 'finding-section compliance-section' },
    el('h4', {}, 'Compliance'),
    list,
  );
}

/** Small inline pill listing distinct frameworks affected — for the finding row. */
export function complianceInlinePill(finding) {
  const cites = citationsFor(finding.agentId);
  if (!cites.length) return null;
  const frameworks = Array.from(new Set(cites.map(c => c.framework)));
  return el('span', { class: 'compliance-inline', title: frameworks.join(' · ') },
    el('i', { 'data-lucide': 'scale', style: 'width: 10px; height: 10px; vertical-align: middle;' }),
    ' ',
    frameworks.length === 1 ? frameworks[0] : `${frameworks.length} regs`,
  );
}
