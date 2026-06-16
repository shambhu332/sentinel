// Compliance citations panel — rendered inside the finding detail.
// Pure function: given a finding, returns a DOM node (or null if no citations).
import { el } from '../utils.js';
import { citationsFor } from '../data/compliance.js';

const FRAMEWORK_VARS = {
  'GDPR':    'var(--framework-gdpr)',
  'HIPAA':   'var(--framework-hipaa)',
  'PCI-DSS': 'var(--framework-pci)',
  'DPDP':    'var(--framework-dpdp)',
  'CCPA':    'var(--framework-ccpa)',
};

export function renderCompliancePanel(finding) {
  const cites = citationsFor(finding.agentId);
  if (!cites.length) return null;

  const list = el('div', { class: 'compliance-list' });
  for (const c of cites) {
    const color = FRAMEWORK_VARS[c.framework] || 'var(--framework-other)';
    list.appendChild(
      el('div', { class: 'compliance-row' },
        el('span', {
          class: 'compliance-badge',
          style:
            `background:color-mix(in srgb, ${color} 13%, transparent);` +
            `color:${color};` +
            `border:1px solid color-mix(in srgb, ${color} 33%, transparent);`,
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
