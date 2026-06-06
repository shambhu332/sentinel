// Verify engine status page
import { el, refreshIcons } from '../utils.js';
import { AGENTS } from '../data/agents.js';

// Agent IDs that have a shipped verifier (matches sentinel/verify/verifiers/).
const SUPPORTED = new Set([
  'META_002', 'P_005', 'STG_007', 'STG_009',
  'N_002', 'A_003', 'N_005',
]);

const SAMPLE_RESULTS = [
  { agent: 'META_002', vuln: 'Debuggable Release Build',     outcome: 'verified',    method: 'manifest-reread',     confidence: 0.99 },
  { agent: 'P_005',    vuln: 'Sensitive Permission: READ_SMS', outcome: 'verified',  method: 'permission-reread',   confidence: 0.85 },
  { agent: 'STG_007',  vuln: 'Insecure FileProvider Mapping', outcome: 'verified',   method: 'paths-xml-reread',    confidence: 0.85 },
  { agent: 'STG_009',  vuln: 'Insecure Auto-Backup Rules',    outcome: 'refuted',    method: 'backup-rules-reread', confidence: 0.85 },
  { agent: 'N_002',    vuln: 'Cleartext Traffic',             outcome: 'verified',   method: 'mitm-flow-match',     confidence: 0.90 },
  { agent: 'A_003',    vuln: 'Runtime Weak Cryptography',     outcome: 'verified',   method: 'frida-event-match',   confidence: 0.90 },
  { agent: 'N_005',    vuln: 'Certificate Pinning Bypass',    outcome: 'inconclusive', method: 'frida-event-match', confidence: 0.50 },
  { agent: 'C_007',    vuln: 'Weak Cryptography',             outcome: 'unsupported', method: 'no-verifier-registered', confidence: 0.0 },
];

const OUTCOME_META = {
  verified:     { color: 'verified',    icon: 'badge-check',   label: 'Verified' },
  refuted:      { color: 'refuted',     icon: 'x-circle',      label: 'Refuted' },
  inconclusive: { color: 'inconclusive', icon: 'help-circle',  label: 'Inconclusive' },
  unsupported: { color: 'unsupported',  icon: 'minus-circle',  label: 'Unsupported' },
};

export function renderVerifyPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Verify Engine'),
      el('div', { class: 'page-subtitle' },
        `${SUPPORTED.size} of ${AGENTS.length} agents have a shipped verifier — every triaged finding is routed for re-confirmation against the actual artefacts.`,
      ),
    ),
    el('div', { class: 'page-actions' },
      el('a', { class: 'btn btn-secondary', href: '#docs' },
        el('i', { 'data-lucide': 'book-open' }), 'How verifiers work',
      ),
    ),
  ));

  // Outcome legend / counts
  const counts = SAMPLE_RESULTS.reduce((acc, r) => {
    acc[r.outcome] = (acc[r.outcome] || 0) + 1;
    return acc;
  }, {});
  const legend = el('div', { class: 'verify-legend' });
  for (const [key, meta] of Object.entries(OUTCOME_META)) {
    legend.appendChild(el('div', { class: `verify-pill verify-pill-${meta.color}` },
      el('i', { 'data-lucide': meta.icon }),
      el('span', {}, `${meta.label}`),
      el('span', { class: 'verify-pill-count' }, String(counts[key] || 0)),
    ));
  }
  main.appendChild(legend);

  // Verifiers shipped
  main.appendChild(el('h2', { class: 'verify-section-title' }, 'Shipped verifiers'));
  const verifiers = el('div', { class: 'verify-grid' });
  for (const aid of SUPPORTED) {
    const agent = AGENTS.find(a => a.id === aid);
    verifiers.appendChild(el('div', { class: 'card verify-card' },
      el('div', { class: 'verify-card-head' },
        el('code', { class: 'mono' }, aid),
        el('span', { class: 'chip chip-info' }, agent ? agent.category : ''),
      ),
      el('div', { class: 'verify-card-title' }, agent ? agent.vuln_class : 'Unknown agent'),
      el('div', { class: 'verify-card-method' }, methodFor(aid)),
    ));
  }
  main.appendChild(verifiers);

  // Recent verifications table (mock)
  main.appendChild(el('h2', { class: 'verify-section-title' }, 'Recent verifications'));
  const tableCard = el('div', { class: 'card', style: 'padding: 0; overflow: hidden;' });
  const table = el('table', { class: 'data-table' });
  table.appendChild(el('thead', {},
    el('tr', {},
      el('th', {}, 'Agent'),
      el('th', {}, 'Vulnerability'),
      el('th', {}, 'Outcome'),
      el('th', {}, 'Method'),
      el('th', {}, 'Confidence'),
    ),
  ));
  const tbody = el('tbody');
  for (const r of SAMPLE_RESULTS) {
    const meta = OUTCOME_META[r.outcome];
    tbody.appendChild(el('tr', {},
      el('td', {}, el('code', { class: 'mono' }, r.agent)),
      el('td', {}, r.vuln),
      el('td', {}, el('span', { class: `verify-badge verify-badge-${meta.color}` },
        el('i', { 'data-lucide': meta.icon }),
        meta.label,
      )),
      el('td', {}, el('code', { class: 'mono small' }, r.method)),
      el('td', {}, r.confidence > 0
        ? `${(r.confidence * 100).toFixed(0)}%`
        : '—'),
    ));
  }
  table.appendChild(tbody);
  tableCard.appendChild(table);
  main.appendChild(tableCard);

  // CLI hint
  main.appendChild(el('div', { class: 'card', style: 'margin-top: 24px;' },
    el('h3', {}, 'Run it'),
    el('pre', { class: 'cli' },
      'sentinel verify scan-result.json --workspace ./workspace',
    ),
    el('p', { style: 'font-size: 13px; color: var(--text-dim);' },
      'Every finding gets ',
      el('code', { class: 'inline' }, 'evidence._verify'),
      ' populated; the VAPT report renders the outcome inline. Missing inputs (no capture / no device) collapse to ',
      el('strong', {}, 'unsupported'),
      ' rather than failing the pipeline.',
    ),
  ));

  refreshIcons();
}

function methodFor(agentId) {
  if (agentId.startsWith('META') || agentId === 'P_005') return 'Re-parse AndroidManifest.xml';
  if (agentId.startsWith('STG')) return 'Re-parse res/xml/*.xml';
  if (agentId === 'N_002') return 'Scan mitmproxy flow capture';
  if (agentId === 'A_003') return 'Match Frida cipher events';
  if (agentId === 'N_005') return 'Match Frida tls.bypass events';
  return 'See sentinel/verify/verifiers/';
}
