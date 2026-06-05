// Severity badge + breakdown row
import { el } from '../utils.js';

export function sevBadge(severity, label) {
  return el('span', { class: `badge sev-${severity}` }, label || severity);
}

export function statusBadge(status, label) {
  const cls = `status-${(status || '').replace('_', '-')}`;
  return el('span', { class: `badge ${cls}` }, label || status.replace('_', ' '));
}

export function triageBadge(triage) {
  return el('span', { class: `badge triage-${triage}` }, triage);
}

// Severity breakdown row (4 mini chips)
export function sevRow(sev) {
  const cells = [
    { key: 'critical', short: 'C', n: sev?.critical || 0, cls: 'crit' },
    { key: 'high',     short: 'H', n: sev?.high     || 0, cls: 'high' },
    { key: 'medium',   short: 'M', n: sev?.medium   || 0, cls: 'med' },
    { key: 'low',      short: 'L', n: sev?.low      || 0, cls: 'low' },
  ];
  return el('span', { class: 'sev-row' },
    ...cells.map(c =>
      el('span', { class: `sev-cell ${c.cls}${c.n === 0 ? ' zero' : ''}` }, c.short, ':', String(c.n)),
    ),
  );
}
