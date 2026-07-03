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

// Verify pill for a finding — reads finding.evidence._verify (runtime
// verifier outcome) and falls back to finding.verification_status when
// no runtime verifier ran (typical for pure-SAST agents).
export function verifyBadge(finding) {
  const v = (finding.evidence && finding.evidence._verify) || null;
  if (!v) {
    if (finding.verification_status === 'Code-level only') {
      return el('span', { class: 'badge badge-static', style: 'font-size: 11px;', title: 'static analysis only — no runtime verification' },
        'static');
    }
    if (finding.verification_status) {
      const s = finding.verification_status;
      return el('span', { class: 'badge badge-warning', style: 'font-size: 11px;', title: s },
        s.length > 14 ? s.slice(0, 14) + '…' : s);
    }
    return el('span', { class: 'badge badge-muted', style: 'font-size: 11px;', title: 'no verifier ran' }, '—');
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
  return el('span', { class: `badge ${c.cls}`, style: 'font-size: 11px;', title: tooltip }, c.label);
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
