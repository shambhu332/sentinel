/**
 * triage-chip.js — render triage outcome chips with the
 * symbol shorthand spec'd in BUILD.md (verified ✓ / filtered ✗ /
 * uncertain ? / skipped —).
 */

const SYMBOLS = { verified: '✓', filtered: '✗', uncertain: '?', skipped: '—' };

export function triageChip(outcome) {
  const k = String(outcome || 'skipped').toLowerCase();
  const sym = SYMBOLS[k] ?? '—';
  const label = k.charAt(0).toUpperCase() + k.slice(1);
  return `<span class="chip chip-triage-${k}" title="${label}"><span class="mono">${sym}</span> ${label}</span>`;
}

/** Compact icon-only variant for dense tables. */
export function triageBadge(outcome) {
  const k = String(outcome || 'skipped').toLowerCase();
  const sym = SYMBOLS[k] ?? '—';
  return `<span class="chip chip-triage-${k} chip-sm mono" title="${k}">${sym}</span>`;
}
