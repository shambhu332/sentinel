/**
 * severity-chip.js — render a severity badge.
 *
 * Usage:
 *   import { severityChip, severityDot, severityChipsRow } from '…';
 *   container.innerHTML = severityChip('High');
 */

const NORMALIZE = {
  critical: 'critical', crit: 'critical',
  high: 'high',
  medium: 'medium', med: 'medium',
  low: 'low',
  info: 'info',
};

function key(sev) {
  return NORMALIZE[String(sev || '').toLowerCase()] || 'info';
}

/** Return HTML for a single severity chip. */
export function severityChip(sev) {
  const k = key(sev);
  const label = k.charAt(0).toUpperCase() + k.slice(1);
  return `<span class="chip chip-sev-${k}">${label}</span>`;
}

/** Smaller dot variant. */
export function severityDot(sev) {
  return `<span class="sev-dot sev-dot-${key(sev)}" aria-label="${sev}"></span>`;
}

/** Render the count chips row used on dashboard / history. */
export function severityChipsRow(counts) {
  const c = counts || {};
  const cells = [
    ['critical', c.critical || 0],
    ['high',     c.high     || 0],
    ['medium',   c.medium   || 0],
    ['low',      c.low      || 0],
  ];
  return `<span class="finding-chips">${cells
    .map(([k, n]) => `<span class="chip chip-sev-${k}" title="${k}: ${n}">${n}</span>`)
    .join('')}</span>`;
}

/** Render a list of severity dots from a range array (used on agent cards). */
export function severityDotsRange(range) {
  const list = Array.isArray(range) ? range : [range];
  return `<span class="agent-sev-dots">${list.map((s) => severityDot(s)).join('')}</span>`;
}
