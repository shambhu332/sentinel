// Financial-impact badge — small inline pill on findings.
// Renders only when finding.financialImpactScore (or finding.financial_impact_score)
// is a positive number set by IMPACT_001.
import { el } from '../utils.js';

export function impactBadge(finding) {
  const score = finding.financialImpactScore ?? finding.financial_impact_score;
  if (typeof score !== 'number' || score <= 0) return null;
  const label = formatUsd(score);
  // colour tier by magnitude
  let cls = 'impact-low';
  if (score >= 200_000) cls = 'impact-extreme';
  else if (score >= 50_000) cls = 'impact-high';
  else if (score >= 10_000) cls = 'impact-medium';
  return el('span', {
    class: `impact-badge ${cls}`,
    title: `IMPACT_001 estimated single-incident loss: $${score.toLocaleString()}`,
  }, '💰 ', label);
}

function formatUsd(n) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `$${Math.round(n / 1_000)}k`;
  return `$${Math.round(n)}`;
}

/** Render an extended impact card for the finding's expanded detail. */
export function renderImpactCard(finding) {
  const score = finding.financialImpactScore ?? finding.financial_impact_score;
  const ev = finding.evidence || {};
  const block = ev._impact;
  if (typeof score !== 'number' || score <= 0 || !block) return null;
  const multipliers = block.multipliers || {};
  return el('div', { class: 'finding-section impact-section' },
    el('h4', {}, '💰 Estimated Impact'),
    el('div', { class: 'impact-headline' },
      el('span', { class: 'impact-amount' }, `$${score.toLocaleString()}`),
      el('span', { class: 'impact-context text-muted' },
        ` per incident · ${block.asset_category || 'general'} surface`),
    ),
    el('div', { class: 'impact-multipliers text-muted', style: 'font-size:11px;' },
      `severity ×${multipliers.severity ?? 1} · asset ×${multipliers.asset ?? 1} · tenant ×${multipliers.tenant ?? 1}`),
    block.rationale
      ? el('p', { class: 'text-muted', style: 'font-size:12px;margin-top:6px;' },
          block.rationale)
      : null,
  );
}
