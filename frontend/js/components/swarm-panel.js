// Red/Blue swarm panel — rendered when finding.evidence._swarm is present.
// Shows Red agent theoretical PoC and Blue agent detection rules side-by-side.
import { el, escape } from '../utils.js';
import { codeBlock } from './code-block.js';

export function renderSwarmPanel(finding) {
  const swarm = finding.evidence?._swarm;
  if (!swarm || (!swarm.red && !swarm.blue && !swarm.error)) return null;

  const panel = el('div', { class: 'finding-section swarm-section' },
    el('h4', {},
      el('span', { class: 'swarm-pill red' }, 'RED'),
      el('span', { class: 'swarm-pill blue' }, 'BLUE'),
      ' Adversarial Swarm',
      swarm.cached
        ? el('span', { class: 'text-muted', style: 'font-size:11px;margin-left:8px;' },
            '(cached)')
        : null,
    ),
  );

  if (swarm.error) {
    panel.appendChild(el('p', { class: 'text-muted' },
      `Swarm encountered an error: ${escape(swarm.error)}`));
    return panel;
  }

  const cols = el('div', { class: 'swarm-cols' });

  // Red column
  if (swarm.red) {
    const red = el('div', { class: 'swarm-col swarm-col-red' },
      el('h5', {}, '⚔️ Theoretical PoC'),
      swarm.red.poc_pseudocode
        ? codeBlock(swarm.red.poc_pseudocode, { showLineNumbers: false })
        : el('p', { class: 'text-muted' }, '—'),
      Array.isArray(swarm.red.exploitation_steps) && swarm.red.exploitation_steps.length
        ? el('ol', { class: 'swarm-steps' },
            ...swarm.red.exploitation_steps.map(s => el('li', {}, s)))
        : null,
      swarm.red.impact_narrative
        ? el('p', { class: 'text-muted', style: 'font-size:12px;margin-top:8px;' },
            swarm.red.impact_narrative)
        : null,
    );
    cols.appendChild(red);
  }

  // Blue column
  if (swarm.blue) {
    const blue = el('div', { class: 'swarm-col swarm-col-blue' },
      el('h5', {}, '🛡️ Detection'),
      swarm.blue.semgrep_rule
        ? el('div', {},
            el('div', { class: 'swarm-label' }, 'Semgrep'),
            codeBlock(swarm.blue.semgrep_rule, { showLineNumbers: false }))
        : null,
      swarm.blue.waf_rule
        ? el('div', {},
            el('div', { class: 'swarm-label' }, 'WAF'),
            codeBlock(swarm.blue.waf_rule, { showLineNumbers: false }))
        : null,
      swarm.blue.log_signature
        ? el('div', {},
            el('div', { class: 'swarm-label' }, 'Log signature'),
            codeBlock(swarm.blue.log_signature, { showLineNumbers: false }))
        : null,
    );
    cols.appendChild(blue);
  }

  panel.appendChild(cols);

  // Purple row — business narrative spans full width below the cols.
  if (swarm.purple) {
    panel.appendChild(el('div', { class: 'swarm-purple' },
      el('h5', {}, '💼 Business Impact (Purple)'),
      swarm.purple.business_narrative
        ? el('p', {}, swarm.purple.business_narrative)
        : null,
      swarm.purple.estimated_blast_radius
        ? el('p', { class: 'text-muted', style: 'font-size:12px;' },
            el('strong', {}, 'Blast radius: '),
            swarm.purple.estimated_blast_radius)
        : null,
      Array.isArray(swarm.purple.affected_stakeholders)
       && swarm.purple.affected_stakeholders.length
        ? el('div', { class: 'swarm-stakeholders' },
            el('span', { class: 'swarm-label' }, 'Affected stakeholders'),
            el('div', {},
              ...swarm.purple.affected_stakeholders.map(s =>
                el('span', { class: 'swarm-stakeholder-chip' }, s))))
        : null,
    ));
  }

  return panel;
}
