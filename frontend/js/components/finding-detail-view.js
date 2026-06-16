// FindingDetailView — Djini-style multi-section finding panel.
// Renders, in order:
//   1. Header banner       (app, package, version, severity, CVSS)
//   2. Description         (LLM rationale + summary)
//   3. Steps to reproduce  (numbered, with screenshots + commands)
//   4. Affected code       (file path + snippet + line/col highlight)
//   5. Context factors     (exposure, controls, impact, likelihood)
//   6. Remediation         (developer-focused fix)
//   7. References          (CWE / MASVS / OWASP)
import { el, refreshIcons } from '../utils.js';
import { sevBadge } from './severity-badge.js';
import { codeBlock } from './code-block.js';
import { screenshotCarousel } from './screenshot-carousel.js';
import { renderCompliancePanel } from './compliance-panel.js';
import { renderImpactCard } from './impact-badge.js';
import { renderSwarmPanel } from './swarm-panel.js';

// Render a finding detail panel. `ctx` is the scan summary
// (session_id, appName, package, version) needed for image URLs and
// the header banner. `agent` is the catalog entry for this finding's
// agent_id (description, category) — may be null.
export function renderFindingDetailView(finding, agent, ctx) {
  const root = el('div', { class: 'finding-detail-v2' });
  root.appendChild(headerBanner(finding, ctx));
  root.appendChild(descriptionSection(finding, agent));

  const repro = stepsToReproduceSection(finding, ctx);
  if (repro) root.appendChild(repro);

  const code = affectedCodeSection(finding);
  if (code) root.appendChild(code);

  const ctxFactors = contextFactorsSection(finding);
  if (ctxFactors) root.appendChild(ctxFactors);

  root.appendChild(remediationSection(finding));

  const refs = referencesSection(finding);
  if (refs) root.appendChild(refs);

  // Existing supplementary panels (compliance / impact / swarm) keep
  // working — pinned under the references section so the primary
  // narrative reads top-down without distraction.
  const supp = el('div', { class: 'finding-supplementary' });
  const compliance = renderCompliancePanel(finding);
  if (compliance) supp.appendChild(compliance);
  const impactCard = renderImpactCard(finding);
  if (impactCard) supp.appendChild(impactCard);
  const swarm = renderSwarmPanel(finding);
  if (swarm) supp.appendChild(swarm);
  if (supp.childNodes.length) root.appendChild(supp);

  refreshIcons();
  return root;
}

// ---------- 1. Header banner ----------
function headerBanner(finding, ctx) {
  const cvss = finding.evidence?.cvss_v3_score;
  const sev = finding.severity || 'Info';
  return el('div', { class: 'fd-banner', 'data-sev': sev },
    el('div', { class: 'fd-banner-left' },
      el('div', { class: 'fd-banner-title' }, finding.vulnClass || finding.vuln_class || 'Finding'),
      el('div', { class: 'fd-banner-meta' },
        ctx?.appName ? el('span', {}, ctx.appName) : null,
        ctx?.package ? el('span', { class: 'mono' }, ctx.package) : null,
        ctx?.version ? el('span', { class: 'mono text-muted' }, `v${ctx.version}`) : null,
      ),
    ),
    el('div', { class: 'fd-banner-right' },
      sevBadge(sev.toLowerCase(), sev),
      typeof cvss === 'number'
        ? el('div', { class: 'fd-cvss-chip', title: finding.cvss_vector || `CVSS:3.1 ${cvss}` },
            el('span', { class: 'fd-cvss-label' }, 'CVSS'),
            el('span', { class: 'fd-cvss-score' }, cvss.toFixed(1)),
          )
        : null,
    ),
  );
}

// ---------- 2. Description ----------
function descriptionSection(finding, agent) {
  const rationale = finding.llmRationale || finding.llm_rationale
    || finding.evidence?.llm_rationale || '';
  const summary = finding.evidence?.summary || finding.evidence?.description || '';
  return el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'file-text', 'aria-hidden': 'true' }), 'Description'),
    summary ? el('p', { class: 'fd-prose' }, summary) : null,
    rationale ? el('div', { class: 'fd-rationale' },
      el('div', { class: 'fd-rationale-label' }, 'Why it matters'),
      el('p', { class: 'fd-prose' }, rationale),
    ) : null,
    agent ? el('div', { class: 'fd-agent-attribution text-muted' },
      `Detected by ${agent.id}${agent.name ? ' — ' + agent.name : ''}`,
    ) : null,
  );
}

// ---------- 3. Steps to reproduce ----------
function stepsToReproduceSection(finding, ctx) {
  const steps = collectSteps(finding);
  const shots = Array.isArray(finding.screenshots) ? finding.screenshots
    : (finding.evidence?.screenshots || []);
  if (!steps.length && !shots.length) return null;

  const section = el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'list-checks', 'aria-hidden': 'true' }), 'Steps to reproduce'),
  );

  if (steps.length) {
    const ol = el('ol', { class: 'fd-steps' });
    steps.forEach((step, i) => {
      const li = el('li', {});
      li.appendChild(el('div', { class: 'fd-step-text' }, step.text));
      if (step.command) {
        li.appendChild(el('pre', { class: 'fd-step-cmd' },
          el('code', {}, step.command),
        ));
      }
      // Inline screenshot for this step if the path includes a matching label.
      const stepShot = matchScreenshot(shots, step.label, i);
      if (stepShot && ctx?.session_id) {
        const carousel = screenshotCarousel([stepShot], ctx.session_id);
        if (carousel) li.appendChild(carousel);
      }
      ol.appendChild(li);
    });
    section.appendChild(ol);
  }

  // Any screenshots not matched to a numbered step → standalone carousel.
  if (shots.length && ctx?.session_id) {
    const matchedSet = new Set();
    steps.forEach((s, i) => {
      const m = matchScreenshot(shots, s.label, i);
      if (m) matchedSet.add(m);
    });
    const leftover = shots.filter((p) => !matchedSet.has(p));
    if (leftover.length) {
      const car = screenshotCarousel(leftover, ctx.session_id, {
        caption: steps.length ? 'Additional captures' : 'Captured during exploit run',
      });
      if (car) section.appendChild(car);
    }
  }

  return section;
}

function collectSteps(finding) {
  // Preferred shape: evidence.repro_steps = [{text, command?, label?}, ...]
  const raw = finding.evidence?.repro_steps;
  if (Array.isArray(raw) && raw.length) {
    return raw
      .filter((s) => s && (s.text || s.command))
      .map((s) => ({
        text: s.text || '',
        command: s.command || '',
        label: s.label || '',
      }));
  }
  // Fallback: synthesise from adb / frida command hints in evidence.
  const synth = [];
  const ev = finding.evidence || {};
  if (ev.adb_command) synth.push({ text: 'Trigger via ADB', command: ev.adb_command, label: 'adb' });
  if (ev.frida_payload) synth.push({ text: 'Attach Frida hook', command: typeof ev.frida_payload === 'string' ? ev.frida_payload : JSON.stringify(ev.frida_payload, null, 2), label: 'frida' });
  if (ev.curl) synth.push({ text: 'Replay request', command: ev.curl, label: 'curl' });
  return synth;
}

function matchScreenshot(paths, label, idx) {
  if (!paths.length) return null;
  if (label) {
    const m = paths.find((p) => p.toLowerCase().includes(label.toLowerCase()));
    if (m) return m;
  }
  return paths[idx] || null;
}

// ---------- 4. Affected code ----------
function affectedCodeSection(finding) {
  const cs = finding.code_snippet || finding.evidence?.code_snippet;
  if (!cs && !finding.evidence?.snippet) return null;

  const file = cs?.file || finding.evidence?.file || '';
  const line = cs?.line || finding.evidence?.line || 0;
  const content = cs?.content || finding.evidence?.snippet || '';
  const startCol = cs?.start_col;
  const endCol = cs?.end_col;

  const section = el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'code-2', 'aria-hidden': 'true' }), 'Affected code'),
    el('div', { class: 'fd-code-path mono text-muted' },
      file || '(no file)',
      line ? el('span', { class: 'fd-code-line-tag' }, `line ${line}`) : null,
    ),
    codeBlock(content || '// (no snippet)', {
      showLineNumbers: true,
      startLine: line || 1,
      highlightLines: line ? [line] : [],
      columnHighlight: (Number.isInteger(startCol) && Number.isInteger(endCol))
        ? { start: startCol, end: endCol }
        : null,
    }),
  );
  return section;
}

// ---------- 5. Context factors ----------
function contextFactorsSection(finding) {
  const cf = finding.context_factors || finding.evidence?.context_factors;
  if (!cf || typeof cf !== 'object') return null;

  const factors = [
    { key: 'exposure',    label: 'Exposure',    icon: 'radar' },
    { key: 'controls',    label: 'Controls',    icon: 'shield' },
    { key: 'impact',      label: 'Impact',      icon: 'zap' },
    { key: 'likelihood',  label: 'Likelihood',  icon: 'percent' },
  ].filter((f) => cf[f.key]);
  if (!factors.length) return null;

  return el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'sliders-horizontal', 'aria-hidden': 'true' }), 'Context'),
    el('div', { class: 'fd-context-grid' },
      ...factors.map((f) => el('div', { class: 'fd-context-card' },
        el('div', { class: 'fd-context-label' },
          el('i', { 'data-lucide': f.icon, 'aria-hidden': 'true' }),
          el('span', {}, f.label),
        ),
        el('div', { class: 'fd-context-value' }, String(cf[f.key])),
      )),
    ),
  );
}

// ---------- 6. Remediation ----------
function remediationSection(finding) {
  return el('section', { class: 'fd-section fd-section-remediation' },
    el('h3', {}, el('i', { 'data-lucide': 'wrench', 'aria-hidden': 'true' }), 'Remediation'),
    el('p', { class: 'fd-prose' }, finding.recommendation || '—'),
  );
}

// ---------- 7. References ----------
function referencesSection(finding) {
  const refs = [];
  const ev = finding.evidence || {};

  // CWE
  const cwe = ev.cwe || finding.cwe;
  if (cwe) {
    const id = String(cwe).replace(/^CWE-?/i, '');
    refs.push({ label: `CWE-${id}`, href: `https://cwe.mitre.org/data/definitions/${id}.html` });
  }
  // OWASP Mobile Top 10
  if (finding.owasp) {
    refs.push({
      label: `OWASP ${finding.owasp}`,
      href: 'https://owasp.org/www-project-mobile-top-10/',
    });
  }
  // MASVS
  if (finding.masvs) {
    refs.push({
      label: `MASVS ${finding.masvs}`,
      href: 'https://mas.owasp.org/MASVS/',
    });
  }
  // Free-form additional refs from evidence.references = [{label,href},...]
  if (Array.isArray(ev.references)) {
    ev.references.forEach((r) => {
      if (r && r.href) refs.push({ label: r.label || r.href, href: r.href });
    });
  }

  if (!refs.length) return null;
  return el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'book-open', 'aria-hidden': 'true' }), 'References'),
    el('ul', { class: 'fd-refs' },
      ...refs.map((r) => el('li', {},
        el('a', { href: r.href, target: '_blank', rel: 'noopener noreferrer' }, r.label),
      )),
    ),
  );
}
