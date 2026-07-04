// FindingDetailView — vertically stacked finding panel.
// Section order (matches the structure the report layer ships):
//   1. Header banner       (severity + title + CVSS chip)
//   2. Description         (summary + LLM rationale + severity rationale)
//   3. Context factors     (exposure / controls / impact / likelihood)
//   4. Metadata tags       (Source tags / CWE / MASVS / OWASP / references)
//   5. Affected code       (one or more numbered snippets w/ file path)
//   6. Steps to reproduce  (steps + reproduction_commands + observed_result
//                           + screenshots; verification-failure callout)
//   7. Remediation         (developer-focused fix)
import { el, refreshIcons } from '../utils.js';
import { sevBadge } from './severity-badge.js';
import { codeBlock } from './code-block.js';
import { screenshotCarousel } from './screenshot-carousel.js';
import { renderCompliancePanel } from './compliance-panel.js';
import { renderImpactCard } from './impact-badge.js';
import { renderSwarmPanel } from './swarm-panel.js';
import { getReproRecipe } from './repro-recipes.js';

export function renderFindingDetailView(finding, agent, ctx) {
  // Djini-parity split: Static Tool findings render in a concise variant
  // (title, description, metadata, code, remediation only) so pure SAST
  // hits don't bury the AI-Powered narrative under empty sections.
  if (isStaticToolFinding(finding)) {
    return renderStaticToolDetailView(finding, agent, ctx);
  }

  const root = el('div', { class: 'finding-detail-v2' });
  root.appendChild(headerBanner(finding, ctx));
  root.appendChild(descriptionSection(finding, agent));

  const ctxFactors = contextFactorsSection(finding);
  if (ctxFactors) root.appendChild(ctxFactors);

  const meta = metadataTagsSection(finding);
  if (meta) root.appendChild(meta);

  const code = affectedCodeSection(finding);
  if (code) root.appendChild(code);

  const repro = stepsToReproduceSection(finding, ctx);
  if (repro) root.appendChild(repro);

  // Djini-style exploitation proof: renders exploit_proof, PoC download
  // buttons, and the API replay evidence table when the Phase 7.5 driver
  // populated them. Silent when the finding has no exploitation data.
  const exploit = exploitationProofSection(finding, ctx);
  if (exploit) root.appendChild(exploit);

  root.appendChild(remediationSection(finding));

  // Supplementary panels (compliance / impact / swarm) hang at the
  // bottom so the canonical 7-section narrative reads top-down without
  // distraction.
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
  const vector = finding.cvss_vector || finding.evidence?.cvss_vector;
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
        ? el('div', { class: 'fd-cvss-chip', title: vector || `CVSS:3.1 ${cvss}` },
            el('span', { class: 'fd-cvss-label' }, 'CVSS'),
            el('span', { class: 'fd-cvss-score' }, cvss.toFixed(1)),
          )
        : null,
      vector ? el('div', { class: 'fd-cvss-vector mono', title: 'CVSS v3.1 vector' }, vector) : null,
    ),
  );
}

// ---------- 2. Description ----------
function descriptionSection(finding, agent) {
  const rationale = finding.llmRationale || finding.llm_rationale
    || finding.evidence?.llm_rationale || '';
  const summary = finding.evidence?.summary || finding.evidence?.description || '';
  const sevRationale = finding.severity_rationale
    || finding.evidence?.severity_rationale || '';
  return el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'file-text', 'aria-hidden': 'true' }), 'Description'),
    summary ? el('p', { class: 'fd-prose' }, summary) : null,
    rationale ? el('div', { class: 'fd-rationale' },
      el('div', { class: 'fd-rationale-label' }, 'Why it matters'),
      el('p', { class: 'fd-prose' }, rationale),
    ) : null,
    sevRationale ? el('div', { class: 'fd-rationale fd-rationale-severity' },
      el('div', { class: 'fd-rationale-label' }, `Severity rationale (${finding.severity})`),
      el('p', { class: 'fd-prose' }, sevRationale),
    ) : null,
    agent ? el('div', { class: 'fd-agent-attribution text-muted' },
      `Detected by ${agent.id}${agent.name ? ' — ' + agent.name : ''}`,
    ) : null,
  );
}

// ---------- 3. Context factors ----------
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
    el('div', { class: 'fd-context-grid fd-context-grid-flat' },
      ...factors.map((f) => el('div', { class: 'fd-context-card fd-context-card-flat' },
        el('div', { class: 'fd-context-label' },
          el('i', { 'data-lucide': f.icon, 'aria-hidden': 'true' }),
          el('span', {}, f.label),
        ),
        el('div', { class: 'fd-context-value' }, String(cf[f.key])),
      )),
    ),
  );
}

// ---------- 4. Metadata tags ----------
function metadataTagsSection(finding) {
  const ev = finding.evidence || {};
  const tags = [];

  // Source tags — agent-supplied taxonomy badges.
  const sources = Array.isArray(finding.source_tags) ? finding.source_tags
    : (Array.isArray(ev.source_tags) ? ev.source_tags : []);
  sources.forEach((s) => {
    if (s) tags.push({ kind: 'source', label: String(s) });
  });

  // CWE
  const cwe = ev.cwe || finding.cwe;
  if (cwe) {
    const id = String(cwe).replace(/^CWE-?/i, '');
    tags.push({ kind: 'cwe', label: `CWE-${id}`,
      href: `https://cwe.mitre.org/data/definitions/${id}.html` });
  }
  // MASVS
  if (finding.masvs) {
    tags.push({ kind: 'masvs', label: `MASVS ${finding.masvs}`,
      href: 'https://mas.owasp.org/MASVS/',
      title: 'Mobile Application Security Verification Standard' });
  }
  // OWASP Mobile Top 10
  if (finding.owasp) {
    tags.push({ kind: 'owasp', label: `OWASP ${finding.owasp}`,
      href: 'https://owasp.org/www-project-mobile-top-10/' });
  }
  // Free-form references
  if (Array.isArray(ev.references)) {
    ev.references.forEach((r) => {
      if (r && r.href) tags.push({ kind: 'ref', label: r.label || r.href, href: r.href });
    });
  }

  if (!tags.length) return null;
  return el('section', { class: 'fd-section fd-section-tags' },
    el('h3', {}, el('i', { 'data-lucide': 'tags', 'aria-hidden': 'true' }), 'Metadata'),
    el('div', { class: 'fd-tag-row' },
      ...tags.map((t) => {
        const attrs = { class: `fd-tag fd-tag-${t.kind}` };
        if (t.title) attrs.title = t.title;
        return t.href
          ? el('a', { ...attrs, href: t.href, target: '_blank', rel: 'noopener noreferrer' }, t.label)
          : el('span', attrs, t.label);
      }),
    ),
  );
}

// ---------- 5. Affected code ----------
function affectedCodeSection(finding) {
  // Prefer the multi-snippet field; fall back to the legacy singular one.
  let snippets = Array.isArray(finding.code_snippets) ? finding.code_snippets.slice()
    : (Array.isArray(finding.evidence?.code_snippets) ? finding.evidence.code_snippets.slice() : []);
  const single = finding.code_snippet || finding.evidence?.code_snippet;
  if (!snippets.length && single) snippets = [single];
  if (!snippets.length && finding.evidence?.snippet) {
    snippets = [{
      file: finding.evidence.file,
      line: finding.evidence.line,
      content: finding.evidence.snippet,
    }];
  }
  if (!snippets.length) return null;

  const section = el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'code-2', 'aria-hidden': 'true' }),
      `Affected code${snippets.length > 1 ? ` (${snippets.length})` : ''}`),
  );

  snippets.forEach((cs, idx) => {
    const file = cs?.file || '';
    const line = cs?.line || 0;
    const content = cs?.content || '// (no snippet)';
    const startCol = cs?.start_col;
    const endCol = cs?.end_col;

    const wrap = el('div', { class: 'fd-snippet' });
    wrap.appendChild(el('div', { class: 'fd-code-path mono' },
      snippets.length > 1
        ? el('span', { class: 'fd-snippet-index' }, `${idx + 1}.`)
        : null,
      cs?.label ? el('span', { class: 'fd-snippet-label' }, cs.label) : null,
      el('span', { class: 'fd-snippet-file' }, file || '(no file)'),
      line ? el('span', { class: 'fd-code-line-tag' }, `line ${line}`) : null,
    ));
    wrap.appendChild(codeBlock(content, {
      showLineNumbers: true,
      startLine: line || 1,
      highlightLines: line ? [line] : [],
      columnHighlight: (Number.isInteger(startCol) && Number.isInteger(endCol))
        ? { start: startCol, end: endCol }
        : null,
    }));
    section.appendChild(wrap);
  });

  return section;
}

// ---------- 6. Steps to reproduce ----------
function stepsToReproduceSection(finding, ctx) {
  let steps = collectSteps(finding);
  let isSynthesised = false;
  if (steps.length < 2) {
    // Agent didn't ship a full playbook — fall back to the canonical
    // per-vuln-class recipe so a junior researcher always has a
    // concrete, copy-pasteable walkthrough.
    steps = getReproRecipe(finding, ctx);
    isSynthesised = true;
  }
  const shots = normaliseScreenshots(finding);
  const reproCmds = Array.isArray(finding.reproduction_commands)
    ? finding.reproduction_commands.filter(Boolean) : [];
  const observed = finding.observed_result || finding.evidence?.observed_result || '';
  const verStatus = finding.verification_status
    || finding.evidence?.verification_status || '';

  if (!steps.length && !shots.length && !reproCmds.length && !observed && !verStatus) {
    return null;
  }

  const section = el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'list-checks', 'aria-hidden': 'true' }), 'Steps to reproduce'),
  );

  // Prerequisites — listed once at the top so juniors don't get stuck
  // hunting for tooling on step 3.
  section.appendChild(el('div', { class: 'fd-prereqs', role: 'note' },
    el('div', { class: 'fd-prereqs-label' }, 'Prerequisites'),
    el('ul', { class: 'fd-prereqs-list' },
      el('li', {}, 'Android test device or emulator (Android 8+ recommended)'),
      el('li', {}, 'USB debugging enabled — ', el('code', {}, 'adb devices'), ' must list it'),
      el('li', {}, 'Toolchain: ', el('code', {}, 'adb'), ', ', el('code', {}, 'apktool'), ', ',
        el('code', {}, 'jadx'), ', ', el('code', {}, 'frida'), ' (only when noted in a step)'),
      el('li', {}, 'A local copy of the target APK saved as ', el('code', {}, './target.apk')),
    ),
  ));

  if (isSynthesised) {
    section.appendChild(el('div', { class: 'fd-synth-note text-muted', style: 'font-size:12px; margin-bottom: 8px;' },
      el('i', { 'data-lucide': 'sparkles', 'aria-hidden': 'true' }),
      ' Steps below are a canonical reproduction recipe for this vulnerability class. Substitute concrete component / file names from the Affected Code section.',
    ));
  }

  // Verification-failure callout (e.g. "Unverified due to auth gating").
  if (verStatus && /unverified|fail|block|auth/i.test(verStatus)) {
    section.appendChild(el('div', { class: 'fd-verify-callout', role: 'note' },
      el('i', { 'data-lucide': 'alert-triangle', 'aria-hidden': 'true' }),
      el('div', {},
        el('div', { class: 'fd-verify-title' }, verStatus),
        el('div', { class: 'fd-verify-body text-muted' },
          'A blocking state prevented full runtime verification. Screenshots below show the observed state at the point the verifier halted.'),
      ),
    ));
  } else if (verStatus) {
    section.appendChild(el('div', { class: 'fd-verify-badge' },
      el('i', { 'data-lucide': 'badge-check', 'aria-hidden': 'true' }),
      el('span', {}, verStatus),
    ));
  }

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
      // Match screenshot — by explicit step_index, then label, then position.
      const stepShot = pickShot(shots, i, step.label);
      if (stepShot && ctx?.session_id) {
        const car = screenshotCarousel(
          [stepShot.path],
          ctx.session_id,
          { caption: stepShot.caption || step.label || '' },
        );
        if (car) li.appendChild(car);
      }
      ol.appendChild(li);
    });
    section.appendChild(ol);
  }

  // Verifier-supplied raw commands. Renders as a single fenced block so
  // a developer can copy-paste the whole exploit reproduction.
  if (reproCmds.length) {
    section.appendChild(el('div', { class: 'fd-repro-cmds' },
      el('div', { class: 'fd-repro-cmds-label' }, 'Commands used by the verifier'),
      el('pre', { class: 'fd-step-cmd' },
        el('code', {}, reproCmds.join('\n')),
      ),
    ));
  }

  if (observed) {
    section.appendChild(el('div', { class: 'fd-observed' },
      el('div', { class: 'fd-observed-label' }, 'Observed result'),
      el('p', { class: 'fd-observed-text' }, observed),
    ));
  }

  // Any screenshots not matched to a numbered step → standalone carousel.
  if (shots.length && ctx?.session_id) {
    const used = new Set();
    steps.forEach((s, i) => {
      const m = pickShot(shots, i, s.label);
      if (m) used.add(m);
    });
    const leftover = shots.filter((s) => !used.has(s));
    if (leftover.length) {
      const paths = leftover.map((s) => s.path);
      const captionByPath = new Map(leftover.map((s) => [s.path, s.caption || '']));
      const car = screenshotCarousel(paths, ctx.session_id, {
        caption: steps.length ? 'Additional captures' : 'Captured during exploit run',
      });
      if (car) {
        // Per-image caption hints (rendered via figcaption on the carousel itself).
        car.querySelectorAll('figure.screenshot-item').forEach((fig, i) => {
          const c = captionByPath.get(paths[i]);
          if (c) {
            const cap = fig.querySelector('.screenshot-label');
            if (cap) cap.textContent = c;
          }
        });
        section.appendChild(car);
      }
    }
  }

  return section;
}

function collectSteps(finding) {
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
  const synth = [];
  const ev = finding.evidence || {};
  if (ev.adb_command) synth.push({ text: 'Trigger via ADB', command: ev.adb_command, label: 'adb' });
  if (ev.frida_payload) synth.push({ text: 'Attach Frida hook', command: typeof ev.frida_payload === 'string' ? ev.frida_payload : JSON.stringify(ev.frida_payload, null, 2), label: 'frida' });
  if (ev.curl) synth.push({ text: 'Replay request', command: ev.curl, label: 'curl' });
  return synth;
}

// Normalise screenshots into [{path, caption, step_index, label}] form.
// Failed-capture entries (path === null) are filtered out so the
// carousel never renders a broken image; the warning callout already
// surfaces the verification failure.
function normaliseScreenshots(finding) {
  const raw = Array.isArray(finding.screenshots) ? finding.screenshots
    : (Array.isArray(finding.evidence?.screenshots) ? finding.evidence.screenshots : []);
  const out = [];
  raw.forEach((entry, i) => {
    if (typeof entry === 'string') {
      out.push({ path: entry, caption: '', step_index: null, label: '' });
    } else if (entry && typeof entry === 'object' && entry.path) {
      out.push({
        path: entry.path,
        caption: entry.caption || '',
        step_index: Number.isInteger(entry.step_index) ? entry.step_index : null,
        label: entry.label || '',
      });
    }
  });
  return out;
}

function pickShot(shots, idx, label) {
  if (!shots.length) return null;
  // 1. explicit step_index wins
  const byIdx = shots.find((s) => s.step_index === idx);
  if (byIdx) return byIdx;
  // 2. label substring match
  if (label) {
    const byLabel = shots.find((s) =>
      (s.label && s.label.toLowerCase().includes(label.toLowerCase())) ||
      (s.path && s.path.toLowerCase().includes(label.toLowerCase())));
    if (byLabel) return byLabel;
  }
  // 3. positional fallback only when no step_indices are present anywhere
  const anyIndexed = shots.some((s) => s.step_index != null);
  if (!anyIndexed) return shots[idx] || null;
  return null;
}

// ---------- 7. Remediation ----------
function remediationSection(finding) {
  return el('section', { class: 'fd-section fd-section-remediation' },
    el('h3', {}, el('i', { 'data-lucide': 'wrench', 'aria-hidden': 'true' }), 'Remediation'),
    el('div', { class: 'fd-remediation-box' },
      el('p', { class: 'fd-prose' }, finding.recommendation || '—'),
    ),
  );
}

// ---------- 6.5 Exploitation proof (Djini-style) ----------
// Renders four data planes when the Phase 7.5 driver populated them:
//   - Exploitation status badge (Verified_Exploited / Auth_Gated / etc.)
//   - Exfiltrated data block (finding.exploit_proof)
//   - PoC artifact download buttons (finding.poc_artifacts)
//   - API replay evidence table (finding.api_replay_logs)
// Returns null if none of the above are present — the section only
// appears for findings the exploit pipeline actually touched.
function exploitationProofSection(finding, ctx) {
  const status = finding.exploitation_status;
  const proof = finding.exploit_proof;
  const artifacts = Array.isArray(finding.poc_artifacts) ? finding.poc_artifacts.filter(Boolean) : [];
  const replay = Array.isArray(finding.api_replay_logs) ? finding.api_replay_logs.filter(Boolean) : [];
  if (!status && !proof && artifacts.length === 0 && replay.length === 0) return null;

  const section = el('section', { class: 'fd-section fd-exploitation' });
  section.appendChild(el('h3', { class: 'fd-section-title' },
    el('i', { 'data-lucide': 'target' }), 'Exploitation Proof'));

  if (status) {
    const label = String(status).replace(/_/g, ' ');
    const cls = (status === 'Verified_Exploited') ? 'ok' :
                (status === 'Auth_Gated') ? 'warn' :
                (status === 'Runtime_Failed') ? 'err' : '';
    section.appendChild(el('div', { class: 'fd-exploitation-status' },
      el('span', { class: `badge ${cls}` }, label),
    ));
  }

  if (proof) {
    section.appendChild(el('div', { class: 'fd-exploitation-proof' },
      el('div', { class: 'fd-subhead' }, 'Exfiltrated data'),
      el('pre', { class: 'fd-code' }, proof),
    ));
  }

  if (artifacts.length) {
    const list = el('div', { class: 'fd-poc-list' });
    artifacts.forEach((rel) => {
      const filename = String(rel).split('/').pop();
      const kind = filename.endsWith('.py') ? 'Python' :
                   filename.endsWith('.sh') ? 'Bash (ADB)' :
                   filename.endsWith('.js') ? 'Frida JS' : 'PoC';
      const href = ctx?.session_id
        ? `/reports/${encodeURIComponent(ctx.session_id)}/${rel}`
        : `#${rel}`;
      list.appendChild(el('a', {
        class: 'btn btn-ghost fd-poc-download',
        href,
        download: filename,
      }, el('i', { 'data-lucide': 'download' }), `Download PoC (${kind})`));
    });
    section.appendChild(el('div', { class: 'fd-poc-block' },
      el('div', { class: 'fd-subhead' }, 'Reproducible PoC scripts'),
      list,
    ));
  }

  if (replay.length) {
    section.appendChild(apiReplayTable(replay));
  }

  return section;
}

function apiReplayTable(replay) {
  const details = el('details', { class: 'fd-api-replay', open: true });
  details.appendChild(el('summary', {}, `API replay evidence (${replay.length} attempt${replay.length === 1 ? '' : 's'})`));
  const wrap = el('div', { class: 'fd-api-replay-body' });
  const table = el('table', { class: 'fd-api-replay-table' });
  table.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Mutation'),
    el('th', {}, 'URL'),
    el('th', {}, 'Baseline → Response'),
    el('th', {}, 'Verdict'),
  )));
  const tbody = el('tbody');
  replay.forEach((entry) => {
    const mutation = entry.mutated_id != null
      ? `id → ${entry.mutated_id}`
      : entry.signal_key
        ? `+${entry.signal_key}=${JSON.stringify(entry.payload?.[entry.signal_key])}`
        : '(see snippet)';
    const url = entry.url || '';
    const base = entry.baseline_status ?? '—';
    const got = entry.status ?? entry.error ?? '—';
    const verdict = entry.verdict || '';
    const verdictCls = (verdict === 'bola' || verdict === 'reflected' || verdict === 'accepted') ? 'err' :
                       (verdict === 'no-signal' || verdict === 'rejected') ? '' : 'warn';
    tbody.appendChild(el('tr', {},
      el('td', { class: 'mono' }, mutation),
      el('td', { class: 'mono' }, url),
      el('td', { class: 'mono' }, `${base} → ${got}`),
      el('td', {}, el('span', { class: `badge ${verdictCls}` }, verdict || '—')),
    ));
    if (entry.response_snippet) {
      tbody.appendChild(el('tr', { class: 'fd-api-replay-snippet' },
        el('td', { colspan: '4' },
          el('pre', { class: 'fd-code fd-code-sm' }, String(entry.response_snippet).slice(0, 800)),
        ),
      ));
    }
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  details.appendChild(wrap);
  return details;
}

// ---------- Djini-parity: category detection + concise Static variant ----------
function isStaticToolFinding(finding) {
  if (!finding) return false;
  if (finding.finding_category === 'Static_Tool') return true;
  if (finding.finding_category === 'AI-Powered') return false;
  // No explicit category — infer. Anything the Phase 7.5 pipeline or
  // API replay agents touched has rationale / exploit fields; everything
  // else is treated as a Static Tool finding.
  if (finding.severity_rationale) return false;
  if (finding.exploit_proof) return false;
  if (Array.isArray(finding.api_replay_logs) && finding.api_replay_logs.length) return false;
  if (Array.isArray(finding.poc_artifacts) && finding.poc_artifacts.length) return false;
  if (finding.exploitation_status
      && finding.exploitation_status !== 'Unverified'
      && finding.exploitation_status !== 'Code_Only') return false;
  return true;
}

function renderStaticToolDetailView(finding, agent, ctx) {
  const root = el('div', { class: 'finding-detail-v2 finding-detail-static' });
  root.appendChild(headerBanner(finding, ctx));
  root.appendChild(el('section', { class: 'fd-section' },
    el('h3', {}, el('i', { 'data-lucide': 'file-text', 'aria-hidden': 'true' }), 'Description'),
    el('p', { class: 'fd-prose' },
      finding.evidence?.description || finding.evidence?.summary || finding.recommendation || '—'),
    agent ? el('div', { class: 'fd-agent-attribution text-muted' },
      `Detected by ${agent.id}${agent.name ? ' — ' + agent.name : ''}`) : null,
  ));
  const meta = metadataTagsSection(finding);
  if (meta) root.appendChild(meta);
  const code = affectedCodeSection(finding);
  if (code) root.appendChild(code);
  root.appendChild(remediationSection(finding));
  refreshIcons();
  return root;
}
