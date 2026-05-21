/**
 * reports.js — Saved reports grid + 5-step report builder.
 *
 * Step 1 Source · Step 2 Template · Step 3 Sections · Step 4 Branding
 * · Step 5 Format. Live preview pane on the right. Generation uses
 * jsPDF (PDF), Blob downloads (HTML/MD/JSON), and a new tab for HTML.
 */

import { REPORTS, TEMPLATES, SECTIONS, FORMATS, getReport } from '../data/reports.js';
import { SCANS, getScan } from '../data/scans.js';
import { PROJECTS, getProject } from '../data/projects.js';
import { findingsByScan } from '../data/findings.js';
import { toast } from '../components/toast.js';

const FMT_ICON = { PDF: 'file-text', HTML: 'globe', MD: 'hash', JSON: 'braces' };

function fmtSize(kb) {
  if (kb < 1024) return `${kb} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

/* ---------- State (form for the builder) ----------------------- */

const state = {
  scope: 'single',
  scanIds: [SCANS[0].id],
  projectId: PROJECTS[0].id,
  template: 'technical',
  sections: new Set(['cover', 'exec', 'methodology', 'phases', 'findings', 'triage', 'recs']),
  branding: {
    title:    'SENTINEL Security Audit',
    subtitle: 'Findings report',
    author:   'Nehal Mehta',
    org:      'Personal',
    logoLabel:'SENTINEL',
  },
  format: 'PDF',
};

/* ---------- Render ---------------------------------------------- */

export function renderReports(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Reports</h1>
        <div class="page-sub">${REPORTS.length} saved · PDF · HTML · Markdown · JSON</div>
      </div>
    </div>

    <h6 class="mb-4">Saved reports</h6>
    <div class="grid-3 mb-8">
      ${REPORTS.map((r) => `
        <article class="card" data-report="${r.id}">
          <div class="row-between mb-3">
            <span class="chip chip-cat"><i data-lucide="${FMT_ICON[r.format]}" style="width:12px;height:12px;"></i> ${r.format}</span>
            <span class="text-mute text-xs">${fmtSize(r.sizeKb)}</span>
          </div>
          <h3 style="font-size: var(--fs-md); margin-bottom: 4px;">${r.title}</h3>
          <div class="text-mute text-xs">by ${r.author} · ${r.generatedAt}</div>
          <p class="text-dim text-sm mt-2">${r.summary}</p>
          <div class="row mt-4">
            <button class="btn btn-secondary btn-sm" data-action="preview"><i data-lucide="eye"></i> Preview</button>
            <button class="btn btn-primary btn-sm" data-action="download"><i data-lucide="download"></i> Download</button>
          </div>
        </article>`).join('')}
    </div>

    <h6 class="mb-4">Report builder</h6>
    <div class="report-builder">
      <div class="stack-lg">
        <!-- STEP 1 SOURCE -->
        <section class="step">
          <h5 class="row-sm mb-3"><span class="step-num">1</span> Source</h5>
          <div class="grid-3" style="gap: var(--space-3);">
            <label class="radio"><input type="radio" name="rb-scope" value="single" ${state.scope==='single'?'checked':''}/> Single scan</label>
            <label class="radio"><input type="radio" name="rb-scope" value="project" ${state.scope==='project'?'checked':''}/> All scans in project</label>
            <label class="radio"><input type="radio" name="rb-scope" value="custom" ${state.scope==='custom'?'checked':''}/> Custom selection</label>
          </div>
          <div class="mt-4" id="rb-source-pick"></div>
        </section>

        <!-- STEP 2 TEMPLATE -->
        <section class="step">
          <h5 class="row-sm mb-3"><span class="step-num">2</span> Template</h5>
          <div class="grid-2">
            ${TEMPLATES.map((t) => `
              <label class="card-flat" style="padding: var(--space-4); cursor:pointer; border: 1px solid var(--border); border-radius: var(--radius-lg);">
                <div class="row-sm mb-2"><input type="radio" name="rb-tmpl" value="${t.id}" ${state.template===t.id?'checked':''}/> <i data-lucide="${t.icon}"></i> <strong>${t.name}</strong></div>
                <div class="text-dim text-sm">${t.desc}</div>
              </label>`).join('')}
          </div>
        </section>

        <!-- STEP 3 SECTIONS -->
        <section class="step">
          <h5 class="row-sm mb-3"><span class="step-num">3</span> Sections to include</h5>
          <div class="grid-3" style="gap: var(--space-2);">
            ${SECTIONS.map((s) => `<label class="checkbox"><input type="checkbox" data-section="${s.id}" ${state.sections.has(s.id)?'checked':''}/> ${s.name}</label>`).join('')}
          </div>
        </section>

        <!-- STEP 4 BRANDING -->
        <section class="step">
          <h5 class="row-sm mb-3"><span class="step-num">4</span> Branding</h5>
          <div class="form-row">
            <div class="form-group"><label class="label">Title</label><input class="input" data-br="title" value="${state.branding.title}"/></div>
            <div class="form-group"><label class="label">Subtitle</label><input class="input" data-br="subtitle" value="${state.branding.subtitle}"/></div>
          </div>
          <div class="form-row mt-3">
            <div class="form-group"><label class="label">Author</label><input class="input" data-br="author" value="${state.branding.author}"/></div>
            <div class="form-group"><label class="label">Organisation</label><input class="input" data-br="org" value="${state.branding.org}"/></div>
          </div>
        </section>

        <!-- STEP 5 FORMAT -->
        <section class="step">
          <h5 class="row-sm mb-3"><span class="step-num">5</span> Format</h5>
          <div class="grid-4" style="gap: var(--space-3);">
            ${FORMATS.map((f) => `
              <label class="card-flat" style="padding: var(--space-3); text-align:center; cursor:pointer; border:1px solid var(--border); border-radius: var(--radius-md);">
                <input type="radio" name="rb-fmt" value="${f.id}" ${state.format===f.id?'checked':''} style="display:none;"/>
                <i data-lucide="${f.icon}" style="width:24px;height:24px;display:block;margin:0 auto var(--space-2);"></i>
                <div style="font-weight:600;">${f.name}</div>
              </label>`).join('')}
          </div>
        </section>

        <div class="row-sm">
          <button class="btn btn-ghost btn-sm" id="rb-save-draft"><i data-lucide="save"></i> Save draft</button>
          <button class="btn btn-primary btn-sm" id="rb-generate" style="margin-left:auto;"><i data-lucide="play"></i> Generate report</button>
        </div>
      </div>

      <!-- PREVIEW PANE -->
      <aside class="report-preview">
        <div class="row-between mb-3">
          <strong>Live preview</strong>
          <span class="chip chip-cat" id="rb-fmt-chip">PDF</span>
        </div>
        <div class="report-paper" id="rb-paper"></div>
      </aside>
    </div>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  renderSourcePicker(mount);
  renderPreview(mount);

  /* ---------- form wiring ----------------------------------------- */

  mount.querySelectorAll('[name="rb-scope"]').forEach((r) => r.addEventListener('change', (e) => {
    state.scope = e.target.value;
    renderSourcePicker(mount);
    renderPreview(mount);
  }));
  mount.querySelectorAll('[name="rb-tmpl"]').forEach((r) => r.addEventListener('change', (e) => {
    state.template = e.target.value;
    renderPreview(mount);
  }));
  mount.querySelectorAll('[data-section]').forEach((cb) => cb.addEventListener('change', () => {
    const id = cb.dataset.section;
    if (cb.checked) state.sections.add(id);
    else state.sections.delete(id);
    renderPreview(mount);
  }));
  mount.querySelectorAll('[data-br]').forEach((inp) => inp.addEventListener('input', (e) => {
    state.branding[e.target.dataset.br] = e.target.value;
    renderPreview(mount);
  }));
  mount.querySelectorAll('[name="rb-fmt"]').forEach((r) => r.addEventListener('change', (e) => {
    state.format = e.target.value;
    mount.querySelector('#rb-fmt-chip').textContent = state.format;
    renderPreview(mount);
  }));
  mount.querySelector('#rb-save-draft').addEventListener('click', () => toast('Draft saved (mock)', { type: 'info' }));
  mount.querySelector('#rb-generate').addEventListener('click', () => generate(state));

  /* Saved reports actions */
  mount.querySelectorAll('[data-report]').forEach((card) => {
    card.querySelector('[data-action="preview"]').addEventListener('click', () => {
      const r = getReport(card.dataset.report);
      toast(`Previewing "${r.title}" (mock)`, { type: 'info' });
    });
    card.querySelector('[data-action="download"]').addEventListener('click', () => {
      const r = getReport(card.dataset.report);
      regenerateSaved(r);
    });
  });
}

/* ---------- Source picker (changes based on scope) ----------- */

function renderSourcePicker(mount) {
  const slot = mount.querySelector('#rb-source-pick');
  if (state.scope === 'single') {
    slot.innerHTML = `<select class="select" id="rb-single-scan">
      ${SCANS.map((s) => `<option value="${s.id}" ${state.scanIds[0]===s.id?'selected':''}>${s.apkName} · ${s.id}</option>`).join('')}
    </select>`;
    slot.querySelector('#rb-single-scan').addEventListener('change', (e) => {
      state.scanIds = [e.target.value];
      renderPreview(mount);
    });
  } else if (state.scope === 'project') {
    slot.innerHTML = `<select class="select" id="rb-proj">
      ${PROJECTS.map((p) => `<option value="${p.id}" ${state.projectId===p.id?'selected':''}>${p.name}</option>`).join('')}
    </select>`;
    slot.querySelector('#rb-proj').addEventListener('change', (e) => {
      state.projectId = e.target.value;
      state.scanIds = SCANS.filter((s) => s.projectId === state.projectId).map((s) => s.id);
      renderPreview(mount);
    });
    state.scanIds = SCANS.filter((s) => s.projectId === state.projectId).map((s) => s.id);
  } else {
    slot.innerHTML = `<div class="card-flat" style="padding: var(--space-3); max-height: 200px; overflow-y: auto;">
      ${SCANS.map((s) => `<label class="checkbox" style="padding: 4px 0;"><input type="checkbox" data-cs="${s.id}" ${state.scanIds.includes(s.id)?'checked':''}/> <code class="mono" style="font-size:12px;">${s.id}</code> · ${s.apkName}</label><br>`).join('')}
    </div>`;
    slot.querySelectorAll('[data-cs]').forEach((cb) => cb.addEventListener('change', () => {
      const id = cb.dataset.cs;
      if (cb.checked) state.scanIds = [...new Set([...state.scanIds, id])];
      else            state.scanIds = state.scanIds.filter((x) => x !== id);
      renderPreview(mount);
    }));
  }
}

/* ---------- Preview ------------------------------------------ */

function renderPreview(mount) {
  const paper = mount.querySelector('#rb-paper');
  const scans = state.scanIds.map((id) => getScan(id)).filter(Boolean);
  const totalFindings = scans.reduce((n, s) => n + s.counts.critical + s.counts.high + s.counts.medium + s.counts.low + s.counts.info, 0);
  paper.innerHTML = `
    <div style="font-size:10px; color:#7C3AED; letter-spacing:.12em; text-transform:uppercase;">${state.branding.logoLabel}</div>
    <h2>${state.branding.title}</h2>
    <div style="color:#5C5C70; font-size:10px;">${state.branding.subtitle}</div>
    <hr class="divider"/>
    <p><strong>Author:</strong> ${state.branding.author}</p>
    <p><strong>Organisation:</strong> ${state.branding.org}</p>
    <p><strong>Scans included:</strong> ${scans.length}</p>
    <p><strong>Total findings:</strong> ${totalFindings}</p>
    <p><strong>Format:</strong> ${state.format}</p>
    ${state.sections.has('exec') ? '<h3 class="accent">Executive summary</h3><p>This report covers ' + scans.length + ' scan(s) producing ' + totalFindings + ' findings, prioritised by severity and LLM-triage outcome.</p>' : ''}
    ${state.sections.has('methodology') ? '<h3 class="accent">Methodology</h3><p>SENTINEL 5-phase pipeline · static analysis + dynamic capture + Frida runtime hooks · LLM triage with provider rotation.</p>' : ''}
    ${state.sections.has('phases') ? '<h3 class="accent">Phase timings</h3>' + scans.slice(0,2).map((s) => `<p style="font-family:monospace; font-size:10px;">${s.id} · ` + Object.entries(s.phaseTimings).map(([k,v]) => `${k}=${v.toFixed(1)}s`).join(' · ') + '</p>').join('') : ''}
    ${state.sections.has('findings') ? '<h3 class="accent">Findings detail</h3><p>See appendix for full findings table.</p>' : ''}
    ${state.sections.has('recs') ? '<h3 class="accent">Recommendations</h3><p>Triaged remediations grouped by severity, with sample-fix snippets where applicable.</p>' : ''}
  `;
}

/* ---------- Generation --------------------------------------- */

function generate(s) {
  const scans = s.scanIds.map((id) => getScan(id)).filter(Boolean);
  if (!scans.length) { toast('Pick at least one scan first', { type: 'warning' }); return; }

  if (s.format === 'PDF')  return generatePdf(s, scans);
  if (s.format === 'JSON') return downloadBlob(JSON.stringify(buildJson(s, scans), null, 2), 'application/json', filename(s) + '.json');
  if (s.format === 'MD')   return downloadBlob(buildMarkdown(s, scans), 'text/markdown', filename(s) + '.md');
  if (s.format === 'HTML') return openHtmlReport(s, scans);
}

function filename(s) {
  const safe = s.branding.title.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  return `${safe}-${new Date().toISOString().slice(0,10)}`;
}

function downloadBlob(content, mime, name) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`Downloaded ${name}`, { type: 'success' });
}

function buildJson(s, scans) {
  return {
    title: s.branding.title,
    subtitle: s.branding.subtitle,
    author: s.branding.author,
    org:    s.branding.org,
    generatedAt: new Date().toISOString(),
    template: s.template,
    scans: scans.map((sc) => ({
      ...sc,
      findings: findingsByScan(sc.id),
    })),
  };
}

function buildMarkdown(s, scans) {
  const lines = [];
  lines.push(`# ${s.branding.title}`);
  lines.push(`*${s.branding.subtitle}*`);
  lines.push('');
  lines.push(`**Author:** ${s.branding.author}  `);
  lines.push(`**Organisation:** ${s.branding.org}  `);
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push('');
  for (const sc of scans) {
    const proj = getProject(sc.projectId);
    lines.push(`## Scan \`${sc.id}\` — ${proj?.name || 'Unknown project'}`);
    lines.push(`- APK: \`${sc.apkName}\` (${sc.apkSize} MB)`);
    lines.push(`- Started: ${sc.startedAt}`);
    lines.push(`- Status: **${sc.status}**`);
    lines.push(`- Findings: Critical ${sc.counts.critical} · High ${sc.counts.high} · Medium ${sc.counts.medium} · Low ${sc.counts.low} · Info ${sc.counts.info}`);
    lines.push('');
    if (s.sections.has('findings')) {
      const findings = findingsByScan(sc.id);
      for (const f of findings) {
        lines.push(`### [${f.severity}] ${f.vulnClass}`);
        lines.push(`- Agent: \`${f.agentId}\``);
        lines.push(`- Triage: ${f.triage} (confidence ${(f.confidence*100).toFixed(0)}%)`);
        if (f.evidence.file) lines.push(`- Evidence: \`${f.evidence.file}\``);
        if (f.evidence.fridaEvent) lines.push(`- Evidence: ${f.evidence.fridaEvent}`);
        if (f.evidence.request) lines.push(`- Request: \`${f.evidence.request}\``);
        if (f.evidence.snippet) lines.push('```\n' + f.evidence.snippet + '\n```');
        lines.push(`- Recommendation: ${f.recommendation}`);
        lines.push('');
      }
    }
  }
  return lines.join('\n');
}

function openHtmlReport(s, scans) {
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>${s.branding.title}</title>
    <style>
      body{font:14px/1.6 Inter,system-ui,sans-serif;background:#070A12;color:#E6EAF2;padding:48px;max-width:880px;margin:0 auto;}
      h1,h2,h3{color:#E6EAF2;}
      h1{font-size:32px;letter-spacing:-.02em;background:linear-gradient(135deg,#7C3AED,#22D3EE,#34D399);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
      code{font-family:'JetBrains Mono',monospace;background:#141B2E;padding:2px 6px;border-radius:4px;color:#22D3EE;}
      .meta{color:#9CA8C0;}
      .sev-Critical{color:#EF4444;} .sev-High{color:#F97316;} .sev-Medium{color:#FBBF24;}
      .card{background:#0E1322;border:1px solid #1F2940;border-radius:14px;padding:24px;margin:16px 0;}
      hr{border:none;border-top:1px solid #1F2940;margin:24px 0;}
    </style></head><body>
    <h1>${s.branding.title}</h1>
    <p class="meta">${s.branding.subtitle} · ${s.branding.author} · ${s.branding.org}</p>
    <hr/>
    ${scans.map((sc) => {
      const findings = findingsByScan(sc.id);
      return `<div class="card"><h2>Scan ${sc.id}</h2>
        <p class="meta">${sc.apkName} · ${sc.startedAt} · ${sc.status}</p>
        ${findings.map((f) => `<div style="border-left:3px solid #2A3454;padding-left:12px;margin:12px 0;">
          <div><strong class="sev-${f.severity}">[${f.severity}]</strong> ${f.vulnClass}</div>
          <div class="meta" style="font-size:12px;">Agent <code>${f.agentId}</code> · triage <code>${f.triage}</code> · ${(f.confidence*100).toFixed(0)}%</div>
          <p>${f.recommendation}</p>
        </div>`).join('')}
      </div>`;
    }).join('')}
  </body></html>`;
  const w = window.open('', '_blank');
  if (w) { w.document.write(html); w.document.close(); toast('Opened HTML report in new tab', { type: 'success' }); }
  else toast('Pop-up blocked — allow pop-ups for this site', { type: 'warning' });
}

function generatePdf(s, scans) {
  if (!window.jspdf?.jsPDF) { toast('jsPDF not loaded yet — try again in a moment', { type: 'warning' }); return; }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });

  const m = 56;
  let y = m + 8;

  /* Cover */
  doc.setFillColor(7, 10, 18);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), doc.internal.pageSize.getHeight(), 'F');
  doc.setTextColor(34, 211, 238);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text(s.branding.logoLabel, m, m);
  doc.setTextColor(230, 234, 242);
  doc.setFontSize(28);
  doc.text(s.branding.title, m, y + 32);
  doc.setFontSize(14);
  doc.setTextColor(156, 168, 192);
  doc.text(s.branding.subtitle, m, y + 60);
  doc.setFontSize(10);
  doc.text(`${s.branding.author} · ${s.branding.org} · ${new Date().toISOString().slice(0,10)}`, m, y + 86);

  /* Stats */
  y = y + 130;
  const total = scans.reduce((n, sc) => n + sc.counts.critical + sc.counts.high + sc.counts.medium + sc.counts.low + sc.counts.info, 0);
  doc.setDrawColor(31, 41, 64);
  doc.setLineWidth(0.5);
  doc.line(m, y, doc.internal.pageSize.getWidth() - m, y);
  y += 24;
  doc.setTextColor(230, 234, 242);
  doc.setFontSize(11);
  doc.text(`Scans included: ${scans.length}    Total findings: ${total}    Format: PDF`, m, y);

  /* Per-scan body */
  doc.addPage();
  y = m;
  for (const sc of scans) {
    if (y > doc.internal.pageSize.getHeight() - m) { doc.addPage(); y = m; }
    const proj = getProject(sc.projectId);
    doc.setFontSize(14); doc.setTextColor(230, 234, 242);
    doc.text(`Scan ${sc.id}`, m, y); y += 16;
    doc.setFontSize(10); doc.setTextColor(156, 168, 192);
    doc.text(`${proj?.name || ''}  ·  ${sc.apkName}  ·  ${sc.startedAt}  ·  ${sc.status}`, m, y); y += 14;
    doc.setTextColor(239, 68, 68); doc.text(`Critical ${sc.counts.critical}`, m, y);
    doc.setTextColor(249, 115, 22); doc.text(`High ${sc.counts.high}`, m + 80, y);
    doc.setTextColor(251, 191, 36); doc.text(`Medium ${sc.counts.medium}`, m + 140, y);
    doc.setTextColor(59, 130, 246); doc.text(`Low ${sc.counts.low}`, m + 220, y);
    doc.setTextColor(107, 114, 128); doc.text(`Info ${sc.counts.info}`, m + 270, y);
    y += 20;

    if (s.sections.has('findings')) {
      const findings = findingsByScan(sc.id);
      for (const f of findings) {
        if (y > doc.internal.pageSize.getHeight() - m - 40) { doc.addPage(); y = m; }
        doc.setTextColor(severityRgb(f.severity)[0], severityRgb(f.severity)[1], severityRgb(f.severity)[2]);
        doc.setFontSize(10);
        doc.text(`[${f.severity}]`, m, y);
        doc.setTextColor(230, 234, 242);
        const wrapped = doc.splitTextToSize(f.vulnClass, doc.internal.pageSize.getWidth() - m - m - 60);
        doc.text(wrapped, m + 60, y);
        y += 14 * wrapped.length;
        doc.setTextColor(156, 168, 192); doc.setFontSize(9);
        doc.text(`agent ${f.agentId}  triage ${f.triage}  conf ${(f.confidence*100).toFixed(0)}%`, m, y); y += 12;
        const rec = doc.splitTextToSize(f.recommendation, doc.internal.pageSize.getWidth() - m * 2);
        doc.text(rec, m, y); y += 12 * rec.length + 8;
      }
    }
    y += 12;
  }

  /* Footer note */
  doc.setFontSize(8); doc.setTextColor(92, 103, 136);
  doc.text('Generated by SENTINEL · sentinel.dev', m, doc.internal.pageSize.getHeight() - 28);

  doc.save(filename(s) + '.pdf');
  toast('PDF generated', { type: 'success' });
}

function severityRgb(sev) {
  switch (sev) {
    case 'Critical': return [239, 68, 68];
    case 'High':     return [249, 115, 22];
    case 'Medium':   return [251, 191, 36];
    case 'Low':      return [59, 130, 246];
    default:         return [156, 168, 192];
  }
}

function regenerateSaved(r) {
  /* Re-issue a download for the saved report in its native format. */
  const dummyState = {
    scope: r.scope, scanIds: r.scanIds, projectId: r.projectId,
    template: r.template, sections: new Set(r.sections),
    branding: r.branding, format: r.format,
  };
  generate(dummyState);
}
