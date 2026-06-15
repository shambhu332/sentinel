// Scan Configuration multi-step modal — wires the real APK upload
// + the real /scans endpoint, then navigates to the live scan-detail page.
import { el, refreshIcons, toast } from '../utils.js';
import { openModal, closeModal } from './modal.js';
import { codeBlock } from './code-block.js';
import { api, ApiError } from '../api.js';

const STEPS = ['App', 'Options', 'Scope', 'Review'];

let state = null;

export function openScanModal(prefill = {}) {
  state = {
    step: 0,
    file: prefill.file || null,
    fileName: prefill.fileName || (prefill.file ? prefill.file.name : null),
    fileSize: prefill.fileSize || (prefill.file ? prefill.file.size / (1024 * 1024) : null),
    uploading: false,
    options: {
      dynamic: false,
      frida: false,
      noProxy: false,
      privacy: false,
      llmTriage: true,
      dynamicDuration: 30,
      fridaDuration: 30,
    },
    scope: '',
  };

  const body = el('div', { id: 'scan-modal-body' });
  const footer = el('div', { style: 'display: flex; justify-content: space-between; width: 100%;' },
    el('div', {},
      el('button', { class: 'btn btn-ghost', id: 'scan-back', disabled: true }, 'Back'),
    ),
    el('div', { style: 'display: flex; gap: 8px;' },
      el('button', { class: 'btn btn-ghost', id: 'scan-cancel' }, 'Cancel'),
      el('button', { class: 'btn btn-primary', id: 'scan-next' }, 'Next'),
    ),
  );

  openModal({
    title: 'New Scan',
    body,
    footer,
    size: 'lg',
  });

  renderStep();

  document.getElementById('scan-cancel').addEventListener('click', closeModal);
  document.getElementById('scan-back').addEventListener('click', () => {
    if (state.step > 0) { state.step--; renderStep(); }
  });
  document.getElementById('scan-next').addEventListener('click', () => {
    if (state.step < STEPS.length - 1) { state.step++; renderStep(); }
    else { startScan(); }
  });
}

function renderStep() {
  const body = document.getElementById('scan-modal-body');
  body.innerHTML = '';

  // Stepper
  const stepper = el('div', { class: 'steps' });
  STEPS.forEach((name, i) => {
    const step = el('div', { class: `step ${i === state.step ? 'active' : ''} ${i < state.step ? 'complete' : ''}` },
      el('div', { class: 'step-num' }, i < state.step ? '✓' : String(i + 1)),
      el('span', {}, name),
    );
    stepper.appendChild(step);
    if (i < STEPS.length - 1) stepper.appendChild(el('div', { class: 'step-line' }));
  });
  body.appendChild(stepper);

  if (state.step === 0) body.appendChild(renderStepApp());
  if (state.step === 1) body.appendChild(renderStepOptions());
  if (state.step === 2) body.appendChild(renderStepScope());
  if (state.step === 3) body.appendChild(renderStepReview());

  // Update footer
  document.getElementById('scan-back').disabled = state.step === 0;
  const nextBtn = document.getElementById('scan-next');
  if (state.step === STEPS.length - 1) {
    nextBtn.innerHTML = '';
    const i = document.createElement('i');
    i.setAttribute('data-lucide', 'play');
    nextBtn.appendChild(i);
    nextBtn.appendChild(document.createTextNode('Start Scan'));
  } else {
    nextBtn.innerHTML = '';
    nextBtn.appendChild(document.createTextNode('Next'));
    const i = document.createElement('i');
    i.setAttribute('data-lucide', 'arrow-right');
    nextBtn.appendChild(i);
  }

  refreshIcons();
}

function renderStepApp() {
  const wrap = el('div');
  wrap.appendChild(el('h4', { style: 'margin-bottom: 8px;' }, 'Select an APK'));
  wrap.appendChild(el('p', { class: 'text-muted', style: 'margin-bottom: 16px;' },
    'Drag and drop an APK / AAB / XAPK, or click to browse.'));

  // Hidden native file picker
  const input = el('input', {
    type: 'file',
    accept: '.apk,.aab,.xapk,application/vnd.android.package-archive',
    style: 'display:none;',
  });
  input.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) acceptFile(f);
  });

  const drop = el('div', { class: 'upload-zone', style: 'margin: 0; padding: 28px;' },
    el('i', { 'data-lucide': 'upload-cloud' }),
    el('div', { class: 'upload-title' }, state.fileName ? state.fileName : 'Drop your APK / AAB / XAPK here'),
    el('div', { class: 'upload-sub' }, state.fileName ? '— ready to scan —' : 'or click to browse'),
    el('div', { class: 'upload-formats' }, '.apk · .aab · .xapk  (max 500 MB)'),
  );

  drop.addEventListener('click', () => input.click());
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('dragover'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) acceptFile(f);
  });
  wrap.appendChild(input);
  wrap.appendChild(drop);

  if (state.file) {
    wrap.appendChild(el('div', { class: 'card', style: 'margin-top: 16px; padding: 14px 16px;' },
      el('div', { style: 'display: flex; align-items: center; gap: 12px;' },
        el('div', { class: 'avatar', style: 'background: var(--accent-bg-soft); color: var(--accent-primary);' },
          el('i', { 'data-lucide': 'file' })),
        el('div', { style: 'flex: 1;' },
          el('div', { class: 'mono', style: 'font-size: 13px;' }, state.fileName),
          el('div', { class: 'text-muted', style: 'font-size: 12px;' }, `${state.fileSize?.toFixed(1)} MB`),
        ),
        el('button', { class: 'btn btn-ghost btn-sm', onclick: () => { state.file = null; state.fileName = null; renderStep(); } }, 'Change'),
      ),
    ));
  }

  return wrap;
}

function acceptFile(f) {
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  if (!['apk', 'aab', 'xapk'].includes(ext)) {
    toast(`Unsupported extension .${ext}`, 'error');
    return;
  }
  state.file = f;
  state.fileName = f.name;
  state.fileSize = f.size / (1024 * 1024);
  renderStep();
}

function renderStepOptions() {
  const wrap = el('div');
  wrap.appendChild(el('h4', { style: 'margin-bottom: 8px;' }, 'Scan options'));
  wrap.appendChild(el('p', { class: 'text-muted', style: 'margin-bottom: 12px;' },
    'Pick analysis modes. Dynamic and Frida require a connected Android device with adb and frida-server.'));

  // Quick presets — single click sets a coherent VAPT/SAST/Full posture.
  const presetBar = el('div', { style: 'display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;' });
  function mkPreset(label, desc, opts) {
    const btn = el('button', { class: 'btn btn-ghost btn-sm', title: desc }, label);
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      Object.assign(state.options, opts);
      renderStep();
      toast(`Preset applied: ${label}`, 'success');
    });
    return btn;
  }
  presetBar.append(
    mkPreset('SAST only',
      'Pure static — no device required',
      { dynamic: false, frida: false, noProxy: false, llmTriage: true }),
    mkPreset('Full VAPT',
      'SAST + DAST + Frida hybrid dispatch (device + frida-server required)',
      { dynamic: true, frida: true, noProxy: false, llmTriage: true,
        dynamicDuration: 60, fridaDuration: 45 }),
    mkPreset('Stealth VAPT',
      'Full VAPT with anti-MITM apps — skips proxy',
      { dynamic: true, frida: true, noProxy: true, llmTriage: true,
        dynamicDuration: 60, fridaDuration: 45 }),
    mkPreset('Privacy mode',
      'Local LLM only, no cloud egress for triage',
      { privacy: true, llmTriage: true }),
  );
  wrap.appendChild(presetBar);

  function toggleRow(key, label, desc, badge) {
    const row = el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, label, badge ? el('span', { class: 'badge accent badge-sm', style: 'margin-left: 8px;' }, badge) : null),
        el('div', { class: 'label-desc' }, desc),
      ),
      el('label', { class: 'toggle' },
        el('input', {
          type: 'checkbox',
          checked: state.options[key] ? true : null,
          onchange: (e) => { state.options[key] = e.target.checked; },
        }),
      ),
    );
    return row;
  }

  const card = el('div', { class: 'card', style: 'padding: 8px 16px;' });
  card.append(
    toggleRow('dynamic', 'Dynamic analysis', 'Install + run app on a connected device to capture runtime behavior.', 'requires device'),
    toggleRow('frida',   'Frida runtime hooks', 'Inject Frida hooks for runtime crypto/TLS introspection.', 'frida-server'),
    toggleRow('noProxy', 'No-proxy mode', 'Skip mitmproxy. Use for apps with strict anti-MITM (Signal, banking).', null),
    toggleRow('privacy', 'Privacy mode', 'Force local LLM (Ollama) for triage. Data stays on device.', 'local'),
    toggleRow('llmTriage', 'LLM triage', 'Filter false positives with LLM (Cerebras / Groq / Ollama).', 'recommended'),
  );
  wrap.appendChild(card);

  wrap.appendChild(el('div', { style: 'display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;' },
    el('div', { class: 'field' },
      el('label', { class: 'field-label' }, 'Dynamic duration (sec)'),
      el('input', { class: 'input', type: 'number', min: 10, max: 1800, value: state.options.dynamicDuration,
        oninput: (e) => { state.options.dynamicDuration = +e.target.value || 30; } }),
    ),
    el('div', { class: 'field' },
      el('label', { class: 'field-label' }, 'Frida duration (sec)'),
      el('input', { class: 'input', type: 'number', min: 10, max: 1800, value: state.options.fridaDuration,
        oninput: (e) => { state.options.fridaDuration = +e.target.value || 30; } }),
    ),
  ));

  return wrap;
}

function renderStepScope() {
  const wrap = el('div');
  wrap.appendChild(el('h4', { style: 'margin-bottom: 8px;' }, 'Scope (optional)'));
  wrap.appendChild(el('p', { class: 'text-muted', style: 'margin-bottom: 16px;' },
    'Paste freeform scope rules (in-scope / out-of-scope, packages, domains). Leave blank to scan everything.'));

  wrap.appendChild(el('div', { class: 'field' },
    el('label', { class: 'field-label' }, 'Scope rules'),
    el('textarea', {
      class: 'textarea',
      placeholder: 'in-scope: com.example.banking\nout-of-scope: *.staging.example.com',
      oninput: (e) => { state.scope = e.target.value; },
    }, state.scope),
  ));

  return wrap;
}

function renderStepReview() {
  const wrap = el('div');
  wrap.appendChild(el('h4', { style: 'margin-bottom: 8px;' }, 'Review'));
  wrap.appendChild(el('p', { class: 'text-muted', style: 'margin-bottom: 16px;' },
    'Confirm the scan configuration. The equivalent CLI is shown below.'));

  const summary = el('div', { class: 'card', style: 'padding: 16px;' });
  const rows = [
    ['App',             state.fileName || '(none)'],
    ['Size',            state.fileSize ? state.fileSize.toFixed(1) + ' MB' : '—'],
    ['Dynamic',         state.options.dynamic ? `Yes (${state.options.dynamicDuration}s)` : 'No'],
    ['Frida',           state.options.frida ? `Yes (${state.options.fridaDuration}s)` : 'No'],
    ['No-proxy',        state.options.noProxy ? 'Yes' : 'No'],
    ['Privacy mode',    state.options.privacy ? 'Local LLM' : 'Cloud LLM'],
    ['LLM triage',      state.options.llmTriage ? 'Enabled' : 'Disabled'],
    ['Scope',           state.scope ? truncate(state.scope, 60) : 'None'],
  ];
  rows.forEach(([k, v]) => {
    summary.appendChild(el('div', { class: 'settings-row' },
      el('div', { style: 'flex: 1; font-size: 13px; color: var(--text-muted);' }, k),
      el('div', { style: 'font-size: 13px; color: var(--text-primary); font-family: var(--font-mono);' }, v),
    ));
  });
  wrap.appendChild(summary);

  wrap.appendChild(el('h5', { style: 'margin: 20px 0 8px; font-family: var(--font-mono); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; color: var(--text-muted);' },
    'CLI Preview'));
  wrap.appendChild(buildCliPreview());

  return wrap;
}

function buildCliPreview() {
  const flags = [];
  if (state.fileName) flags.push(`corpus/${state.fileName}`);
  if (state.options.dynamic) flags.push(`--dynamic --dynamic-duration ${state.options.dynamicDuration}`);
  if (state.options.frida) flags.push(`--frida --frida-duration ${state.options.fridaDuration}`);
  if (state.options.noProxy) flags.push('--no-proxy');
  if (state.options.privacy) flags.push('--private');
  if (!state.options.llmTriage) flags.push('--no-triage');
  if (state.scope) flags.push('--scope-text "' + truncate(state.scope, 40) + '"');
  const cli = 'poetry run sentinel scan \\\n  ' + flags.join(' \\\n  ');
  return codeBlock(cli, { showLineNumbers: false });
}

async function startScan() {
  if (!state.file) {
    toast('Please select an APK first.', 'error');
    state.step = 0;
    renderStep();
    return;
  }
  if (state.uploading) return;
  state.uploading = true;

  const nextBtn = document.getElementById('scan-next');
  nextBtn.disabled = true;
  nextBtn.innerHTML = '';
  nextBtn.appendChild(document.createTextNode('Uploading…'));

  try {
    const options = {
      dynamic: state.options.dynamic,
      frida: state.options.frida,
      no_proxy: state.options.noProxy,
      privacy: state.options.privacy,
      llm_triage: state.options.llmTriage,
      dynamic_duration: state.options.dynamicDuration,
      frida_duration: state.options.fridaDuration,
      scope_text: state.scope || null,
    };

    const resp = await api.createScan({
      file: state.file,
      options,
      onProgress: (loaded, total) => {
        const pct = total ? Math.round((loaded / total) * 100) : 0;
        nextBtn.innerHTML = '';
        nextBtn.appendChild(document.createTextNode(`Uploading… ${pct}%`));
      },
    });

    closeModal();
    toast(`Scan started: ${state.fileName}`, 'success');
    location.hash = `#scans/${resp.session_id}`;
  } catch (e) {
    state.uploading = false;
    const msg = e instanceof ApiError ? e.message : String(e);
    toast(`Scan failed to start: ${msg}`, 'error', 5000);
    nextBtn.disabled = false;
    renderStep();
  }
}

function truncate(s, n) { return s && s.length > n ? s.slice(0, n - 1) + '…' : s; }
