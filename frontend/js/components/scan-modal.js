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
      scanProfile: 'fast',
      dynamic: false,
      frida: false,
      noProxy: false,
      privacy: false,
      llmTriage: false,
      allowLivePoc: false,
      planner: false,
      fuzz: false,
      mlStrategy: false,
      deviceType: 'physical',
      deviceSerial: "",
      dynamicDuration: 30,
      fridaDuration: 30,
      fuzzTime: 60,
      mlModelPath: "",
      uiDriver: 'off',
      appiumUrl: 'http://127.0.0.1:4723',
      testUsername: '',
      testPassword: '',
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
    mkPreset('Fast batch',
      'High-signal static checks for scanning many APKs quickly',
      { scanProfile: 'fast', dynamic: false, frida: false, noProxy: false,
        llmTriage: false, allowLivePoc: false, planner: false, fuzz: false,
        mlStrategy: false, dynamicDuration: 10, fridaDuration: 10, uiDriver: 'off' }),
    mkPreset('SAST only',
      'Full static roster — no device required',
      { scanProfile: 'standard', dynamic: false, frida: false,
        noProxy: false, llmTriage: false, allowLivePoc: false,
        planner: false, fuzz: false, mlStrategy: false, uiDriver: 'off' }),
    mkPreset('Full VAPT',
      'SAST + DAST + Frida + Appium self-login/navigation + PoC scripts + planner + ML + fuzzing (device + frida-server + Appium required)',
      { scanProfile: 'deep', dynamic: true, frida: true, noProxy: false, llmTriage: true,
        allowLivePoc: true, planner: true, fuzz: true, mlStrategy: true,
        dynamicDuration: 60, fridaDuration: 45, fuzzTime: 60, uiDriver: 'appium' }),
    mkPreset('Stealth VAPT',
      'Full VAPT with anti-MITM apps — skips proxy, uses Monkey driver, still emits PoCs + fuzzes',
      { scanProfile: 'deep', dynamic: true, frida: true, noProxy: true, llmTriage: true,
        allowLivePoc: true, planner: true, fuzz: true, mlStrategy: true,
        dynamicDuration: 60, fridaDuration: 45, fuzzTime: 60, uiDriver: 'monkey' }),
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
    toggleRow('allowLivePoc', 'Live PoC artifacts', 'Let PoC Studio emit runnable Frida/curl/HTML exploit scripts for confirmed dynamic findings. Off → markdown-only reproduction guides.', 'authorized only'),
    toggleRow('planner', 'AI Agent Ordering (experimental)', 'LLM-driven agent ordering; falls back to heuristic when no LLM is available.', 'experimental'),
    toggleRow('fuzz', 'AFL++ JNI fuzzing', 'Compile + fuzz the libFuzzer harnesses META_006 emits. Requires clang/afl-fuzz/qemu-user-static on PATH; skips cleanly when absent.', 'toolchain'),
    toggleRow('mlStrategy', 'AI Finding Prioritiser', 'Use the GradientBoostingClassifier in sentinel.learning.ml_strategy instead of the rule-based map. Falls back to the map when sklearn is missing.', 'sklearn'),
  );
  wrap.appendChild(card);

  wrap.appendChild(el('div', { class: 'field', style: 'margin-top: 12px;' },
    el('label', { class: 'field-label' }, 'Scan profile'),
    el('select', {
      class: 'input',
      value: state.options.scanProfile,
      onchange: (e) => { state.options.scanProfile = e.target.value; },
    },
      el('option', { value: 'fast', selected: state.options.scanProfile === 'fast' ? true : null }, 'Fast'),
      el('option', { value: 'standard', selected: state.options.scanProfile === 'standard' ? true : null }, 'Standard'),
      el('option', { value: 'deep', selected: state.options.scanProfile === 'deep' ? true : null }, 'Deep'),
    ),
  ));

  // Device type + serial
  const DEVICE_TYPES = [
    {
      val: 'physical',
      label: 'Physical device',
      icon: 'smartphone',
      serial: '',
      serialPlaceholder: 'leave blank for round-robin (e.g. R9ZR900AEJT)',
      hint: 'Connect via USB and confirm adb devices shows the serial. Enable USB debugging in Developer Options.',
      warn: null,
    },
    {
      val: 'avd',
      label: 'Android Studio AVD',
      icon: 'monitor-smartphone',
      serial: 'emulator-5554',
      serialPlaceholder: 'emulator-5554',
      hint: 'Start the AVD in Android Studio or with: emulator -avd <name>. Default serial is emulator-5554.',
      warn: null,
    },
    {
      val: 'genymotion',
      label: 'Genymotion',
      icon: 'layers',
      serial: '192.168.56.101:5555',
      serialPlaceholder: '192.168.56.101:5555',
      hint: 'Start your Genymotion VM, then run: adb connect 192.168.56.101:5555. Default IP shown — check Genymotion settings if different.',
      warn: 'Ensure ARM Translation is installed in your Genymotion VM (Settings → Android → ARM Translation) for apps that use native ARM libraries.',
    },
  ];

  const currentType = DEVICE_TYPES.find(d => d.val === state.options.deviceType) || DEVICE_TYPES[0];

  const deviceSection = el('div', { style: 'margin-top: 16px;' });
  deviceSection.appendChild(el('div', { class: 'field-label', style: 'margin-bottom: 6px;' }, 'Device / Emulator'));

  // Type pills
  const typePills = el('div', { style: 'display: flex; gap: 8px; margin-bottom: 10px; flex-wrap: wrap;' });
  DEVICE_TYPES.forEach(({ val, label, icon, serial: defaultSerial }) => {
    const active = state.options.deviceType === val;
    const pill = el('button', {
      class: `btn btn-sm ${active ? 'btn-primary' : 'btn-ghost'}`,
      style: 'display: flex; align-items: center; gap: 6px;',
    },
      el('i', { 'data-lucide': icon }),
      label,
    );
    pill.addEventListener('click', () => {
      state.options.deviceType = val;
      // Auto-fill serial with the device type default when user hasn't typed one
      if (defaultSerial && !state.options.deviceSerial) {
        state.options.deviceSerial = defaultSerial;
      } else if (defaultSerial) {
        state.options.deviceSerial = defaultSerial;
      }
      renderStep();
    });
    typePills.appendChild(pill);
  });
  deviceSection.appendChild(typePills);

  // Contextual hint
  deviceSection.appendChild(el('div', {
    class: 'card',
    style: 'padding: 10px 14px; display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px; background: var(--accent-bg-soft);',
  },
    el('i', { 'data-lucide': currentType.icon, style: 'flex-shrink: 0; margin-top: 2px; color: var(--accent-primary);' }),
    el('span', { style: 'font-size: 13px; color: var(--text-secondary);' }, currentType.hint),
  ));

  // Genymotion ARM translation warning
  if (currentType.warn) {
    deviceSection.appendChild(el('div', {
      class: 'card',
      style: 'padding: 10px 14px; display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px; background: var(--sev-medium-bg, #2d2200); border-left: 3px solid var(--sev-medium, #f59e0b);',
    },
      el('i', { 'data-lucide': 'alert-triangle', style: 'flex-shrink: 0; margin-top: 2px; color: var(--sev-medium, #f59e0b);' }),
      el('span', { style: 'font-size: 13px; color: var(--text-secondary);' }, currentType.warn),
    ));
  }

  // Serial input
  deviceSection.appendChild(el('div', { class: 'field' },
    el('label', { class: 'field-label' }, 'Device serial'),
    el('input', {
      class: 'input', type: 'text',
      placeholder: currentType.serialPlaceholder,
      value: state.options.deviceSerial || '',
      oninput: (e) => { state.options.deviceSerial = e.target.value.trim(); },
    }),
  ));

  wrap.appendChild(deviceSection);

  // UI Driver section
  const driverSection = el('div', { style: 'margin-top: 20px;' });
  driverSection.appendChild(el('div', { class: 'field-label', style: 'margin-bottom: 6px;' }, 'UI Driver'));
  driverSection.appendChild(el('div', { class: 'text-muted', style: 'font-size: 12px; margin-bottom: 10px;' },
    'Autonomous app interaction during dynamic phase — self-login, navigation, and scrolling.'));

  const driverPills = el('div', { style: 'display: flex; gap: 8px; margin-bottom: 12px;' });
  [
    { val: 'off',    label: 'Off',    desc: 'No automation — manual or pre-recorded traffic only' },
    { val: 'monkey', label: 'Monkey', desc: 'Blind random events via adb monkey — no login, no targeted nav' },
    { val: 'appium', label: 'Appium', desc: 'Smart: auto-detects login fields, self-navigates, self-scrolls across any app' },
  ].forEach(({ val, label, desc }) => {
    const active = state.options.uiDriver === val;
    const pill = el('button', {
      class: `btn btn-sm ${active ? 'btn-primary' : 'btn-ghost'}`,
      title: desc,
    }, label);
    pill.addEventListener('click', () => {
      state.options.uiDriver = val;
      renderStep();
    });
    driverPills.appendChild(pill);
  });
  driverSection.appendChild(driverPills);

  // Driver-specific hint
  const driverHint = {
    off:    { icon: 'minus-circle',  text: 'No UI automation. Rely on manual device interaction or a pre-captured traffic file.' },
    monkey: { icon: 'shuffle',       text: 'Random touch/swipe events. Cannot log in or reach specific screens.' },
    appium: { icon: 'bot',           text: 'Requires Appium server running on port 4723. Detects login fields automatically — works on any app.' },
  }[state.options.uiDriver];

  const hint = el('div', {
    class: 'card',
    style: 'padding: 10px 14px; display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px; background: var(--accent-bg-soft);',
  },
    el('i', { 'data-lucide': driverHint.icon, style: 'flex-shrink: 0; margin-top: 2px; color: var(--accent-primary);' }),
    el('span', { style: 'font-size: 13px; color: var(--text-secondary);' }, driverHint.text),
  );
  driverSection.appendChild(hint);

  // Appium-specific extra fields
  if (state.options.uiDriver === 'appium') {
    const appiumFields = el('div', { style: 'display: grid; grid-template-columns: 1fr 1fr; gap: 12px;' });
    appiumFields.append(
      el('div', { class: 'field' },
        el('label', { class: 'field-label' }, 'Appium server URL'),
        el('input', {
          class: 'input', type: 'text',
          placeholder: 'http://127.0.0.1:4723',
          value: state.options.appiumUrl,
          oninput: (e) => { state.options.appiumUrl = e.target.value.trim(); },
        }),
      ),
      el('div', { class: 'field' },
        el('label', { class: 'field-label' }, 'Test username (auto-login)'),
        el('input', {
          class: 'input', type: 'text',
          placeholder: 'test@example.com',
          value: state.options.testUsername,
          oninput: (e) => { state.options.testUsername = e.target.value.trim(); },
        }),
      ),
      el('div', { class: 'field' },
        el('label', { class: 'field-label' }, 'Test password'),
        el('input', {
          class: 'input', type: 'password',
          placeholder: 'leave blank to skip auto-login',
          value: state.options.testPassword,
          oninput: (e) => { state.options.testPassword = e.target.value; },
        }),
      ),
    );
    driverSection.appendChild(appiumFields);

    driverSection.appendChild(el('div', { class: 'text-muted', style: 'font-size: 11px; margin-top: 8px;' },
      'Credentials are stored only for this scan session and never logged. Use test accounts only.'));
  }
  wrap.appendChild(driverSection);

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
    el('div', { class: 'field' },
      el('label', { class: 'field-label' }, 'Fuzz time per harness (sec)'),
      el('input', { class: 'input', type: 'number', min: 10, max: 3600, value: state.options.fuzzTime,
        oninput: (e) => { state.options.fuzzTime = +e.target.value || 60; } }),
    ),
    el('div', { class: 'field' },
      el('label', { class: 'field-label' }, 'ML model path (optional)'),
      el('input', { class: 'input', type: 'text', placeholder: 'data/model.pkl — leave blank for bootstrap',
        value: state.options.mlModelPath,
        oninput: (e) => { state.options.mlModelPath = e.target.value.trim(); } }),
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
    ['Scan profile',    state.options.scanProfile],
    ['Dynamic',         state.options.dynamic ? `Yes (${state.options.dynamicDuration}s)` : 'No'],
    ['Frida',           state.options.frida ? `Yes (${state.options.fridaDuration}s)` : 'No'],
    ['No-proxy',        state.options.noProxy ? 'Yes' : 'No'],
    ['Privacy mode',    state.options.privacy ? 'Local LLM' : 'Cloud LLM'],
    ['LLM triage',      state.options.llmTriage ? 'Enabled' : 'Disabled'],
    ['Live PoC',        state.options.allowLivePoc ? 'Enabled (runnable scripts)' : 'Markdown-only'],
    ['Planner',         state.options.planner ? 'Adaptive' : 'Procedural'],
    ['AFL++ fuzz',      state.options.fuzz ? `Enabled (${state.options.fuzzTime}s/harness)` : 'Disabled'],
    ['ML strategy',     state.options.mlStrategy ? (state.options.mlModelPath || 'Bootstrap classifier') : 'Rule-based map'],
    ['Device type',     { physical: 'Physical device', avd: 'Android Studio AVD', genymotion: 'Genymotion' }[state.options.deviceType] || 'Physical device'],
    ['Device serial',   state.options.deviceSerial || 'Pool round-robin'],
    ['UI Driver',       {
      off:    'Off (manual / pre-recorded)',
      monkey: 'Monkey (blind random events)',
      appium: `Appium — self-login, navigate, scroll${state.options.testUsername ? ` · user: ${state.options.testUsername}` : ''}`,
    }[state.options.uiDriver] || state.options.uiDriver],
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
  if (state.options.allowLivePoc) flags.push('--allow-live-poc');
  if (state.options.planner) flags.push('--planner');
  if (state.options.fuzz) flags.push(`--fuzz --fuzz-time ${state.options.fuzzTime}`);
  if (state.options.mlStrategy) flags.push('--ml-strategy');
  if (state.options.mlModelPath) flags.push(`--ml-model-path ${state.options.mlModelPath}`);
  if (state.options.deviceType && state.options.deviceType !== 'physical') flags.push(`--device-type ${state.options.deviceType}`);
  if (state.options.deviceSerial) flags.push(`--device-serial ${state.options.deviceSerial}`);
  if (state.options.uiDriver && state.options.uiDriver !== 'off') {
    flags.push(`--ui-driver ${state.options.uiDriver}`);
    if (state.options.uiDriver === 'appium' && state.options.appiumUrl && state.options.appiumUrl !== 'http://127.0.0.1:4723') {
      flags.push(`--appium-url ${state.options.appiumUrl}`);
    }
    if (state.options.uiDriver === 'appium' && state.options.testUsername) {
      flags.push(`--test-username ${state.options.testUsername}`);
    }
  }
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
      scan_profile: state.options.scanProfile,
      dynamic: state.options.dynamic,
      frida: state.options.frida,
      no_proxy: state.options.noProxy,
      privacy: state.options.privacy,
      llm_triage: state.options.llmTriage,
      allow_live_poc: state.options.allowLivePoc,
      planner: state.options.planner,
      fuzz: state.options.fuzz,
      fuzz_time: state.options.fuzzTime,
      ml_strategy: state.options.mlStrategy,
      ml_model_path: state.options.mlModelPath || "",
      device_type: state.options.deviceType || "physical",
      device_serial: state.options.deviceSerial || "",
      dynamic_duration: state.options.dynamicDuration,
      frida_duration: state.options.fridaDuration,
      ui_driver: state.options.uiDriver || "off",
      appium_url: state.options.appiumUrl || "http://127.0.0.1:4723",
      test_username: state.options.testUsername || "",
      test_password: state.options.testPassword || "",
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
