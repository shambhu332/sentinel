// Devices page - dynamic testing console for attached Android targets.
import { api, ApiError } from '../api.js';
import { el, refreshIcons, toast } from '../utils.js';

// Active mirror sessions keyed by serial — ensures only one per device.
const _mirrors = new Map();

const GENYMOTION_SERIAL_RE = /^192\.168\.\d+\.\d+:\d+$/;
const GENYMOTION_LOCAL_RE  = /^(127\.0\.0\.1|localhost):\d+$/;
const AVD_SERIAL_RE        = /^emulator-\d+$/;

function detectEmulatorType(serial, manufacturer) {
  const mfr = (manufacturer || '').toLowerCase();
  if (
    GENYMOTION_SERIAL_RE.test(serial) ||
    GENYMOTION_LOCAL_RE.test(serial)  ||
    mfr.includes('genymobile') ||
    mfr.includes('genymotion')
  ) return 'genymotion';
  if (AVD_SERIAL_RE.test(serial)) return 'avd';
  return null; // physical or unknown
}

const APPIUM_DEFAULT_URL = 'http://127.0.0.1:4723';

export function renderDevicesPage(main) {
  const appiumStatusEl = el('span', { class: 'text-muted', style: 'font-size: 12px; align-self: center;' }, '');

  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Devices'),
      el('div', { class: 'page-subtitle', id: 'devices-subtitle' },
        'Attached Android targets and runtime controls.'),
    ),
    el('div', { class: 'page-actions', style: 'flex-wrap: wrap; gap: 8px;' },
      appiumStatusEl,
      el('button', {
        class: 'btn btn-secondary btn-sm',
        title: `Check if Appium server is running at ${APPIUM_DEFAULT_URL}`,
        onclick: () => checkAppiumServer(appiumStatusEl),
      },
        el('i', { 'data-lucide': 'bot' }),
        'Check Appium',
      ),
      el('button', {
        class: 'btn btn-secondary btn-sm',
        title: 'Run adb connect for a Genymotion / WiFi ADB device',
        onclick: () => connectGenymotion(container),
      },
        el('i', { 'data-lucide': 'layers' }),
        'Connect Genymotion',
      ),
      el('button', { class: 'btn btn-secondary btn-sm', id: 'devices-refresh' },
        el('i', { 'data-lucide': 'refresh-cw' }),
        'Refresh',
      ),
    ),
  ));

  const container = el('div', { id: 'devices-list' });
  main.appendChild(container);

  document.getElementById('devices-refresh')
    .addEventListener('click', () => loadAndRender(container));

  loadAndRender(container);
  refreshIcons();
}

async function loadAndRender(container) {
  container.innerHTML = '';
  container.appendChild(el('div', { class: 'text-muted' }, 'Loading…'));

  let devs = null;
  try {
    devs = await api.listDevices();
  } catch (e) {
    container.innerHTML = '';
    const msg = e instanceof ApiError ? e.message : String(e);
    container.appendChild(el('div', { class: 'card', style: 'padding: 20px;' },
      el('h3', {}, 'Pool unreachable'),
      el('p', { class: 'text-muted' }, msg),
      el('p', { class: 'text-muted' }, 'No Android device is currently visible to adb.'),
    ));
    refreshIcons();
    return;
  }

  container.innerHTML = '';
  const sub = document.getElementById('devices-subtitle');
  if (sub) {
    const ready = devs.filter(d => d.state === 'device').length;
    sub.textContent = `${devs.length} attached · ${ready} ready to lease`;
  }

  if (!devs || devs.length === 0) {
    container.appendChild(el('div', { class: 'card empty-state', style: 'padding: 24px;' },
      el('i', { 'data-lucide': 'smartphone-x' }),
      el('h3', {}, 'No devices attached'),
      el('p', { class: 'text-muted' },
        'Plug in an Android device with USB-debugging enabled, or boot ',
        'an emulator. Then click Refresh.'),
      el('pre', { class: 'mono', style: 'margin-top: 12px;' }, 'adb devices'),
    ));
    refreshIcons();
    return;
  }

  const grid = el('div', { class: 'devices-grid', style:
    'display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px;' });
  devs.forEach(d => grid.appendChild(buildDeviceCard(d)));
  container.appendChild(grid);
  refreshIcons();
}

function buildDeviceCard(d) {
  const stateColor =
      d.state === 'device' ? 'var(--device-online)'
    : d.state === 'unauthorized' ? 'var(--device-unauthorized)'
    : d.state === 'offline' ? 'var(--device-offline)'
    : 'var(--device-other)';
  const stateBadge = el('span', {
    class: 'badge',
    style:
      `background:color-mix(in srgb, ${stateColor} 13%, transparent);` +
      `color:${stateColor};` +
      `border:1px solid color-mix(in srgb, ${stateColor} 33%, transparent);` +
      'font-size:10px;text-transform:uppercase;letter-spacing:0.05em;',
  }, d.state);

  const output = el('pre', { class: 'device-output mono' }, 'Ready.');
  const fileInput = el('input', {
    class: 'input device-file',
    type: 'file',
    multiple: true,
    accept: '.apk,application/vnd.android.package-archive',
  });
  const replaceInput = el('input', { type: 'checkbox', checked: true });
  const grantInput = el('input', { type: 'checkbox', checked: true });
  const packageInput = el('input', {
    class: 'input mono',
    type: 'text',
    placeholder: 'com.example.app',
  });
  const activityInput = el('input', {
    class: 'input mono',
    type: 'text',
    placeholder: '.MainActivity',
  });

  const online = d.state === 'device';
  const disabled = online ? null : true;

  return el('div', { class: 'card device-card' },
    el('div', { class: 'device-card-head' },
      el('div', { class: 'mono', style: 'font-size: 13px; color: var(--accent-primary);' }, d.serial),
      stateBadge,
    ),
    el('div', { style: 'font-size: 13px; margin-bottom: 4px;' },
      (d.manufacturer || '?'), ' · ', (d.model || 'unknown')),
    el('div', { class: 'text-muted', style: 'font-size: 12px;' },
      'SDK ', (d.sdk || '?'), ' · ABI ', (d.abi || '?'),
      (() => {
        const emuType = detectEmulatorType(d.serial, d.manufacturer);
        if (emuType === 'genymotion') return ' · Genymotion';
        if (emuType === 'avd')        return ' · AVD';
        if (d.is_emulator === 'true') return ' · emulator';
        return '';
      })()),
    d.fingerprint
      ? el('div', { class: 'mono text-muted', style: 'font-size: 11px; margin-top: 8px; word-break: break-all;' },
          d.fingerprint)
      : null,
    el('div', { class: 'device-action-bar' },
      actionButton('activity', 'Preflight', () => runDeviceAction(
        d.serial, output, 'Running preflight...', () => api.devicePreflight(d.serial),
      ), disabled),
      actionButton('shield-off', 'Disable verifier', () => runDeviceAction(
        d.serial, output, 'Updating verifier settings...', () => api.disableVerifier(d.serial),
      ), disabled),
      actionButton('radio-tower', 'Setup Frida', () => runDeviceAction(
        d.serial, output, 'Starting Frida...', () => api.setupFrida(d.serial),
      ), disabled),
      actionButton('trash-2', 'Clear logcat', () => runDeviceAction(
        d.serial, output, 'Clearing logcat...', () => api.clearLogcat(d.serial),
      ), disabled),
    ),
    el('div', { class: 'device-panel' },
      el('div', { class: 'device-panel-title' },
        el('i', { 'data-lucide': 'package-plus' }),
        'Install APKs',
      ),
      fileInput,
      el('div', { class: 'device-checkbox-row' },
        el('label', { class: 'checkbox' }, replaceInput, el('span', {}, 'Replace existing')),
        el('label', { class: 'checkbox' }, grantInput, el('span', {}, 'Grant permissions')),
      ),
      el('button', {
        class: 'btn btn-primary btn-sm',
        disabled,
        onclick: () => {
          const files = Array.from(fileInput.files || []);
          if (!files.length) {
            toast('Select at least one APK', 'error');
            return;
          }
          runDeviceAction(
            d.serial,
            output,
            `Installing ${files.length} APK file${files.length === 1 ? '' : 's'}...`,
            () => api.installOnDevice(d.serial, {
              files,
              replace: replaceInput.checked,
              grantPermissions: grantInput.checked,
            }),
          );
        },
      },
        el('i', { 'data-lucide': 'upload' }),
        'Install',
      ),
    ),
    el('div', { class: 'device-panel' },
      el('div', { class: 'device-panel-title' },
        el('i', { 'data-lucide': 'play' }),
        'Launch / Inspect',
      ),
      el('div', { class: 'device-form-grid' },
        packageInput,
        activityInput,
      ),
      el('div', { class: 'device-action-bar compact' },
        actionButton('play', 'Launch', () => {
          const packageName = packageInput.value.trim();
          if (!packageName) {
            toast('Package name required', 'error');
            return;
          }
          runDeviceAction(
            d.serial,
            output,
            `Launching ${packageName}...`,
            () => api.launchOnDevice(d.serial, {
              packageName,
              activity: activityInput.value.trim(),
            }),
          );
        }, disabled),
        actionButton('info', 'Status', () => {
          const packageName = packageInput.value.trim();
          if (!packageName) {
            toast('Package name required', 'error');
            return;
          }
          runDeviceAction(
            d.serial,
            output,
            `Checking ${packageName}...`,
            () => api.packageStatus(d.serial, packageName),
          );
        }, disabled),
        actionButton('scroll-text', 'Logcat', () => runDeviceAction(
          d.serial, output, 'Reading logcat...', () => api.readLogcat(d.serial, { lines: 250 }),
        ), disabled),
      ),
    ),
    buildMirrorPanel(d.serial, online),
    output,
  );
}

function buildMirrorPanel(serial, online) {
  const canvas    = el('canvas', {
    style: 'display:none; width:100%; border-radius:6px; border:1px solid var(--border); cursor:crosshair; margin-top:10px; background:#000;',
  });
  const statusEl  = el('span', { style: 'font-size:11px; color:var(--text-muted);' }, '');
  const fpsEl     = el('span', { style: 'font-size:11px; color:var(--text-muted); margin-left:8px;' }, '');

  let mirrorHandle = null;
  let frameCount   = 0;
  let fpsTimer     = null;

  const startBtn = el('button', {
    class: 'btn btn-secondary btn-sm',
    disabled: online ? null : true,
    style: 'display:flex; align-items:center; gap:6px;',
  },
    el('i', { 'data-lucide': 'monitor' }),
    'Start Mirror',
  );

  startBtn.addEventListener('click', () => {
    if (mirrorHandle) {
      // Stop
      mirrorHandle.stop();
      _mirrors.delete(serial);
      mirrorHandle = null;
      canvas.style.display = 'none';
      statusEl.textContent = '';
      fpsEl.textContent    = '';
      clearInterval(fpsTimer);
      startBtn.innerHTML   = '';
      startBtn.appendChild(el('i', { 'data-lucide': 'monitor' }));
      startBtn.appendChild(document.createTextNode(' Start Mirror'));
      refreshIcons();
      return;
    }

    // Start
    canvas.style.display = 'block';
    statusEl.textContent = 'Connecting…';
    startBtn.innerHTML   = '';
    startBtn.appendChild(el('i', { 'data-lucide': 'monitor-off' }));
    startBtn.appendChild(document.createTextNode(' Stop Mirror'));
    refreshIcons();

    const ctx = canvas.getContext('2d');

    mirrorHandle = api.mirrorScreen(serial, {
      onStatus: (s) => {
        statusEl.textContent = s;
        if (s === 'error' || s === 'disconnected') {
          fpsEl.textContent = '';
          clearInterval(fpsTimer);
        }
      },
      onFrame: (b64, fps) => {
        frameCount++;
        const img = new Image();
        img.onload = () => {
          if (canvas.width !== img.naturalWidth || canvas.height !== img.naturalHeight) {
            canvas.width  = img.naturalWidth;
            canvas.height = img.naturalHeight;
          }
          ctx.drawImage(img, 0, 0);
        };
        img.src = 'data:image/png;base64,' + b64;
        if (!fpsTimer) {
          fpsTimer = setInterval(() => {
            fpsEl.textContent = `${frameCount} fps`;
            frameCount = 0;
          }, 1000);
        }
      },
    });

    _mirrors.set(serial, mirrorHandle);

    // Tap forwarding — click on canvas sends normalised coords
    canvas.addEventListener('click', (e) => {
      if (!mirrorHandle) return;
      const rect = canvas.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width;
      const y = (e.clientY - rect.top)  / rect.height;
      mirrorHandle.sendTap(x, y);
    });
  });

  return el('div', { class: 'device-panel' },
    el('div', { class: 'device-panel-title' },
      el('i', { 'data-lucide': 'monitor' }),
      'Screen Mirror',
      el('span', { style: 'margin-left:auto; display:flex; align-items:center; gap:4px;' },
        statusEl,
        fpsEl,
      ),
    ),
    el('div', { style: 'display:flex; align-items:center; gap:8px; margin-bottom:4px;' },
      startBtn,
      el('span', { class: 'text-muted', style: 'font-size:12px;' },
        online ? 'Click canvas to tap the device' : 'Device offline',
      ),
    ),
    canvas,
  );
}

function actionButton(icon, label, onclick, disabled = null) {
  return el('button', { class: 'btn btn-secondary btn-sm', onclick, disabled },
    el('i', { 'data-lucide': icon }),
    label,
  );
}

async function runDeviceAction(serial, output, pendingText, fn) {
  output.textContent = pendingText;
  try {
    const result = await fn();
    output.textContent = renderResult(result);
    toast(result.ok ? `Device ${serial} action complete` : `Device ${serial} action failed`,
      result.ok ? 'success' : 'error');
  } catch (e) {
    const msg = e instanceof ApiError ? e.message : String(e);
    output.textContent = msg;
    toast(msg, 'error', 4000);
  } finally {
    refreshIcons();
  }
}

async function checkAppiumServer(statusEl) {
  statusEl.textContent = 'Checking Appium…';
  statusEl.style.color = 'var(--text-muted)';
  try {
    const r = await fetch(`${APPIUM_DEFAULT_URL}/status`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) {
      const data = await r.json().catch(() => ({}));
      const ver = data?.value?.build?.version || '';
      statusEl.textContent = `Appium ${ver} · ready`;
      statusEl.style.color = 'var(--success)';
      toast(`Appium server is running${ver ? ' v' + ver : ''}`, 'success');
    } else {
      statusEl.textContent = `Appium · HTTP ${r.status}`;
      statusEl.style.color = 'var(--sev-high)';
      toast('Appium server responded with an error', 'error');
    }
  } catch (_) {
    statusEl.textContent = 'Appium · not reachable';
    statusEl.style.color = 'var(--sev-high)';
    toast(`Appium not running at ${APPIUM_DEFAULT_URL} — start with: appium --port 4723`, 'error', 5000);
  }
}

async function connectGenymotion(container) {
  const addr = window.prompt(
    'Enter Genymotion / WiFi ADB address (host:port)',
    '127.0.0.1:6562',
  );
  if (!addr) return;
  toast(`Connecting to ${addr}…`, 'info');
  try {
    const result = await api.adbConnect(addr.trim());
    if (result && result.ok) {
      toast(`Connected to ${addr} — refreshing device list`, 'success');
      loadAndRender(container);
    } else {
      toast(result?.error || `adb connect failed — is Genymotion running at ${addr}?`, 'error', 5000);
    }
  } catch (e) {
    const msg = e instanceof ApiError ? e.message : String(e);
    toast(`Connect failed: ${msg}`, 'error', 5000);
  }
}

function renderResult(result) {
  const lines = [];
  if (result.serial) lines.push(`serial: ${result.serial}`);
  if (result.mode) lines.push(`mode: ${result.mode}`);
  if (Array.isArray(result.files) && result.files.length) {
    lines.push(`files: ${result.files.join(', ')}`);
  }
  if (typeof result.bytes === 'number') lines.push(`bytes: ${result.bytes}`);
  if (Array.isArray(result.checks)) {
    for (const check of result.checks) {
      lines.push(`[${check.ok ? 'OK' : 'FAIL'}] ${check.name}: ${check.detail}`);
    }
  }
  if (Array.isArray(result.actions)) {
    for (const action of result.actions) {
      lines.push(`[${action.ok ? 'OK' : 'FAIL'}] ${action.name}`);
      if (action.stdout) lines.push(action.stdout.trimEnd());
      if (action.stderr) lines.push(action.stderr.trimEnd());
      if (action.error) lines.push(action.error);
    }
  }
  if (result.stdout) lines.push(result.stdout.trimEnd());
  if (result.error) lines.push(result.error);
  if (!lines.length) lines.push(JSON.stringify(result, null, 2));
  return lines.filter(Boolean).join('\n');
}
