// Devices page — surfaces the DeviceManager pool over /devices.
//
// Shows every attached Android device, its state (device / offline /
// unauthorized / emulator), manufacturer/model, sdk, abi, and the
// build fingerprint. Hits /devices on render + on the Refresh
// button. Doesn't write — leasing happens server-side during scans.
import { api, ApiError } from '../api.js';
import { el, refreshIcons, toast } from '../utils.js';

export function renderDevicesPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Devices'),
      el('div', { class: 'page-subtitle', id: 'devices-subtitle' },
        'DeviceManager pool — devices the orchestrator can lease for dynamic scans.'),
    ),
    el('div', { class: 'page-actions' },
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
      el('p', { class: 'text-muted' },
        'Make sure adb is installed and at least one device is plugged in. ',
        'When ', el('code', { class: 'inline' }, 'SENTINEL_REDIS_URL'),
        ' is set, lease coordination uses Redis across workers.'),
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

  return el('div', { class: 'card', style: 'padding: 16px;' },
    el('div', { style: 'display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;' },
      el('div', { class: 'mono', style: 'font-size: 13px; color: var(--accent-primary);' }, d.serial),
      stateBadge,
    ),
    el('div', { style: 'font-size: 13px; margin-bottom: 4px;' },
      (d.manufacturer || '?'), ' · ', (d.model || 'unknown')),
    el('div', { class: 'text-muted', style: 'font-size: 12px;' },
      'SDK ', (d.sdk || '?'), ' · ABI ', (d.abi || '?'),
      d.is_emulator === 'true' ? ' · emulator' : ''),
    d.fingerprint
      ? el('div', { class: 'mono text-muted', style: 'font-size: 11px; margin-top: 8px; word-break: break-all;' },
          d.fingerprint)
      : null,
  );
}
