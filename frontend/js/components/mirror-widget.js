// Reusable live screen-mirror widget.
// Auto-detects the first online device from /devices and streams frames.
// Used on the Dashboard (right panel) and Scan Detail (live view).
//
// buildMirrorWidget({ serial, title, compact })
//   serial  — pin to a specific device serial (skip auto-detect)
//   title   — card heading (default 'Live Device')
//   compact — use a shorter canvas height (default false)

import { el, refreshIcons } from '../utils.js';
import { api }              from '../api.js';

export function buildMirrorWidget({ serial: pinnedSerial, title = 'Live Device', compact = false } = {}) {
  let mirrorHandle = null;
  let activeSerial = pinnedSerial || null;
  let frameCount   = 0;
  let fpsTimer     = null;

  // ── DOM nodes ───────────────────────────────────────────────────────────────

  const deviceLabelEl = el('span', {
    style: 'font-size:11px;color:var(--text-muted);font-family:monospace;margin-left:4px;',
  }, pinnedSerial || 'detecting…');

  const statusEl = el('span', { style: 'font-size:11px;color:var(--text-muted);' }, '');
  const fpsEl    = el('span', { style: 'font-size:11px;color:var(--accent-primary);margin-left:6px;' }, '');

  const canvas = el('canvas', {
    style: 'display:none;width:100%;object-fit:contain;border-radius:6px;' +
           'border:1px solid var(--border);cursor:crosshair;background:#000;',
  });

  const noDeviceEl = el('div', {
    style: 'text-align:center;padding:24px 12px;color:var(--text-muted);font-size:12px;',
  },
    el('i', { 'data-lucide': 'smartphone-x', style: 'display:block;margin:0 auto 8px;width:28px;height:28px;' }),
    'No device online — connect one on the ',
    el('a', { href: '#devices', style: 'color:var(--accent-primary);' }, 'Devices'),
    ' page.',
  );

  const startBtn = el('button', {
    class: 'btn btn-secondary btn-sm',
    style: 'display:flex;align-items:center;gap:6px;',
    disabled: true,
  },
    el('i', { 'data-lucide': 'monitor' }),
    'Start Mirror',
  );

  // ── helpers ─────────────────────────────────────────────────────────────────

  function setStartBtn(running) {
    startBtn.innerHTML = '';
    startBtn.appendChild(el('i', { 'data-lucide': running ? 'monitor-off' : 'monitor' }));
    startBtn.appendChild(document.createTextNode(running ? ' Stop Mirror' : ' Start Mirror'));
    refreshIcons();
  }

  function stopMirror() {
    if (!mirrorHandle) return;
    mirrorHandle.stop();
    mirrorHandle  = null;
    clearInterval(fpsTimer);
    fpsTimer      = null;
    frameCount    = 0;
    canvas.style.display = 'none';
    statusEl.textContent = '';
    fpsEl.textContent    = '';
    setStartBtn(false);
  }

  function startMirror(serial) {
    canvas.style.display     = 'block';
    noDeviceEl.style.display = 'none';
    statusEl.textContent     = 'Connecting…';
    setStartBtn(true);

    const ctx = canvas.getContext('2d');

    mirrorHandle = api.mirrorScreen(serial, {
      onStatus(s) {
        statusEl.textContent = s;
        if (s === 'error' || s === 'disconnected') {
          fpsEl.textContent = '';
          clearInterval(fpsTimer);
          fpsTimer = null;
          canvas.style.display = 'none';
          setStartBtn(false);
        }
      },
      onFrame(b64) {
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
          fpsTimer = setInterval(() => { fpsEl.textContent = `${frameCount} fps`; frameCount = 0; }, 1000);
        }
      },
    });

    canvas.onclick = (e) => {
      if (!mirrorHandle) return;
      const rect = canvas.getBoundingClientRect();
      mirrorHandle.sendTap(
        (e.clientX - rect.left) / rect.width,
        (e.clientY - rect.top)  / rect.height,
      );
    };
  }

  startBtn.addEventListener('click', () => {
    if (mirrorHandle) { stopMirror(); } else if (activeSerial) { startMirror(activeSerial); }
  });

  // ── device auto-detect ──────────────────────────────────────────────────────

  async function detect() {
    if (pinnedSerial) {
      activeSerial = pinnedSerial;
      deviceLabelEl.textContent = pinnedSerial;
      startBtn.removeAttribute('disabled');
      noDeviceEl.style.display = 'none';
      return;
    }
    deviceLabelEl.textContent = 'detecting…';
    startBtn.disabled = true;
    try {
      const devs = await api.listDevices();
      console.log('[mirror-widget] listDevices =>', devs);
      const online = Array.isArray(devs) ? devs.find(d => d.state === 'device') : null;
      console.log('[mirror-widget] online device =>', online);
      if (online) {
        activeSerial = online.serial;
        deviceLabelEl.textContent =
          `${online.serial} · ${(online.manufacturer || '')} ${(online.model || '')}`.trim();
        startBtn.removeAttribute('disabled');
        noDeviceEl.style.display = 'none';
      } else {
        activeSerial = null;
        deviceLabelEl.textContent = 'no device';
        startBtn.disabled = true;
        noDeviceEl.style.display = '';
      }
    } catch (err) {
      console.error('[mirror-widget] detect error =>', err);
      activeSerial = null;
      deviceLabelEl.textContent = 'API unreachable';
      startBtn.disabled = true;
      noDeviceEl.style.display = '';
    }
    refreshIcons();
  }

  // ── assemble ────────────────────────────────────────────────────────────────

  const widget = el('div', { class: 'card mirror-widget' },
    el('div', { class: 'card-header', style: 'padding:12px 16px;margin:0;border-bottom:1px solid var(--border);' },
      el('div', { class: 'card-title', style: 'gap:6px;font-size:13px;' },
        el('i', { 'data-lucide': 'monitor' }),
        title,
        deviceLabelEl,
      ),
      el('div', { style: 'display:flex;align-items:center;gap:6px;' },
        statusEl,
        fpsEl,
        el('button', {
          class: 'btn btn-ghost btn-sm',
          title: 'Re-detect device',
          style: 'padding:4px 8px;',
          onclick: () => detect(),
        }, el('i', { 'data-lucide': 'refresh-cw' })),
      ),
    ),
    el('div', { style: 'padding:12px;' },
      el('div', { style: 'display:flex;gap:8px;margin-bottom:10px;align-items:center;' },
        startBtn,
        el('span', { class: 'text-muted', style: 'font-size:11px;' }, 'Click canvas to tap'),
      ),
      noDeviceEl,
      canvas,
    ),
  );

  // Auto-detect after DOM attaches
  setTimeout(detect, 0);

  return widget;
}
