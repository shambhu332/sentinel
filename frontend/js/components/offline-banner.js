// Offline banner — shown when the SENTINEL API is unreachable.
// Single source of truth: every page falls back to this when its API
// call throws. Pass the caught error through so the message stays
// contextual (network error, HTTP status, etc.).
import { el } from '../utils.js';
import { ApiError } from '../api.js';

export function offlineBanner(err) {
  const msg = err == null
    ? ''
    : (err instanceof ApiError ? err.message : String(err));

  return el('div', { class: 'card offline-banner' },
    el('div', { class: 'offline-banner-row' },
      el('i', { 'data-lucide': 'wifi-off', class: 'offline-banner-icon' }),
      el('div', { style: 'font-size: 13px; flex: 1;' },
        el('strong', {}, 'SENTINEL API offline.', ' '),
        'Showing sample data — start the gateway or change the API URL in ',
        el('a', { href: '#settings', class: 'offline-banner-link' },
          el('i', { 'data-lucide': 'settings', style: 'width: 14px; height: 14px;' }),
          'Settings ▸ Connection',
        ),
        '. Or run ',
        el('span', { class: 'mono' }, 'poetry run sentinel serve'),
        '.',
        msg ? el('div', { class: 'text-muted', style: 'font-size: 12px; margin-top: 4px;' }, msg) : null,
      ),
      el('button', {
        class: 'btn btn-sm btn-ghost',
        onclick: () => location.reload(),
      },
        el('i', { 'data-lucide': 'rotate-cw' }),
        'Retry',
      ),
    ),
  );
}
