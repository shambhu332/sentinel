// Settings page
import { el, refreshIcons, toast } from '../utils.js';
import { API_BASE, setApiBase } from '../api.js';

export function renderSettingsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Settings'),
      el('div', { class: 'page-subtitle' }, 'Configure your LLM provider, scan defaults, and instance preferences'),
    ),
  ));

  const wrap = el('div', { class: 'settings-layout' });

  // Connection (deliberately first — most-needed when the user is here)
  wrap.appendChild(buildConnectionSection());
  // LLM Provider
  wrap.appendChild(buildLLMSection());
  // Scan Defaults
  wrap.appendChild(buildScanDefaults());
  // Theme
  wrap.appendChild(buildThemeSection());
  // About
  wrap.appendChild(buildAboutSection());

  main.appendChild(wrap);
  refreshIcons();
}

function buildConnectionSection() {
  const section = el('div', { class: 'settings-section', id: 'settings-connection' });

  const statusDot = el('span', { class: 'conn-dot conn-dot-unknown', id: 'conn-status-dot' });
  const statusLabel = el('span', { id: 'conn-status-label', class: 'mono' }, 'checking…');

  const input = el('input', {
    class: 'input mono',
    type: 'text',
    value: API_BASE,
    placeholder: 'http://localhost:8000',
    style: 'min-width: 320px; flex: 1;',
  });

  const detail = el('div', { class: 'label-desc conn-detail', id: 'conn-status-detail' },
    'Probing the gateway…',
  );

  async function probe(url) {
    const trimmed = (url || API_BASE).replace(/\/+$/, '');
    statusDot.className = 'conn-dot conn-dot-unknown';
    statusLabel.textContent = 'checking…';
    detail.textContent = `GET ${trimmed}/health`;
    try {
      const res = await fetch(`${trimmed}/health`, { method: 'GET' });
      if (!res.ok) {
        statusDot.className = 'conn-dot conn-dot-error';
        statusLabel.textContent = `HTTP ${res.status}`;
        detail.textContent = `Gateway reachable but returned ${res.status}. Check the server log.`;
        return false;
      }
      const body = await res.json();
      statusDot.className = 'conn-dot conn-dot-ok';
      statusLabel.textContent = body.status || 'online';
      detail.textContent = `Connected — ${trimmed}`;
      return true;
    } catch (e) {
      statusDot.className = 'conn-dot conn-dot-error';
      statusLabel.textContent = 'offline';
      detail.textContent = (
        `Cannot reach ${trimmed}/health. ` +
        `Is the gateway running on that port?`
      );
      return false;
    }
  }

  const testBtn = el('button', { class: 'btn btn-secondary' },
    el('i', { 'data-lucide': 'activity' }), 'Test',
  );
  testBtn.addEventListener('click', () => probe(input.value.trim()));

  const saveBtn = el('button', { class: 'btn btn-primary' },
    el('i', { 'data-lucide': 'save' }), 'Save & reload',
  );
  saveBtn.addEventListener('click', async () => {
    const url = input.value.trim().replace(/\/+$/, '');
    if (!url) {
      toast('Enter a base URL like http://localhost:8000');
      return;
    }
    const ok = await probe(url);
    if (!ok && !confirm('Gateway is unreachable. Save anyway?')) return;
    setApiBase(url);
    toast('Saved. Reloading…');
    setTimeout(() => location.reload(), 500);
  });

  const resetBtn = el('button', { class: 'btn btn-ghost' },
    el('i', { 'data-lucide': 'rotate-ccw' }), 'Reset',
  );
  resetBtn.addEventListener('click', () => {
    input.value = 'http://localhost:8000';
    probe(input.value);
  });

  section.append(
    el('h3', {}, 'Connection'),
    el('div', { class: 'section-sub' },
      'The frontend talks to the FastAPI gateway via this URL. If you run ',
      el('code', { class: 'inline' }, 'sentinel serve --port 8001'),
      ', point this here.',
    ),

    el('div', { class: 'conn-row' },
      el('div', { class: 'conn-status' }, statusDot, statusLabel),
      detail,
    ),

    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'API base URL'),
        el('div', { class: 'label-desc' }, 'Stored in localStorage. Browser-only — never sent to SENTINEL.'),
      ),
      el('div', { style: 'display: flex; gap: 8px; flex-wrap: wrap;' },
        input, testBtn, saveBtn, resetBtn,
      ),
    ),

    el('div', { class: 'conn-cli' },
      el('div', { class: 'label-desc' }, 'Start the gateway with:'),
      el('pre', { class: 'cli' }, 'poetry run sentinel serve --port 8000'),
    ),
  );

  // Probe on page render
  setTimeout(() => probe(API_BASE), 0);

  return section;
}

function buildLLMSection() {
  const section = el('div', { class: 'settings-section' });
  section.append(
    el('h3', {}, 'LLM Provider'),
    el('div', { class: 'section-sub' }, 'SENTINEL uses an LLM to triage findings. Primary is tried first, with automatic fallback.'),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Primary provider'),
        el('div', { class: 'label-desc' }, 'Currently: Groq (free tier, fastest)'),
      ),
      el('select', { class: 'select', style: 'min-width: 180px;' },
        el('option', { selected: true }, 'Groq (cloud)'),
        el('option', {}, 'Cerebras (cloud)'),
        el('option', {}, 'Ollama (local)'),
        el('option', {}, 'Anthropic (cloud)'),
      ),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'API key'),
        el('div', { class: 'label-desc' }, 'Stored in browser session only — never sent to SENTINEL.'),
      ),
      el('div', { style: 'display: flex; gap: 8px; align-items: center;' },
        el('input', { class: 'input mono', type: 'password', placeholder: 'gsk_••••••••••••', style: 'width: 240px;', value: 'gsk_••••••••••••••••••••mxYz' }),
        el('button', { class: 'btn btn-secondary btn-sm', onclick: () => toast('Connection OK — Groq llama-3.3-70b', 'success') }, 'Test'),
      ),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Fallback chain'),
        el('div', { class: 'label-desc' }, 'Auto-switches on rate-limit (429) or timeout'),
      ),
      el('span', { class: 'mono text-secondary', style: 'font-size: 12px;' }, 'Groq → Cerebras → Ollama'),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Privacy mode'),
        el('div', { class: 'label-desc' }, 'Forces local LLM (Ollama) — no data leaves your machine'),
      ),
      el('label', { class: 'toggle' }, el('input', { type: 'checkbox' })),
    ),
  );
  return section;
}

function buildScanDefaults() {
  const section = el('div', { class: 'settings-section' });
  section.append(
    el('h3', {}, 'Scan defaults'),
    el('div', { class: 'section-sub' }, 'Flags enabled by default when starting a new scan'),
    toggleRow('Dynamic analysis', 'Install + run on a connected device', true),
    toggleRow('Frida runtime hooks', 'Inject Frida for deep introspection', false),
    toggleRow('LLM triage', 'Filter false positives via LLM', true),
    toggleRow('No-proxy mode', 'Skip mitmproxy', false),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Default dynamic duration (sec)'),
        el('div', { class: 'label-desc' }, 'How long to exercise the app on device'),
      ),
      el('input', { class: 'input', type: 'number', value: 300, style: 'width: 100px;' }),
    ),
  );
  return section;
}

function buildThemeSection() {
  const section = el('div', { class: 'settings-section' });
  section.append(
    el('h3', {}, 'Appearance'),
    el('div', { class: 'section-sub' }, 'Visual preferences for the dashboard'),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Theme'),
        el('div', { class: 'label-desc' }, 'Light theme coming soon'),
      ),
      el('div', { style: 'display: flex; gap: 6px;' },
        el('button', { class: 'btn btn-primary btn-sm' }, el('i', { 'data-lucide': 'moon' }), 'Dark'),
        el('button', { class: 'btn btn-secondary btn-sm', disabled: true }, el('i', { 'data-lucide': 'sun' }), 'Light'),
      ),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Reduced motion'),
        el('div', { class: 'label-desc' }, 'Honor OS preference automatically'),
      ),
      el('label', { class: 'toggle' }, el('input', { type: 'checkbox', checked: true })),
    ),
  );
  return section;
}

function buildAboutSection() {
  const section = el('div', { class: 'settings-section' });
  section.append(
    el('h3', {}, 'About'),
    el('div', { class: 'section-sub' }, 'Build info for this SENTINEL instance'),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Version'),
      ),
      el('span', { class: 'mono text-secondary' }, 'v1.4.0'),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Build'),
      ),
      el('span', { class: 'mono text-secondary' }, '65eaa1a · main'),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'License'),
      ),
      el('span', { class: 'mono text-secondary' }, 'Apache 2.0'),
    ),
    el('div', { class: 'settings-row' },
      el('div', { class: 'settings-row-label' },
        el('div', { class: 'label-title' }, 'Source'),
      ),
      el('a', { href: 'https://github.com', target: '_blank' }, 'github.com/sentinel-android-scanner'),
    ),
  );
  return section;
}

function toggleRow(title, desc, defaultChecked) {
  return el('div', { class: 'settings-row' },
    el('div', { class: 'settings-row-label' },
      el('div', { class: 'label-title' }, title),
      el('div', { class: 'label-desc' }, desc),
    ),
    el('label', { class: 'toggle' }, el('input', { type: 'checkbox', checked: defaultChecked ? true : null })),
  );
}
