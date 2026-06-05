// Settings page
import { el, refreshIcons, toast } from '../utils.js';

export function renderSettingsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Settings'),
      el('div', { class: 'page-subtitle' }, 'Configure your LLM provider, scan defaults, and instance preferences'),
    ),
  ));

  const wrap = el('div', { class: 'settings-layout' });

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
