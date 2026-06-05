// Docs page (lightweight)
import { el, refreshIcons } from '../utils.js';
import { codeBlock } from '../components/code-block.js';

export function renderDocsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Documentation'),
      el('div', { class: 'page-subtitle' }, 'Get started with SENTINEL'),
    ),
  ));

  const layout = el('div', { class: 'settings-layout' });

  layout.appendChild(section('Installation', [
    el('p', { style: 'margin-bottom: 12px;' }, 'SENTINEL ships as a Python CLI. Install via Poetry:'),
    codeBlock('git clone https://github.com/sentinel-android-scanner/sentinel\ncd sentinel\npoetry install\npoetry run sentinel --help', { showLineNumbers: false }),
  ]));

  layout.appendChild(section('Run your first scan', [
    el('p', { style: 'margin-bottom: 12px;' }, 'Place an APK in the corpus/ directory, then:'),
    codeBlock('poetry run sentinel scan corpus/example.apk \\\n  --dynamic \\\n  --frida \\\n  --llm-triage', { showLineNumbers: false }),
    el('p', { style: 'margin-top: 12px;' }, 'Open the JSON report:'),
    codeBlock('cat sentinel-out/example_apk/report.json | jq', { showLineNumbers: false }),
  ]));

  layout.appendChild(section('Common flags', [
    el('table', { class: 'table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Flag'), el('th', {}, 'Description'))),
      el('tbody', {},
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--dynamic')), el('td', {}, 'Run app on connected device')),
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--frida')), el('td', {}, 'Inject Frida agent for runtime hooks')),
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--no-proxy')), el('td', {}, 'Skip mitmproxy (for anti-MITM apps)')),
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--privacy-mode')), el('td', {}, 'Use local LLM only (Ollama)')),
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--llm-triage')), el('td', {}, 'Enable LLM-powered triage')),
        el('tr', {}, el('td', {}, el('code', { class: 'inline' }, '--scope-url')), el('td', {}, 'HackerOne/Bugcrowd scope URL')),
      ),
    ),
  ]));

  main.appendChild(layout);
  refreshIcons();
}

function section(title, children) {
  return el('div', { class: 'settings-section' },
    el('h3', {}, title),
    ...children,
  );
}
