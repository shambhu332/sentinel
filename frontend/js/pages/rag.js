// RAG Knowledge Base browser
import { el, refreshIcons, debounce } from '../utils.js';
import { PASSAGES, PASSAGE_SOURCES, PASSAGE_TOTAL } from '../data/knowledge.js';

const state = {
  q: '',
  source: 'ALL',
};

const SOURCE_LABEL = {
  MASVS: 'OWASP MASVS',
  OWASP_MOBILE: 'OWASP Mobile Top 10',
  CWE: 'MITRE CWE',
  OSV: 'OSV (vuln. DB)',
  ALL: 'All sources',
};

export function renderRagPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Knowledge Base'),
      el('div', { class: 'page-subtitle' },
        `${PASSAGE_TOTAL} retrievable passages across MASVS, OWASP Mobile Top 10, and CWE — embedded for LLM-triage augmentation.`,
      ),
    ),
    el('div', { class: 'page-actions' },
      el('div', { class: 'search-input', style: 'min-width: 320px;' },
        el('i', { 'data-lucide': 'search' }),
        el('input', {
          type: 'text',
          placeholder: 'Search controls, CWEs, MASVS ids…',
          oninput: debounce((e) => { state.q = e.target.value.toLowerCase(); renderList(); }, 150),
        }),
      ),
    ),
  ));

  const layout = el('div', { class: 'agents-layout' });

  // Sidebar: source filter + how-it-works
  const sidebar = el('aside', { class: 'agents-sidebar' });
  const sourceWrap = el('div');
  sourceWrap.appendChild(el('h4', {}, 'Source'));
  for (const src of ['ALL', ...PASSAGE_SOURCES]) {
    const label = el('label', { class: 'checkbox' },
      el('input', { type: 'radio', name: 'rag-source', value: src, checked: src === 'ALL' }),
      SOURCE_LABEL[src] || src,
    );
    label.querySelector('input').addEventListener('change', (e) => {
      state.source = e.target.value;
      renderList();
    });
    sourceWrap.appendChild(label);
  }
  sidebar.appendChild(sourceWrap);

  sidebar.appendChild(el('div', { class: 'card', style: 'margin-top: 16px; padding: 12px;' },
    el('h4', { style: 'margin: 0 0 8px;' }, 'How it works'),
    el('p', { style: 'font-size: 12px; color: var(--text-dim);' },
      'When the LLM triager evaluates a finding, the top-K most similar passages from this corpus are prepended to the prompt as authoritative reference context. ',
      'The mapping is persisted into ',
      el('code', { class: 'inline' }, 'finding.evidence._rag_mapping'),
      ' so the report generator can render references inline.',
    ),
    el('div', { style: 'margin-top: 8px;' },
      el('code', { class: 'inline' }, 'sentinel rag build'),
    ),
  ));

  layout.appendChild(sidebar);
  layout.appendChild(el('div', { id: 'rag-list', class: 'rag-list' }));
  main.appendChild(layout);

  renderList();
  refreshIcons();
}

function renderList() {
  const list = document.getElementById('rag-list');
  if (!list) return;
  list.innerHTML = '';

  const filtered = PASSAGES.filter(p => {
    if (state.source !== 'ALL' && p.source !== state.source) return false;
    if (state.q) {
      const t = `${p.control_id} ${p.title} ${p.text} ${p.category}`.toLowerCase();
      if (!t.includes(state.q)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    list.appendChild(el('div', { class: 'card empty-state' },
      el('i', { 'data-lucide': 'search-x' }),
      el('p', {}, 'No passages match your filter.'),
    ));
    refreshIcons();
    return;
  }

  // Counter row
  list.appendChild(el('div', { class: 'rag-counter' },
    `${filtered.length} passage${filtered.length === 1 ? '' : 's'}`,
  ));

  for (const p of filtered) {
    const card = el('div', { class: 'card rag-card' },
      el('div', { class: 'rag-card-head' },
        el('span', { class: `chip chip-${p.source.toLowerCase().replace('_', '-')}` }, p.source.replace('_', ' ')),
        el('span', { class: 'mono rag-cid' }, p.control_id),
        p.category ? el('span', { class: 'rag-category' }, p.category) : null,
      ),
      el('h3', { class: 'rag-title' }, p.title),
      el('p', { class: 'rag-text' }, p.text),
    );
    list.appendChild(card);
  }
  refreshIcons();
}
