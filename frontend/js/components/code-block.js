// Code block component with syntax highlighting + copy button
import { el, highlight, refreshIcons, toast } from '../utils.js';

export function codeBlock(source, opts = {}) {
  const { showLineNumbers = true, highlightLines = [] } = opts;
  const lines = source.split('\n');

  const body = el('div', { class: 'code-body' });
  lines.forEach((line, i) => {
    const lineEl = el('div', { class: `code-line${highlightLines.includes(i + 1) ? ' highlight-line' : ''}` });
    if (showLineNumbers) lineEl.appendChild(el('span', { class: 'line-no' }, String(i + 1)));
    lineEl.appendChild(el('span', { html: highlight(line) || '&nbsp;', class: 'code-content' }));
    body.appendChild(lineEl);
  });

  const copyBtn = el('button', { class: 'copy-btn' }, 'Copy');
  copyBtn.addEventListener('click', async (ev) => {
    ev.stopPropagation();
    try {
      await navigator.clipboard.writeText(source);
      copyBtn.textContent = 'Copied!';
      toast('Code copied to clipboard', 'success');
      setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
    } catch {
      toast('Copy failed', 'error');
    }
  });

  const block = el('div', { class: `code-block ${highlightLines.length ? 'with-highlight' : ''}` }, copyBtn, body);
  refreshIcons();
  return block;
}
