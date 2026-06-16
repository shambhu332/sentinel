// Code block component with syntax highlighting + copy button
import { el, highlight, refreshIcons, toast } from '../utils.js';

export function codeBlock(source, opts = {}) {
  const {
    showLineNumbers = true,
    highlightLines = [],
    startLine = 1,
    columnHighlight = null,
  } = opts;
  const lines = source.split('\n');

  const body = el('div', { class: 'code-body' });
  lines.forEach((line, i) => {
    const lineNo = startLine + i;
    const isHighlight = highlightLines.includes(lineNo);
    const lineEl = el('div', {
      class: `code-line${isHighlight ? ' highlight-line' : ''}`,
    });
    if (showLineNumbers) lineEl.appendChild(el('span', { class: 'line-no' }, String(lineNo)));

    let html;
    if (isHighlight && columnHighlight
        && Number.isInteger(columnHighlight.start)
        && Number.isInteger(columnHighlight.end)
        && columnHighlight.end > columnHighlight.start) {
      const a = Math.max(0, Math.min(line.length, columnHighlight.start));
      const b = Math.max(a, Math.min(line.length, columnHighlight.end));
      const pre = line.slice(0, a);
      const mid = line.slice(a, b);
      const post = line.slice(b);
      html = (highlight(pre) || '')
        + `<mark class="col-highlight">${highlight(mid) || mid}</mark>`
        + (highlight(post) || '');
    } else {
      html = highlight(line) || '&nbsp;';
    }
    lineEl.appendChild(el('span', { html, class: 'code-content' }));
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
